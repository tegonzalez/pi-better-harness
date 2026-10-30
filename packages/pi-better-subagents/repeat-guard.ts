/**
 * Repeat guard: escalate instead of looping on a failing or no-progress tool call.
 *
 * Session 01a18443 failed `subagent_spawn` 1493 times in 3h45m with 173 different
 * argument variants, usually paired in the same assistant message with a
 * successful `get_background_activity` poll that returned the same result 830
 * times. Matching identical arguments alone would have allowed ~519 failures, and
 * blocking only the repeated call never ended the turn: Pi's agent loop stops
 * after a tool batch only when EVERY result in that batch is terminating
 * (`shouldTerminateToolBatch` in pi-agent-core `agent-loop.ts`).
 *
 * Escalation triggers (thresholds are the exported constants):
 * - SIGNATURE_LIMIT failures of one tool with the same normalized error signature
 *   (tool name + error text with quoted strings, ids, paths and numbers
 *   replaced), whatever the arguments; not for SIGNATURE_EXEMPT_TOOLS, whose
 *   varied-argument failures are normal exploration (no-match search, missing file);
 * - REPEAT_LIMIT failures of the same call (same tool, same arguments);
 * - POLL_LIMIT consecutive identical successful results of the same call
 *   (no-progress polling). A successful call with a new result is progress and
 *   restarts every other call's streak.
 *
 * On escalation the triggering result is annotated and, from then on, EVERY tool
 * call (any tool, any arguments) is blocked with `terminate: true`, so every
 * result of the next batch terminates and the loop ends:
 * - top level: the turn ends, the user gets a `ctx.ui.notify` warning;
 * - subagent child (loaded via child-steer in every child): the child run ends
 *   and its output carries the escalation to the parent agent.
 *
 * `ctx.abort()` is a backstop, not the primary mechanism, because it also
 * cancels the model's chance to report and marks the run aborted. It is used only
 * when blocking cannot end the loop: a post-escalation batch with a result the
 * guard could not block (unknown tool or argument validation failure never reach
 * `tool_call`), or a new turn starting after a fully blocked batch (a runtime that
 * ignores `terminate`, or a queued follow-up message).
 *
 * New input (the user at top level, the parent's steer in a child) or a new
 * session clears all state. Registers no tools and performs no I/O. Children get
 * it from child-steer; the top-level subagents extension registers it only
 * outside a child.
 */
import { createHash } from "node:crypto";

/** Failures of the same call (same tool, same arguments) that escalate. */
export const REPEAT_LIMIT = 3;
/**
 * Failures of one tool with the same normalized error across different arguments
 * that escalate. Higher than REPEAT_LIMIT: varied arguments are often legitimate
 * exploration, and a loop like the incident's still escalates within seconds.
 */
export const SIGNATURE_LIMIT = 5;
/**
 * Exploration tools whose failures with different arguments are normal outcomes,
 * not loops (a search with no match, a guessed path that does not exist): their
 * normalized errors collide ("Command exited with code <n>", "ENOENT ... <str>").
 * Only the same-call rule applies to them.
 */
export const SIGNATURE_EXEMPT_TOOLS: ReadonlySet<string> = new Set(["bash", "read", "grep", "find", "ls"]);
/** Consecutive identical successful results of the same call that escalate. */
export const POLL_LIMIT = 5;
/** Characters of the exact error text quoted in the escalation. */
export const ERROR_EXCERPT_CHARS = 600;
/** Characters of the normalized error text kept in a signature. */
const SIGNATURE_CHARS = 400;

type GuardApi = {
    on(event: string, handler: (event: any, ctx: any) => unknown): void;
};

export type Escalation = {
    kind: "failure" | "poll";
    toolName: string;
    count: number;
    /** Distinct argument variants that produced this failure signature. */
    variants: number;
    /** Exact (truncated) error text for failures. */
    error?: string;
};

/** Stable JSON: object keys sorted, so key order never makes two calls differ. */
export function stableStringify(value: unknown): string {
    if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "undefined";
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
    const entries = Object.keys(value as Record<string, unknown>).sort()
        .map((key) => `${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key])}`);
    return `{${entries.join(",")}}`;
}

export function callSignature(toolName: unknown, input: unknown): string {
    return `${String(toolName)}\u0000${stableStringify(input ?? {})}`;
}

/** Text parts of a tool result, joined. */
export function resultText(content: unknown): string {
    if (typeof content === "string") return content;
    if (!Array.isArray(content)) return "";
    return content
        .map((part) => (part && typeof part === "object" && typeof (part as any).text === "string" ? (part as any).text : ""))
        .filter(Boolean)
        .join("\n");
}

/**
 * Error text with run-specific detail removed, so the same failure with other
 * arguments maps to one signature: quoted strings, UUIDs, long id-like tokens,
 * paths and numbers become placeholders; whitespace collapses.
 */
export function normalizeErrorText(text: string): string {
    return text
        .replace(/"[^"\n]*"|'[^'\n]*'|`[^`\n]*`/g, "<str>")
        .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<id>")
        .replace(/(?:~|\.{1,2})?(?:\/[^\s"'`,;:()<>[\]{}]+)+\/?/g, "<path>")
        .replace(/\b(?=[A-Za-z_-]*\d)(?=[\d_-]*[A-Za-z])[A-Za-z0-9_-]{8,}\b/g, "<id>")
        .replace(/\d+(?:\.\d+)?/g, "<n>")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, SIGNATURE_CHARS);
}

export function errorSignature(toolName: unknown, errorText: string): string {
    return `${String(toolName)}\u0000${normalizeErrorText(errorText)}`;
}

function digest(value: unknown): string {
    return createHash("sha256").update(stableStringify(value ?? null)).digest("hex");
}

export function escalationText(escalation: Escalation, child: boolean): string {
    const who = child ? "Stop now and return to the parent agent" : "Stop now and ask the user";
    const until = child ? "the parent agent replies" : "the user replies";
    const blocked = `Every further tool call (any tool) is blocked until ${until}; do not call tools.`;
    if (escalation.kind === "poll") {
        return `NO PROGRESS: ${escalation.toolName} returned the same result ${escalation.count} times in a row with identical arguments. ` +
            `Polling again will not change it. ${blocked} ` +
            `${who}: report what you were waiting for, the exact result you keep getting, what you tried, and what you need to proceed.`;
    }
    const args = escalation.variants > 1
        ? `across ${escalation.variants} different argument variants`
        : "with identical arguments";
    const error = escalation.error ? ` Exact error: ${JSON.stringify(escalation.error)}.` : "";
    return `REPEATED FAILURE: ${escalation.toolName} failed ${escalation.count} times with the same error ${args}.${error} ` +
        `Retrying, with these or other arguments, will not work. ${blocked} ` +
        `${who}: report the exact error, what you tried (each argument variant), and what you need to proceed.`;
}

/** Pure state machine, exported for tests. */
export function createRepeatGuard(limit = REPEAT_LIMIT, pollLimit = POLL_LIMIT, signatureLimit = SIGNATURE_LIMIT) {
    /** Same call → failures. */
    const callFailures = new Map<string, number>();
    /** Error signature → failures and the argument variants that produced them. */
    const errorFailures = new Map<string, { tool: string; count: number; variants: Set<string> }>();
    /** Same call → last successful result digest and its consecutive count. */
    const polls = new Map<string, { result: string; count: number }>();
    let escalation: Escalation | undefined;

    const clearToolErrors = (toolName: string) => {
        for (const [key, entry] of errorFailures) if (entry.tool === toolName) errorFailures.delete(key);
    };

    return {
        /** The active escalation: once set, every call is blocked until reset(). */
        get escalation(): Escalation | undefined { return escalation; },
        /** Returns the escalation that blocks this call, if any (it blocks every call). */
        check(_toolName?: string, _input?: unknown): Escalation | undefined {
            return escalation;
        },
        /** Records an outcome; returns the escalation when this result triggers it. */
        record(toolName: string, input: unknown, isError: boolean, content?: unknown): Escalation | undefined {
            if (escalation) return undefined;
            const name = String(toolName);
            const sig = callSignature(name, input);
            if (!isError) {
                callFailures.delete(sig);
                clearToolErrors(name);
                const result = digest(content);
                const previous = polls.get(sig);
                if (previous?.result === result) {
                    previous.count += 1;
                } else {
                    // A new result is progress: restart every streak, keeping the last results.
                    for (const entry of polls.values()) entry.count = 0;
                    polls.set(sig, { result, count: 1 });
                }
                const count = polls.get(sig)!.count;
                if (count >= pollLimit) {
                    escalation = { kind: "poll", toolName: name, count, variants: 1 };
                }
                return escalation;
            }
            polls.delete(sig);
            const callCount = (callFailures.get(sig) ?? 0) + 1;
            callFailures.set(sig, callCount);
            const text = resultText(content);
            const errorKey = errorSignature(name, text);
            const entry = errorFailures.get(errorKey) ?? { tool: name, count: 0, variants: new Set<string>() };
            entry.count += 1;
            entry.variants.add(sig);
            errorFailures.set(errorKey, entry);
            const bySignature = !SIGNATURE_EXEMPT_TOOLS.has(name) && entry.count >= signatureLimit;
            if (callCount >= limit || bySignature) {
                escalation = {
                    kind: "failure",
                    toolName: name,
                    count: bySignature ? Math.max(callCount, entry.count) : callCount,
                    variants: bySignature ? entry.variants.size : 1,
                    error: text.trim().slice(0, ERROR_EXCERPT_CHARS),
                };
            }
            return escalation;
        },
        reset(): void {
            callFailures.clear();
            errorFailures.clear();
            polls.clear();
            escalation = undefined;
        },
    };
}

export function isSubagentChild(env: NodeJS.ProcessEnv = process.env): boolean {
    return Boolean(env.PI_SUBAGENT_STEER_FILE);
}

function abort(ctx: any): void {
    try { ctx?.abort?.(); } catch { /* context may be inactive */ }
}

export default function repeatGuard(
    pi: GuardApi,
    options: { child?: boolean; limit?: number; pollLimit?: number; signatureLimit?: number } = {},
): void {
    const child = options.child ?? isSubagentChild();
    const guard = createRepeatGuard(options.limit ?? REPEAT_LIMIT, options.pollLimit ?? POLL_LIMIT, options.signatureLimit ?? SIGNATURE_LIMIT);
    /** Tool calls blocked during the current turn. */
    let blockedThisTurn = 0;
    /** Turns ended since the escalation (0 = the escalation's own turn). */
    let turnsSinceEscalation = 0;
    /** The previous turn ran after the escalation and every one of its calls was blocked. */
    let previousTurnFullyBlocked = false;

    const reset = () => {
        guard.reset();
        blockedThisTurn = 0;
        turnsSinceEscalation = 0;
        previousTurnFullyBlocked = false;
    };

    pi.on("input", () => { reset(); });
    pi.on("session_start", () => { reset(); });

    pi.on("agent_start", () => { blockedThisTurn = 0; previousTurnFullyBlocked = false; });
    pi.on("agent_end", () => { blockedThisTurn = 0; previousTurnFullyBlocked = false; });

    pi.on("turn_start", (_event, ctx) => {
        // A fully blocked batch terminates the loop; another turn means it did not.
        if (guard.escalation && previousTurnFullyBlocked) abort(ctx);
        blockedThisTurn = 0;
    });

    pi.on("turn_end", (event, ctx) => {
        const results = Array.isArray(event?.toolResults) ? event.toolResults.length : 0;
        const blocked = blockedThisTurn;
        blockedThisTurn = 0;
        if (!guard.escalation) return;
        const afterEscalation = turnsSinceEscalation > 0;
        turnsSinceEscalation += 1;
        previousTurnFullyBlocked = afterEscalation && results > 0 && blocked >= results;
        // The model already saw the escalation; a result the guard could not block keeps the loop going.
        if (afterEscalation && results > blocked) abort(ctx);
    });

    pi.on("tool_call", (event) => {
        if (event?.parentToolCallId) return undefined;
        const escalation = guard.check(event?.toolName, event?.input);
        if (!escalation) return undefined;
        blockedThisTurn += 1;
        return { block: true, terminate: true, reason: escalationText(escalation, child) };
    });

    pi.on("tool_result", (event, ctx) => {
        if (event?.parentToolCallId) return undefined;
        const escalation = guard.record(event?.toolName, event?.input, event?.isError === true, event?.content);
        if (!escalation) return undefined;
        turnsSinceEscalation = 0;
        if (!child) {
            const what = escalation.kind === "poll"
                ? `returned the same result ${escalation.count}× in a row`
                : `failed ${escalation.count}× with the same error`;
            try {
                ctx?.ui?.notify?.(`Agent stuck: ${escalation.toolName} ${what}. Its tool calls are blocked until you reply.`, "warning");
            } catch { /* UI optional */ }
        }
        const content = Array.isArray(event?.content) ? event.content : [];
        const notice = { type: "text", text: `\n\n${escalationText(escalation, child)}` };
        return escalation.kind === "failure"
            ? { content: [...content, notice], isError: true }
            : { content: [...content, notice] };
    });
}
