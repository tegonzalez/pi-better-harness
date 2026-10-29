/**
 * Repeat-failure guard: escalate instead of looping on an identical failing tool call.
 *
 * A model that resends the same failing call (same tool, same arguments) is not
 * making progress; session 01a18443 sent one rejected `subagent_spawn` 1482 times.
 * After REPEAT_LIMIT identical failures the third result is annotated with an
 * escalation notice, and any further identical call is blocked with
 * `terminate: true`, which ends the agent run:
 *
 * - top level: the turn ends and the user is told why (escalation to the user);
 * - subagent child (loaded via child-steer in every child): the child run ends and
 *   its final output carries the escalation, which reaches the parent agent.
 *
 * A success of the same call, or new user input, clears the count.
 * Registers no tools and performs no I/O. Children get it from child-steer; the
 * top-level subagents extension registers it only outside a child.
 */

export const REPEAT_LIMIT = 3;

type GuardApi = {
    on(event: string, handler: (event: any, ctx: any) => unknown): void;
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

export function escalationText(toolName: string, count: number, child: boolean): string {
    const who = child
        ? "Stop now and return to the parent agent"
        : "Stop now and ask the user";
    return `REPEATED FAILURE: ${toolName} failed ${count} times with identical arguments. ` +
        `Retrying the same call will not work and further identical calls are blocked. ` +
        `${who}: report the exact error, what you tried, and what you need to proceed. ` +
        `Change the arguments only if the error message says how.`;
}

/** Pure state machine, exported for tests. */
export function createRepeatGuard(limit = REPEAT_LIMIT) {
    const failures = new Map<string, number>();
    return {
        /** Returns the block reason when this exact call already failed `limit` times. */
        check(toolName: string, input: unknown): string | undefined {
            const count = failures.get(callSignature(toolName, input)) ?? 0;
            return count >= limit ? `${count}` : undefined;
        },
        /** Records an outcome; returns the failure count when it just reached `limit`. */
        record(toolName: string, input: unknown, isError: boolean): number | undefined {
            const sig = callSignature(toolName, input);
            if (!isError) { failures.delete(sig); return undefined; }
            const count = (failures.get(sig) ?? 0) + 1;
            failures.set(sig, count);
            return count === limit ? count : undefined;
        },
        reset(): void { failures.clear(); },
    };
}

export function isSubagentChild(env: NodeJS.ProcessEnv = process.env): boolean {
    return Boolean(env.PI_SUBAGENT_STEER_FILE);
}

export default function repeatGuard(pi: GuardApi, options: { child?: boolean; limit?: number } = {}): void {
    const child = options.child ?? isSubagentChild();
    const guard = createRepeatGuard(options.limit ?? REPEAT_LIMIT);

    pi.on("input", () => { guard.reset(); });
    pi.on("session_start", () => { guard.reset(); });

    pi.on("tool_call", (event) => {
        if (event?.parentToolCallId) return undefined;
        const blocked = guard.check(event?.toolName, event?.input);
        if (!blocked) return undefined;
        return { block: true, terminate: true, reason: escalationText(String(event?.toolName), Number(blocked), child) };
    });

    pi.on("tool_result", (event, ctx) => {
        if (event?.parentToolCallId) return undefined;
        const reached = guard.record(event?.toolName, event?.input, event?.isError === true);
        if (reached === undefined) return undefined;
        const text = escalationText(String(event?.toolName), reached, child);
        if (!child) {
            try { ctx?.ui?.notify?.(`Agent stuck: ${event?.toolName} failed ${reached}× with identical arguments.`, "warning"); } catch { /* UI optional */ }
        }
        const content = Array.isArray(event?.content) ? event.content : [];
        return { content: [...content, { type: "text", text: `\n\n${text}` }], isError: true };
    });
}
