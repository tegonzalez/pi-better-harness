/**
 * Parent → child steer queue (shared by the parent host and child-steer.ts).
 *
 * One directory per run (`<runDir>/steer/`). Each steer request is its own file,
 * written tmp-then-rename so the child never reads a partial request. File names
 * sort in request order (zero-padded request time, then a per-process sequence),
 * so the child delivers pending requests in the order the parent queued them.
 * When a request enters the child's conversation, the child writes a receipt
 * next to it. A request without a receipt is pending; the parent never deletes
 * requests, so an undelivered steer is still visible after the run ends.
 *
 * Pure filesystem helpers; no Pi APIs, no registry, so the child can load it.
 */
import { randomBytes } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Child env: the run's steer queue directory. */
export const STEER_DIR_ENV = "PI_SUBAGENT_STEER_DIR";

const REQUEST_SUFFIX = ".request.json";
const RECEIPT_SUFFIX = ".receipt.json";

export type SteerKind = "parent" | "deadline";

export interface SteerRequest {
    id: string;
    text: string;
    at: number;
    kind: SteerKind;
    /** File base name (without suffix); the receipt shares it. */
    base: string;
}

export interface SteerReceipt {
    id: string;
    at: number;
}

export interface SteerQueueStatus {
    requests: SteerRequest[];
    pending: SteerRequest[];
    delivered: number;
    lastDeliveredAt?: number;
    receipts: Map<string, SteerReceipt>;
}

/** The queue directory inside a run directory. */
export function steerDirIn(runDirectory: string): string {
    return join(runDirectory, "steer");
}

/** A fresh request id for a parent steer. */
export function newSteerId(now: number = Date.now()): string {
    return `st_${now.toString(36)}_${randomBytes(4).toString("hex")}`;
}

/** Framing for a parent's amendment, so the child knows where it comes from. */
export const PARENT_STEER_PREFIX = "Instruction amendment from your parent:";

export function formatParentSteer(message: string): string {
    return `${PARENT_STEER_PREFIX}\n\n${message.trim()}`;
}

let sequence = 0;

function safeId(id: string): string {
    return id.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 80);
}

function parseRequest(raw: string, base: string): SteerRequest | undefined {
    try {
        const value = JSON.parse(raw) as { id?: unknown; text?: unknown; at?: unknown; kind?: unknown };
        if (typeof value?.id !== "string" || typeof value.text !== "string" || value.text.trim() === "") return undefined;
        const at = typeof value.at === "number" && Number.isFinite(value.at) ? value.at : 0;
        return { id: value.id, text: value.text, at, kind: value.kind === "deadline" ? "deadline" : "parent", base };
    } catch {
        return undefined;
    }
}

/** All readable requests in queue order. A missing directory is an empty queue. */
export function listSteerRequests(dir: string): SteerRequest[] {
    let names: string[];
    try { names = readdirSync(dir); } catch { return []; }
    const out: SteerRequest[] = [];
    for (const name of names.filter((n) => n.endsWith(REQUEST_SUFFIX)).sort()) {
        const base = name.slice(0, -REQUEST_SUFFIX.length);
        let raw: string;
        try { raw = readFileSync(join(dir, name), "utf8"); } catch { continue; }
        const request = parseRequest(raw, base);
        if (request) out.push(request);
    }
    return out;
}

/**
 * Queue one steer. A request id already in the queue is not queued twice
 * (the deadline steer is retried after a crash between enqueue and its marker).
 */
export function enqueueSteer(dir: string, input: { id: string; text: string; kind?: SteerKind; at?: number }): SteerRequest {
    if (input.text.trim() === "") throw new Error("A steer needs non-empty text.");
    mkdirSync(dir, { recursive: true });
    const existing = listSteerRequests(dir).find((request) => request.id === input.id);
    if (existing) return existing;
    const at = input.at ?? Date.now();
    sequence = (sequence + 1) % 1_000_000;
    const base = `${String(Math.max(0, Math.trunc(at))).padStart(15, "0")}-${String(sequence).padStart(6, "0")}-${safeId(input.id)}`;
    const kind = input.kind ?? "parent";
    const path = join(dir, `${base}${REQUEST_SUFFIX}`);
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ id: input.id, text: input.text, at, kind }));
    renameSync(tmp, path);
    return { id: input.id, text: input.text, at, kind, base };
}

export function readSteerReceipt(dir: string, request: Pick<SteerRequest, "id" | "base">): SteerReceipt | undefined {
    try {
        const value = JSON.parse(readFileSync(join(dir, `${request.base}${RECEIPT_SUFFIX}`), "utf8")) as { id?: unknown; at?: unknown };
        return value?.id === request.id && typeof value.at === "number" && Number.isFinite(value.at) ? { id: value.id, at: value.at } : undefined;
    } catch {
        return undefined;
    }
}

/** Child side: record that a request entered the conversation. */
export function writeSteerReceipt(dir: string, request: Pick<SteerRequest, "id" | "base">, at: number = Date.now()): void {
    const path = join(dir, `${request.base}${RECEIPT_SUFFIX}`);
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ id: request.id, at }));
    renameSync(tmp, path);
}

/** The receipt for the request with this id, if it was delivered. */
export function receiptForId(dir: string, id: string): SteerReceipt | undefined {
    const request = listSteerRequests(dir).find((r) => r.id === id);
    return request ? readSteerReceipt(dir, request) : undefined;
}

export function steerQueueStatus(dir: string): SteerQueueStatus {
    const requests = listSteerRequests(dir);
    const receipts = new Map<string, SteerReceipt>();
    const pending: SteerRequest[] = [];
    let lastDeliveredAt: number | undefined;
    for (const request of requests) {
        const receipt = readSteerReceipt(dir, request);
        if (!receipt) { pending.push(request); continue; }
        receipts.set(request.id, receipt);
        lastDeliveredAt = Math.max(lastDeliveredAt ?? receipt.at, receipt.at);
    }
    return { requests, pending, delivered: receipts.size, lastDeliveredAt, receipts };
}

/**
 * Steer facts for a status-cursor content revision: each request id with its
 * receipt (id and time) or null while pending. A newly queued steer and a
 * pending → delivered transition both change it; an empty queue is [].
 */
export function steerRevisionFacts(dir: string): Array<[string, string | null, number | null]> {
    return listSteerRequests(dir).map((request) => {
        const receipt = readSteerReceipt(dir, request);
        return [request.id, receipt?.id ?? null, receipt?.at ?? null];
    });
}

/** Compact list-row token, or "" when the run was never steered. */
export function formatSteerShort(status: SteerQueueStatus, running: boolean): string {
    if (status.requests.length === 0) return "";
    const pending = status.pending.length;
    const pendingText = pending === 0 ? "" : running ? `, ${pending} pending` : `, ${pending} UNDELIVERED`;
    return `steer: ${status.delivered} delivered${pendingText}`;
}

/** One diagnostic line for subagent_output / subagent_result, or undefined when never steered. */
export function formatSteerLine(status: SteerQueueStatus, running: boolean): string | undefined {
    if (status.requests.length === 0) return undefined;
    const last = status.lastDeliveredAt !== undefined ? ` (last ${new Date(status.lastDeliveredAt).toISOString()})` : "";
    const delivered = `${status.delivered} delivered${last}`;
    const pending = status.pending.length;
    if (pending === 0) return `Steer: ${delivered}, 0 pending.`;
    const ids = status.pending.map((r) => r.id).join(", ");
    if (running) return `Steer: ${delivered}, ${pending} pending (${ids}) — delivered at the child's next turn boundary.`;
    return `Steer: ${delivered}; ${pending} NOT delivered — no delivery receipt when the run ended (${ids}).`;
}

/** Completion-callback note for steers without a receipt at run end, or undefined when none. */
export function formatUndeliveredSteerNote(status: SteerQueueStatus): string | undefined {
    const pending = status.pending.length;
    if (pending === 0) return undefined;
    const ids = status.pending.map((r) => r.id).join(", ");
    return `${pending} steer${pending === 1 ? "" : "s"} NOT delivered (no delivery receipt): ${ids}.`;
}
