/**
 * Child-side harness control: deliver parent steers into the running child session.
 *
 * Loaded into every subagent child (`--extension`) by the parent. It registers no
 * tools and performs no command I/O. The parent queues steer requests as files
 * in the run's steer directory (path in PI_SUBAGENT_STEER_DIR, see
 * steer-queue.ts); this extension polls it and hands each pending request, in
 * queue order, to Pi's own steering queue (`sendUserMessage` with
 * `deliverAs: "steer"`), which the agent loop reads at the next turn boundary,
 * after the current tool call finishes. When a steer actually enters the
 * conversation (its user `message_end`), it writes that request's receipt, so
 * the parent can report delivery and start a deadline grace period from real
 * delivery rather than from the moment the steer was queued behind a long tool
 * call. A file, not a log line: in print mode an extension's stdout writes are
 * not flushed to the log until exit. This extension runs in the trusted Pi
 * process; the child's confined tools cannot write the run directory, so they
 * cannot forge a receipt.
 *
 * Each request is handed to Pi at most once per child process, and only while
 * the agent is working: an idle print-mode child is about to exit, and a new
 * prompt there would start work instead of steering it. A request that is never
 * delivered keeps no receipt, so the parent reports it as undelivered.
 */
import repeatGuard from "./repeat-guard.ts";
import { STEER_DIR_ENV, listSteerRequests, readSteerReceipt, writeSteerReceipt, type SteerRequest } from "./steer-queue.ts";

export { STEER_DIR_ENV };
const POLL_MS = 2_000;

type SteerApi = {
    on(event: string, handler: (event: any, ctx: { isIdle?: () => boolean }) => unknown): void;
    sendUserMessage(content: string, options?: { deliverAs?: "steer" | "followUp" }): void;
};

function messageText(content: unknown): string {
    return typeof content === "string" ? content
        : Array.isArray(content) ? content.filter((part: any) => part?.type === "text").map((part: any) => part.text).join("\n") : "";
}

export default function childSteer(pi: SteerApi): void {
    // Every child escalates repeated failures or no-progress polling to its parent.
    repeatGuard(pi, { child: true });
    const dir = process.env[STEER_DIR_ENV];
    if (!dir) return;
    /** Request ids handed to Pi in this process. */
    const sent = new Set<string>();
    /** Steer text → requests handed to Pi with that text (FIFO), until each shows up as a user message. */
    const queued = new Map<string, SteerRequest[]>();
    let timer: ReturnType<typeof setInterval> | undefined;
    let isIdle: (() => boolean) | undefined;
    const check = () => {
        const pending = listSteerRequests(dir).filter((request) => !sent.has(request.id) && !readSteerReceipt(dir, request));
        if (pending.length === 0) return;
        try { if (isIdle?.() === true) return; } catch { return; }
        for (const request of pending) {
            sent.add(request.id);
            const waiting = queued.get(request.text) ?? [];
            waiting.push(request);
            queued.set(request.text, waiting);
            try {
                pi.sendUserMessage(request.text, { deliverAs: "steer" });
            } catch {
                waiting.pop();
                if (waiting.length === 0) queued.delete(request.text);
                sent.delete(request.id);
                return; // keep order: retry this and later requests on the next poll
            }
        }
    };
    pi.on("message_end", (event) => {
        const message = event?.message;
        if (message?.role !== "user" || queued.size === 0) return;
        const text = messageText(message.content);
        const waiting = queued.get(text);
        const request = waiting?.shift();
        if (!request) return;
        if (waiting!.length === 0) queued.delete(text);
        try { writeSteerReceipt(dir, request, Date.now()); } catch { /* the parent reports it as pending */ }
    });
    // Pick up a request at a turn boundary too, so it does not wait a whole extra turn for the poll.
    pi.on("turn_end", () => { check(); });
    pi.on("session_start", (_event, ctx) => {
        isIdle = typeof ctx?.isIdle === "function" ? () => ctx.isIdle!() : undefined;
        if (timer) clearInterval(timer);
        timer = setInterval(check, POLL_MS);
        timer.unref?.();
    });
    pi.on("session_shutdown", () => {
        if (timer) clearInterval(timer);
        timer = undefined;
    });
}
