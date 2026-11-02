/**
 * Active `subagent_wait` calls in this process.
 *
 * While an agent waits on a run, an attention notice for that run (failure,
 * stall, orphaned, timing) is handed to the wait and returned in its result,
 * instead of being queued as a follow-up turn that would arrive after the
 * agent's final answer. A claimed notice wakes the wait so the agent can act.
 */

type Waiter = { ids: ReadonlySet<string>; notices: string[]; wake: () => void };

const waiters = new Set<Waiter>();

/** Register a wait on `ids`; call `dispose` when the wait returns. */
export function registerWaiter(ids: Iterable<string>, wake: () => void): { notices: string[]; dispose: () => void } {
    const waiter: Waiter = { ids: new Set(ids), notices: [], wake };
    waiters.add(waiter);
    return { notices: waiter.notices, dispose: () => { waiters.delete(waiter); } };
}

/**
 * Give a run's attention notice to every active wait on that run. Returns false
 * when nobody waits on it, so the caller delivers it as usual.
 */
export function claimUrgentNotice(runId: string, text: string): boolean {
    let claimed = false;
    for (const waiter of waiters) {
        if (!waiter.ids.has(runId)) continue;
        waiter.notices.push(text);
        waiter.wake();
        claimed = true;
    }
    return claimed;
}

/** The slice of an urgent callback event the routing needs. */
export type RoutableUrgentEvent = {
    customType: string;
    id: string;
    status: string;
    content: string;
    isDelivered?: () => boolean;
    getSuppressionReason?: () => string | undefined;
    onDelivered?: (at: number) => void;
};

/** Notices already handed to a wait, by identity, with the handoff time (the batcher's dedupe, for this path). */
const handedToWait = new Map<string, number>();

/**
 * Route one urgent notice: to an active wait on the run if there is one,
 * otherwise to `deliver` (the callback batcher). A notice already handed to a
 * wait is acknowledged again, not repeated. A claimed notice is never also
 * delivered, even if acknowledging it fails.
 */
export function routeUrgentNotice<E extends RoutableUrgentEvent, R>(
    runId: string,
    event: E,
    format: (event: E) => string,
    deliver: (event: E) => R,
): R | boolean {
    const key = `${event.customType}\u0000${event.id}\u0000${event.status}\u0000${event.content}`;
    const prior = handedToWait.get(key);
    if (prior !== undefined) {
        try { event.onDelivered?.(prior); } catch { /* acknowledged before */ }
        return true;
    }
    let eligible = false;
    try {
        eligible = !event.isDelivered?.() && !event.getSuppressionReason?.();
    } catch {
        eligible = false; // metadata unavailable: the batcher defers it as usual
    }
    if (!eligible || !claimUrgentNotice(runId, format(event))) return deliver(event);
    const at = Date.now();
    handedToWait.set(key, at);
    try { event.onDelivered?.(at); } catch { /* the wait already has it */ }
    return true;
}
