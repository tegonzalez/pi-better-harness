/**
 * Shared stop / orphaned-cleanup semantics for subagent runs.
 *
 * `stopRun` is the single stop path used by BOTH the model-facing
 * `subagent_stop` tool and the TUI navigator close action (issues #44/#47/#68),
 * so process-group termination and terminal-status recording can never diverge
 * between the two surfaces.
 *
 * Race safety: the run's metadata and effective status are re-read from disk
 * at call time, never taken from a caller's cached copy. A run that finished
 * while a confirmation was pending is reported as not-running instead of
 * being "terminated" against stale state.
 *
 * Orphaned cleanup (#68): when related process-group work is still alive,
 * SIGTERM the recorded group and record durable `killed`. When no related
 * process-group evidence remains, reread the child log and finalize from
 * coherent terminal evidence (`completed` / `failed`) or record `lost`.
 *
 * Process-group-only contract (ADR 0002): related work is the captured
 * process group (pgid, falling back to pid for old metadata). Escaped /
 * reparented descendants outside that group are out of contract and are
 * never scanned for.
 */

import { realProcessProbe, type ProcessProbe } from "./health.ts";
import { parseRunForLifecycle } from "./parse.ts";
import {
    effectiveStatus,
    readMeta,
    writeMeta,
    type RunMeta,
} from "./registry.ts";
import { killProcessTree, processExists } from "./spawn.ts";
import { existsSync, rmSync } from "node:fs";
import { stopRemoteProcess, stopRemoteProcessAsync, type RemoteStopResult, type RemoteRunMeta } from "./remote.ts";
import { remoteSurelyGone } from "./remote-run.ts";
import { failurePath } from "./failures.ts";
import { observeFailures } from "./shared-failure-observations.ts";

export type StopOutcome =
    | { action: "stopped"; id: string }
    | { action: "finalized"; id: string; status: "completed" | "failed" | "lost" }
    | { action: "not-running"; id: string; status: string };

export interface StopDeps {
    /** OS process probe; defaults to the real probe. Tests inject fakes. */
    probe?: ProcessProbe;
    /** Clock seam for durable timestamps. */
    now?: () => number;
    /** Remote termination seam (ssh); defaults to `stopRemoteProcess`. */
    remoteStop?: (remote: RemoteRunMeta) => RemoteStopResult;
    /** Non-blocking remote termination seam used by `stopRunAsync`; defaults to `stopRemoteProcessAsync`. */
    remoteStopAsync?: (remote: RemoteRunMeta) => Promise<RemoteStopResult>;
    /** Bridge signal seam for the RPC abort request; defaults to SIGUSR2 on the bridge pid. */
    signalBridge?: (pid: number) => void;
}

/** Recorded process group for related-work signals (ADR 0002). */
export function relatedProcessGroupId(meta: Pick<RunMeta, "pid" | "pgid">): number | undefined {
    const pgid = meta.pgid ?? meta.pid;
    return typeof pgid === "number" && pgid > 0 ? pgid : undefined;
}

/**
 * True when stop/close may still act on this effective status.
 * `running` is the supervised path; `orphaned` is the #68 cleanup path.
 */
export function isStoppableStatus(status: string): boolean {
    return status === "running" || status === "orphaned";
}

/** SIGTERM the run's related process group. Returns whether a group target existed. */
function terminateRelatedWork(meta: Pick<RunMeta, "pid" | "pgid">): number | undefined {
    const pgid = relatedProcessGroupId(meta);
    if (pgid === undefined) return undefined;
    killProcessTree(pgid, "SIGTERM");
    return pgid;
}

function recordKilled(meta: RunMeta, now: number): StopOutcome {
    meta.status = "killed";
    meta.lifecycleClassification = "killed";
    meta.endedAt = now;
    writeMeta(meta);
    return { action: "stopped", id: meta.id };
}

/**
 * No related process-group evidence remains. Reread logs, then finalize from
 * coherent terminal stream evidence or record durable `lost`.
 */
function finalizeOrphanedWithoutProcess(meta: RunMeta, now: number): StopOutcome {
    // Log authority is reread at cleanup time — never trust a cached parse.
    const run = parseRunForLifecycle(meta.id);

    if (run.sawEnd && run.unmatchedToolCalls.length === 0) {
        meta.status = "completed";
        meta.lifecycleClassification = "complete";
        if (meta.exitCode === undefined) meta.exitCode = 0;
        meta.endedAt = now;
        writeMeta(meta);
        return { action: "finalized", id: meta.id, status: "completed" };
    }

    if (run.sawEnd && run.unmatchedToolCalls.length > 0) {
        meta.status = "failed";
        meta.lifecycleClassification = "incomplete_open_tools";
        meta.failureReason = "incomplete-stream";
        meta.endedAt = now;
        writeMeta(meta);
        return { action: "finalized", id: meta.id, status: "failed" };
    }

    // No coherent terminal completion evidence and no related process remains.
    meta.status = "lost";
    meta.lifecycleClassification = "lost";
    meta.lostAt = now;
    meta.endedAt = now;
    writeMeta(meta);
    return { action: "finalized", id: meta.id, status: "lost" };
}

/**
 * Cleanup path for a durable orphaned run (#68).
 * Shares kill + killed recording with the running-run stop path when the
 * captured process group is still alive; otherwise finalizes from logs.
 */
function cleanupOrphanedRun(meta: RunMeta, probe: ProcessProbe, now: number): StopOutcome {
    const pgid = relatedProcessGroupId(meta);
    if (pgid !== undefined && probe.groupAlive(pgid)) {
        terminateRelatedWork(meta);
        return recordKilled(meta, now);
    }
    return finalizeOrphanedWithoutProcess(meta, now);
}

function sleepSync(ms: number): void {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Step 1 of a remote stop: ask the local bridge to send RPC abort (the caller then waits for the marker). */
function requestRemoteAbort(meta: RunMeta, status: string, deps: StopDeps): boolean {
    const remote = meta.remote!;
    if ((status === "running" || status === "orphaned") && processExists(meta.pid)) {
        try { rmSync(remote.abortDonePath, { force: true }); } catch { /* ignore */ }
        try { (deps.signalBridge ?? ((pid) => process.kill(pid, "SIGUSR2")))(meta.pid); } catch { /* bridge already gone */ }
        return true;
    }
    return false;
}

function abortPending(meta: RunMeta, deadline: number): boolean {
    return !existsSync(meta.remote!.abortDonePath) && Date.now() < deadline && processExists(meta.pid);
}

/** Last step of a remote stop: record the verdict, finalize locally only when the remote is verified gone. */
function finishRemoteStop(meta: RunMeta, status: string, result: RemoteStopResult, now: number): StopOutcome {
    const remote = meta.remote!;
    if (!result.verified) {
        observeFailures(failurePath(meta.id), [{
            id: `remote-stop:${now}`, operation: "remote-stop", kind: "failure", category: "remote",
            summary: `Remote stop on ${remote.host} was not verified: ${result.reason}. The run was left ${status}; retry subagent_stop.`,
        }], now);
        throw new Error(`Remote stop not verified for ${meta.id}: ${result.reason}. The run was left ${status}; retry subagent_stop.`);
    }
    if (status === "running" || status === "orphaned") {
        terminateRelatedWork(meta);
        return recordKilled(meta, now);
    }
    if (status === "lost") return { action: "finalized", id: meta.id, status: "lost" };
    return finalizeOrphanedWithoutProcess(meta, now);
}

/**
 * A finished bridge whose remote work is known to be over (agent settled, or a failure recorded
 * before any remote work) is stopped without ssh: there is nothing to reach.
 */
function remoteNeedsNoSsh(meta: RunMeta, status: string): boolean {
    return (status === "exited" || status === "lost") && remoteSurelyGone(meta.id);
}

/**
 * Remote stop sequence: (1) ask the local bridge to send RPC abort and wait for its marker,
 * (2) terminate the remote session and verify it is gone, (3) only then finalize locally.
 * An unverifiable remote stop fails closed: the run keeps its status and an incident explains why.
 * This variant blocks; the tool/shutdown paths use `stopRunAsync`.
 */
function stopRemoteRun(meta: RunMeta, status: string, probe: ProcessProbe, now: number, deps: StopDeps): StopOutcome {
    if (remoteNeedsNoSsh(meta, status)) {
        return status === "lost" ? { action: "finalized", id: meta.id, status: "lost" } : finalizeOrphanedWithoutProcess(meta, now);
    }
    if (requestRemoteAbort(meta, status, deps)) {
        const deadline = Date.now() + meta.remote!.abortWaitMs;
        while (abortPending(meta, deadline)) sleepSync(50);
    }
    return finishRemoteStop(meta, status, (deps.remoteStop ?? stopRemoteProcess)(meta.remote!), now);
}

async function stopRemoteRunAsync(meta: RunMeta, status: string, now: number, deps: StopDeps): Promise<StopOutcome> {
    if (remoteNeedsNoSsh(meta, status)) {
        return status === "lost" ? { action: "finalized", id: meta.id, status: "lost" } : finalizeOrphanedWithoutProcess(meta, now);
    }
    if (requestRemoteAbort(meta, status, deps)) {
        const deadline = Date.now() + meta.remote!.abortWaitMs;
        while (abortPending(meta, deadline)) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return finishRemoteStop(meta, status, await (deps.remoteStopAsync ?? stopRemoteProcessAsync)(meta.remote!), now);
}

/**
 * Non-blocking `stopRun`: identical semantics, but a remote stop (abort wait + ssh) never blocks the
 * event loop. Local runs take the synchronous path unchanged.
 */
export async function stopRunAsync(id: string, deps: StopDeps = {}): Promise<StopOutcome> {
    const meta = readMeta(id);
    if (!meta) throw new Error(`Unknown run id: ${id}`);
    const status = effectiveStatus(meta);
    if (meta.remote && (status === "running" || status === "orphaned" || status === "exited" || status === "lost")) {
        const now = typeof deps.now === "function" ? deps.now() : Date.now();
        return stopRemoteRunAsync(meta, status, now, deps);
    }
    return stopRun(id, deps);
}

/**
 * Stop or resolve a run by id.
 *
 * - `running` → SIGTERM related process group, durable `killed`.
 * - `orphaned` → terminate identifiable process-group members when alive;
 *   otherwise reread logs and finalize completed/failed/lost.
 * - other statuses → not-running (on-disk record untouched).
 *
 * Throws on an unknown id (same contract as the stop tool).
 */
export function stopRun(id: string, deps: StopDeps = {}): StopOutcome {
    const meta = readMeta(id);
    if (!meta) throw new Error(`Unknown run id: ${id}`);
    const probe = deps.probe ?? realProcessProbe;
    const now = typeof deps.now === "function" ? deps.now() : Date.now();
    const status = effectiveStatus(meta);

    // A remote run is stopped through its remote process first; a lost/exited bridge does not
    // mean the remote pi is gone (SSH channel drop), so those statuses are cleaned up too.
    if (meta.remote && (status === "running" || status === "orphaned" || status === "exited" || status === "lost")) {
        return stopRemoteRun(meta, status, probe, now, deps);
    }

    if (status === "running") {
        // Supervised path: same process-group kill + killed write as before.
        // Prefer recorded pgid so running and orphaned share one target rule.
        terminateRelatedWork(meta);
        return recordKilled(meta, now);
    }

    if (status === "orphaned") {
        return cleanupOrphanedRun(meta, probe, now);
    }

    return { action: "not-running", id, status };
}
