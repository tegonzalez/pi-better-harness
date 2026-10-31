/**
 * Launch and exit handling for remote subagent runs (see remote.ts for the schema and commands).
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { failurePath } from "./failures.ts";
import {
    buildEnvPayload,
    buildRemotePlan,
    ensureRemoteMux,
    remoteFailurePath,
    remoteSandboxPath,
    remoteSettledPath,
    stopRemoteProcessAsync,
    writeBridgeConfig,
    type RemotePiOptions,
    type RemoteRunMeta,
    type RemoteSandboxVerification,
    type RemoteStopDeps,
    type RemoteStopResult,
    type RemoteTarget,
} from "./remote.ts";
import { logPathFor, promptPathFor, readMeta, runDir, writeMeta } from "./registry.ts";
import { observeFailures } from "./shared-failure-observations.ts";
import { spawnDetached, type SpawnResult } from "./spawn.ts";

export function bridgeScriptPath(): string {
    return join(dirname(fileURLToPath(import.meta.url)), "remote-bridge.mjs");
}

export interface RemoteLaunchInput {
    id: string;
    targetName: string;
    target: RemoteTarget;
    prompt: string;
    options: RemotePiOptions;
    /** Test seam: skip the ControlMaster and use a plain ssh argv. */
    sshArgvOverride?: string[];
}

/**
 * Establish the reusable ssh ControlMaster (fail closed), write the bridge configuration and start
 * the bridge as a detached local process. The caller records the run metadata.
 */
export async function launchRemoteRun(input: RemoteLaunchInput): Promise<{ spawned: SpawnResult; remote: RemoteRunMeta }> {
    const dir = runDir(input.id);
    const sshArgv = input.sshArgvOverride ?? await ensureRemoteMux(input.target);
    const plan = buildRemotePlan({
        target: input.target, targetName: input.targetName, runId: input.id,
        runDirPath: dir, options: input.options, sshArgv,
    });
    writeFileSync(promptPathFor(input.id), input.prompt);
    const configPath = writeBridgeConfig(dir, { ...plan.bridge, promptPath: promptPathFor(input.id) }, buildEnvPayload(input.target, input.id));
    const spawned = spawnDetached({
        file: process.execPath, fileArgs: [bridgeScriptPath(), configPath],
        cwd: dir, logPath: logPathFor(input.id),
    });
    return { spawned, remote: plan.meta };
}

interface RemoteFailure { kind: string; summary: string; code?: number }

export function readRemoteFailure(id: string): RemoteFailure | undefined {
    const path = remoteFailurePath(runDir(id));
    if (!existsSync(path)) return undefined;
    try {
        const value = JSON.parse(readFileSync(path, "utf8")) as RemoteFailure;
        return typeof value?.kind === "string" && typeof value.summary === "string" ? value : undefined;
    } catch {
        return undefined;
    }
}

/** Failure kinds after which the remote process may still be running: never finalized. */
const REMOTE_MAY_RUN = new Set(["channel-lost", "remote-unstopped"]);

/** True when the remote agent settled (the bridge saw `agent_settled`): the remote work is over. */
export function remoteSettled(id: string): boolean {
    return existsSync(remoteSettledPath(runDir(id)));
}

/** The sandbox verification the bridge recorded before sending the prompt, if any. */
export function readRemoteSandbox(id: string): RemoteSandboxVerification | undefined {
    try {
        const value = JSON.parse(readFileSync(remoteSandboxPath(runDir(id)), "utf8")) as RemoteSandboxVerification;
        return typeof value?.policyHash === "string" && typeof value.planHash === "string" ? value : undefined;
    } catch {
        return undefined;
    }
}

/**
 * One line naming the remote run's workspace (working folder, agent dir) and the verified sandbox hashes, so the
 * owner can compare them with `/sandbox workspace` in their own pi started in the same working folder.
 */
export function remoteWorkspaceLine(id: string, remote: RemoteRunMeta | undefined): string | undefined {
    if (!remote) return undefined;
    const verified = remote.sandbox ?? readRemoteSandbox(id);
    const parts = [
        `cwd ${remote.cwd ?? "(login directory)"}`,
        ...(remote.agentDir ? [`agent dir ${remote.agentDir}`] : []),
        verified ? `policyHash ${verified.policyHash} · planHash ${verified.planHash}` : "sandbox not verified yet",
    ];
    return `Remote workspace (${remote.target}): ${parts.join(" · ")}`;
}

/**
 * True when no remote process can be running for this run without asking the host: the remote
 * agent settled, or the bridge recorded a failure that happened before/instead of any remote work.
 * Such a run needs no ssh to be stopped or dismissed.
 */
export function remoteSurelyGone(id: string): boolean {
    if (remoteSettled(id)) return true;
    const failure = readRemoteFailure(id);
    return failure !== undefined && !REMOTE_MAY_RUN.has(failure.kind);
}

/**
 * Record the incident for a remote run whose bridge exited and say whether the exit should be
 * finalized. The remote process may still be alive after a dropped channel, a failed stop, or a
 * bridge that died without a marker (`abnormal`, when `exit` is given): those are NOT finalized.
 */
export function handleRemoteExit(id: string, now = Date.now(), exit?: { code: number | null }): { finalize: boolean; failure?: RemoteFailure; abnormal?: boolean } {
    const failure = readRemoteFailure(id);
    if (!failure) {
        if (exit && exit.code !== 0 && !remoteSettled(id)) return { finalize: false, abnormal: true };
        return { finalize: true };
    }
    observeFailures(failurePath(id), [{
        id: `remote:${failure.kind}`, operation: `remote:${failure.kind}`, kind: "failure", category: "remote", summary: failure.summary,
    }], now);
    return { finalize: !REMOTE_MAY_RUN.has(failure.kind), failure };
}

export interface ReconcileDeps extends RemoteStopDeps {
    now?: number;
    stop?: (remote: RemoteRunMeta) => Promise<RemoteStopResult>;
}

/**
 * Handle the exit of a remote run's bridge. A bridge that died abnormally (SIGKILL/OOM, no marker)
 * leaves the remote possibly running: run the remote stop, and finalize only when it is verified;
 * otherwise the run stays unfinalized (health marks it orphaned) with an incident. The sandbox
 * verification the bridge recorded is copied into the run metadata (`remote.sandbox`).
 */
export async function reconcileRemoteExit(id: string, code: number | null, deps: ReconcileDeps = {}): Promise<{ finalize: boolean; failure?: RemoteFailure; abnormal?: boolean }> {
    const now = deps.now ?? Date.now();
    const handled = handleRemoteExit(id, now, { code });
    const meta = readMeta(id);
    const verified = readRemoteSandbox(id);
    if (meta?.remote && verified && !meta.remote.sandbox) {
        meta.remote = { ...meta.remote, sandbox: verified };
        try { writeMeta(meta); } catch { /* best effort */ }
    }
    if (!handled.abnormal) return handled;
    const remote = meta?.remote;
    // Already stopped through stopRun (verified there) or otherwise terminal: nothing left to reach.
    if (meta && meta.status !== "running") return { finalize: true, abnormal: true };
    const note = (summary: string, kind: string) => observeFailures(failurePath(id), [{
        id: `remote:${kind}`, operation: `remote:${kind}`, kind: "failure", category: "remote", summary,
    }], now);
    if (!remote) return { finalize: true };
    const result = await (deps.stop ?? ((r) => stopRemoteProcessAsync(r, deps)))(remote);
    if (result.verified) {
        note(`The bridge to ${remote.host} ended abnormally (exit ${code ?? "signal"}); the remote session was stopped and verified gone.`, "bridge-died");
        return { finalize: true, abnormal: true };
    }
    note(`The bridge to ${remote.host} ended abnormally (exit ${code ?? "signal"}) and the remote could not be verified stopped: ${result.reason}. The run is left orphaned; retry subagent_stop.`, "bridge-died-unstopped");
    return { finalize: false, abnormal: true };
}
