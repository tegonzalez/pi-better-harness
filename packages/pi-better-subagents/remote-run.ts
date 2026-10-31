/**
 * Launch and exit handling for remote subagent runs (see remote.ts for the schema and commands).
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { failurePath } from "./failures.ts";
import {
    buildRemotePlan,
    ensureRemoteMux,
    remoteFailurePath,
    writeBridgeConfig,
    type RemotePiOptions,
    type RemoteRunMeta,
    type RemoteTarget,
} from "./remote.ts";
import { logPathFor, promptPathFor, runDir } from "./registry.ts";
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
    const configPath = writeBridgeConfig(dir, { ...plan.bridge, promptPath: promptPathFor(input.id) });
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

/**
 * Record the incident for a remote run whose bridge exited and say whether the exit should be
 * finalized. A dropped SSH channel is NOT finalized: the remote process may still be alive, so the
 * run stays for health reconciliation (orphaned/lost) and `subagent_stop` still reaches the remote.
 */
export function handleRemoteExit(id: string, now = Date.now()): { finalize: boolean; failure?: RemoteFailure } {
    const failure = readRemoteFailure(id);
    if (!failure) return { finalize: true };
    observeFailures(failurePath(id), [{
        id: `remote:${failure.kind}`, operation: `remote:${failure.kind}`, kind: "failure", category: "remote", summary: failure.summary,
    }], now);
    return { finalize: failure.kind !== "channel-lost", failure };
}
