/**
 * A remote, resumed or `remoteAgents`-mapped subagent spawn opens an SSH
 * connection from this (unconfined) process and runs the child with network on
 * the target. While the parent's Network access is Off that is network use, so
 * the guard refuses it like any other network-capable tool.
 */
import { readHarnessSetting, type HarnessSettingsSeams } from "./shared-harness-settings.ts";

export const REMOTE_SPAWN_TOOLS: readonly string[] = ["subagent_spawn", "subagent_spawn_batch"];

type Job = { agent?: unknown; remote?: unknown; resume?: unknown };

function present(value: unknown): boolean {
    return typeof value === "string" && value !== "";
}

/** Agent id -> remote target name, from the harness `subagents` setting. Unreadable settings fail closed (undefined). */
export function readRemoteAgents(seams: HarnessSettingsSeams = {}): Record<string, string> | undefined | "unreadable" {
    try {
        const section = readHarnessSetting<{ remoteAgents?: unknown } | undefined>("subagents", seams);
        const map = section?.remoteAgents;
        return map && typeof map === "object" && !Array.isArray(map) ? map as Record<string, string> : undefined;
    } catch {
        return "unreadable";
    }
}

/** Whether this spawn call would run (any job of) the child on a remote target. */
export function spawnUsesRemote(
    name: string,
    input: unknown,
    remoteAgents: () => Record<string, string> | undefined | "unreadable" = readRemoteAgents,
): boolean {
    if (!REMOTE_SPAWN_TOOLS.includes(name) || !input || typeof input !== "object") return false;
    const call = input as Job & { jobs?: unknown };
    const jobs: Job[] = name === "subagent_spawn" ? [call]
        : Array.isArray(call.jobs) ? (call.jobs as Job[]).map((job) => ({
            agent: present(job?.agent) ? job.agent : call.agent,
            remote: present(job?.remote) ? job.remote : call.remote,
            resume: job?.resume,
        })) : [];
    let map: ReturnType<typeof readRemoteAgents> | "unread" = "unread";
    for (const job of jobs) {
        if (present(job.remote) || present(job.resume)) return true;
        if (!present(job.agent)) continue;
        if (map === "unread") map = remoteAgents();
        if (map === "unreadable") return true; // cannot prove it is local
        if (map && Object.hasOwn(map, job.agent as string)) return true;
    }
    return false;
}

export const REMOTE_SPAWN_REFUSAL =
    "Sandbox: Network access is Off. A remote, resumed or remoteAgents-mapped subagent opens an SSH connection and runs with network on another host; turn Network access on in /sandbox or spawn a local subagent.";
