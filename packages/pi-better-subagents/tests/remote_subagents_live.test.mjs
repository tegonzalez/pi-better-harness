/**
 * Live remote-subagent test against a real SSH host. SKIPPED unless configured by environment:
 *
 *   PI_REMOTE_TEST_HOST             ssh Host alias (required; enables the test)
 *   PI_REMOTE_TEST_SANDBOX_PROFILE  remote sandbox profile name (required)
 *   PI_REMOTE_TEST_SANDBOX_ARGS     JSON array of remote pi args, "{profile}" substituted (optional)
 *   PI_REMOTE_TEST_SANDBOX_ENV      JSON object of remote env, "{profile}" substituted (optional)
 *   PI_REMOTE_TEST_SANDBOX_VERIFY   remote shell command that must exit 0 (optional)
 *   PI_REMOTE_TEST_PI               remote pi command (default "pi")
 *   PI_REMOTE_TEST_PI_LOGIN         "1" to start through the remote login shell
 *   PI_REMOTE_TEST_MODEL            model pattern for the remote pi (optional)
 *   PI_REMOTE_TEST_CWD / _ROOT      remote cwd / run-directory root (optional)
 *
 * Scope: only this test's own run-scoped remote directories and the one process recorded in each
 * run's pid file are ever touched. Every run is stopped and its directory removed at the end.
 *
 * // @level live
 */
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { parseRemoteTarget, remoteRunDir } from "../remote.ts";
import { handleRemoteExit, launchRemoteRun } from "../remote-run.ts";
import { finalizeRun } from "../finalization.ts";
import { parseRun } from "../parse.ts";
import { logPathFor, readMeta, runDir, writeMeta } from "../registry.ts";
import { stopRun } from "../stop.ts";

const env = process.env;
const host = env.PI_REMOTE_TEST_HOST;
const profile = env.PI_REMOTE_TEST_SANDBOX_PROFILE;
const skip = !host || !profile ? "set PI_REMOTE_TEST_HOST and PI_REMOTE_TEST_SANDBOX_PROFILE to run" : false;

const targetConfig = () => ({
    host,
    ...(env.PI_REMOTE_TEST_CWD ? { cwd: env.PI_REMOTE_TEST_CWD } : {}),
    ...(env.PI_REMOTE_TEST_ROOT ? { root: env.PI_REMOTE_TEST_ROOT } : {}),
    pi: { command: env.PI_REMOTE_TEST_PI ?? "pi", login: env.PI_REMOTE_TEST_PI_LOGIN === "1" },
    sandbox: {
        profile,
        ...(env.PI_REMOTE_TEST_SANDBOX_ARGS ? { args: JSON.parse(env.PI_REMOTE_TEST_SANDBOX_ARGS) } : {}),
        ...(env.PI_REMOTE_TEST_SANDBOX_ENV ? { env: JSON.parse(env.PI_REMOTE_TEST_SANDBOX_ENV) } : {}),
        ...(env.PI_REMOTE_TEST_SANDBOX_VERIFY ? { verifyCommand: env.PI_REMOTE_TEST_SANDBOX_VERIFY } : {}),
    },
    termGraceSeconds: 10,
});

const runs = [];
let n = 0;
async function startRun(prompt) {
    n += 1;
    const id = `sa_live_${process.pid}_${n}`;
    mkdirSync(runDir(id), { recursive: true });
    const target = parseRemoteTarget(targetConfig(), "live");
    const { spawned, remote } = await launchRemoteRun({
        id, targetName: "live", target, prompt,
        options: { ...(env.PI_REMOTE_TEST_MODEL ? { model: env.PI_REMOTE_TEST_MODEL } : {}), tools: "read,bash" },
    });
    writeMeta({ id, status: "running", pid: spawned.pid, spawnPid: process.pid, cwd: target.cwd ?? "~", promptPreview: prompt.slice(0, 50),
        startedAt: Date.now(), logPath: logPathFor(id), sessionId: id, callback: false, remote });
    runs.push({ id, target, remote });
    return { id, target, remote, exit: spawned.exit };
}

/** Run a shell snippet on the host over plain ssh (BatchMode, no TTY). */
function remoteSh(script) {
    const r = spawnSync("ssh", ["-o", "BatchMode=yes", "-T", "--", host, `sh -c '${script.replace(/'/g, `'\\''`)}'`], { encoding: "utf8", timeout: 30_000 });
    return { code: r.status, out: (r.stdout ?? "").trim() };
}
const remotePid = (id, target) => {
    const r = remoteSh(`cat "${remoteRunDir(target, id)}/pid" 2>/dev/null`);
    return /^\d+$/.test(r.out) ? Number(r.out) : undefined;
};
const remoteAlive = (pid) => remoteSh(`kill -0 ${pid} 2>/dev/null && echo yes || echo no`).out === "yes";

async function until(check, label, ms = 180_000) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
        const v = check();
        if (v) return v;
        await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error(`timed out: ${label}`);
}

after(() => {
    for (const { id, target } of runs) {
        try { if (readMeta(id)?.status === "running") stopRun(id); } catch { /* best effort */ }
        // Only this run's own directory (session file included) is removed.
        remoteSh(`rm -rf "${remoteRunDir(target, id)}"`);
        try { rmSync(runDir(id), { recursive: true, force: true }); } catch { /* */ }
    }
});

describe("remote subagent on a real host", { skip }, () => {
    it("runs a trivial child, is steered over RPC, and reports result and token usage", async () => {
        const { id, exit } = await startRun("Run the shell command `sleep 20` with the bash tool, then reply with the single word: done.");
        await until(() => parseRun(id).toolCalls.length > 0 || parseRun(id).lastActivity, "child active");
        writeFileSync(join(runDir(id), "steer.json"), JSON.stringify({ id: "live-steer", text: "Also include the word steered in your final reply.", at: Date.now() }));
        const code = await exit;
        assert.equal(handleRemoteExit(id).finalize, true, JSON.stringify(handleRemoteExit(id)));
        finalizeRun(id, code);
        assert.equal(readMeta(id).status, "completed");
        assert.ok(existsSync(join(runDir(id), "steer.json.delivered")), "steer receipt");
        const run = parseRun(id);
        assert.ok(run.finalText.length > 0, "result text");
        assert.ok(run.usage.input + run.usage.output > 0, "token usage from get_session_stats");
        assert.ok(run.usage.cacheRead >= 0);
    });

    it("stops a run mid-flight and the remote process is verified gone", async () => {
        const { id, target, exit } = await startRun("Run the shell command `sleep 300` with the bash tool and wait for it.");
        const pid = await until(() => remotePid(id, target), "remote pid file");
        assert.equal(remoteAlive(pid), true);
        const outcome = stopRun(id);
        assert.equal(outcome.action, "stopped");
        assert.equal(remoteAlive(pid), false, "remote process gone after stop");
        await exit;
        assert.equal(readMeta(id).status, "killed");
    });
});
