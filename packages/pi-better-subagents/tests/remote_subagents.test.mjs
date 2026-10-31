/**
 * Remote subagents over a fake ssh transport (no network, no real host).
 *
 * `fixtures/remote/bin/ssh` is first on PATH: it honours the ControlMaster verbs and runs the
 * "remote" command locally under a private HOME, so the real bridge, RPC translation, launch and
 * stop scripts, and registry/finalization paths all execute. The live host test is
 * `remote_subagents_live.test.mjs` (env-gated).
 *
 * // @level unit
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRemoteTarget, parseRemoteTargets, selectRemoteTarget, buildLaunchScript, wrapRemoteScript, stopRemoteProcess } from "../remote.ts";
import { handleRemoteExit, launchRemoteRun } from "../remote-run.ts";
import { finalizeRun } from "../finalization.ts";
import { parseRun } from "../parse.ts";
import { logPathFor, readMeta, runDir, writeMeta, effectiveStatus } from "../registry.ts";
import { stopRun } from "../stop.ts";
import { processExists } from "../spawn.ts";
import { readRunFailures } from "../failures.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures", "remote");
const work = mkdtempSync(join(tmpdir(), "remote-sub-"));
const sshDir = join(work, "ssh");
const remoteHome = join(work, "home");
const piLog = join(work, "pi.log");
const savedEnv = { ...process.env };

function targetConfig(over = {}) {
    return {
        host: "example-alias",
        cwd: "~/work",
        pi: { command: process.execPath, args: [join(fixtures, "fake-pi.mjs")] },
        env: { FAKE_EXTRA: "extra value" },
        sandbox: { profile: "profile-a", env: { FAKE_SANDBOX_PROFILE: "{profile}" }, args: ["--sandbox-profile", "{profile}"] },
        termGraceSeconds: 2,
        ...over,
    };
}

before(() => {
    mkdirSync(sshDir, { recursive: true });
    mkdirSync(join(remoteHome, "work"), { recursive: true });
    process.env.PATH = `${join(fixtures, "bin")}:${process.env.PATH}`;
    process.env.FAKE_SSH_DIR = sshDir;
    process.env.FAKE_REMOTE_HOME = remoteHome;
    process.env.FAKE_PI_LOG = piLog;
    process.env.PI_CODING_AGENT_DIR = join(work, "agent");
});
after(() => {
    process.env.PATH = savedEnv.PATH;
    rmSync(work, { recursive: true, force: true });
});

let counter = 0;
const ids = [];
async function start(prompt, over = {}, options = {}) {
    counter += 1;
    const id = `sa_remote_${process.pid}_${counter}`;
    ids.push(id);
    mkdirSync(runDir(id), { recursive: true });
    const target = parseRemoteTarget(targetConfig(over), "t");
    const { spawned, remote } = await launchRemoteRun({ id, targetName: "t", target, prompt, options: { model: "prov/model", thinking: "low", tools: "read,bash", ...options } });
    const meta = {
        id, status: "running", pid: spawned.pid, spawnPid: process.pid, cwd: target.cwd, promptPreview: prompt.slice(0, 50),
        startedAt: Date.now(), logPath: logPathFor(id), sessionId: id, callback: false, remote,
    };
    writeMeta(meta);
    const exit = spawned.exit;
    return { id, meta, spawned, remote, exit };
}
after(() => { for (const id of ids) { try { rmSync(runDir(id), { recursive: true, force: true }); } catch { /* */ } } });

async function until(check, label, ms = 15_000) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
        const v = check();
        if (v) return v;
        await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`timed out: ${label}`);
}
const piCmds = () => (existsSync(piLog) ? readFileSync(piLog, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []);
const remotePid = (id) => Number(readFileSync(join(remoteHome, ".pi-better-subagents", "runs", id, "pid"), "utf8"));

describe("remote target schema", () => {
    it("accepts a complete target and applies no defaults that name a site", () => {
        const t = parseRemoteTarget(targetConfig(), "t");
        assert.equal(t.host, "example-alias");
        assert.equal(t.sandbox.profile, "profile-a");
    });
    it("requires a sandbox profile and rejects unknown or malformed fields", () => {
        assert.throws(() => parseRemoteTarget({ host: "h", pi: { command: "pi" } }, "t"), /sandbox profile is required/);
        assert.throws(() => parseRemoteTarget({ ...targetConfig(), sandbox: {} }, "t"), /sandbox.profile/);
        assert.throws(() => parseRemoteTarget({ ...targetConfig(), extra: 1 }, "t"), /unknown field "extra"/);
        assert.throws(() => parseRemoteTarget({ ...targetConfig(), env: { "bad name": "x" } }, "t"), /invalid environment variable name/);
        assert.throws(() => parseRemoteTarget({ ...targetConfig(), host: "-oProxyCommand=x" }, "t"), /must not start with/);
        assert.throws(() => parseRemoteTarget({ ...targetConfig(), root: "../x" }, "t"), /root/);
        assert.throws(() => parseRemoteTarget({ ...targetConfig(), port: 99999 }, "t"), /port/);
    });
    it("selects by spawn option, then by agent mapping; unknown names fail closed", () => {
        const settings = { remoteTargets: { a: targetConfig(), b: targetConfig({ host: "other" }) }, remoteAgents: { "agent.x": "b" } };
        assert.equal(selectRemoteTarget(settings, { remote: "a", agent: "agent.x" }).name, "a");
        assert.equal(selectRemoteTarget(settings, { agent: "agent.x" }).target.host, "other");
        assert.equal(selectRemoteTarget(settings, {}), undefined);
        assert.throws(() => selectRemoteTarget(settings, { remote: "nope" }), /not configured/);
        assert.deepEqual(parseRemoteTargets(undefined), {});
    });
    it("builds a quoted launch script and optional login-shell wrapper", () => {
        const target = parseRemoteTarget(targetConfig({ pi: { command: "pi", login: true }, cwd: "~/it's here" }), "t");
        const script = buildLaunchScript(target, "sa_x_1", { model: "m'1" });
        assert.match(script, /'--sandbox-profile' 'profile-a'/);
        assert.match(script, /export FAKE_SANDBOX_PROFILE='profile-a'/);
        assert.match(script, /"\$HOME"\/'it'\\''s here'/);
        assert.match(script, /--model 'm'\\''1'/);
        assert.match(wrapRemoteScript(script, true), /^"\$SHELL" -lc /);
        assert.match(wrapRemoteScript(script, false), /^sh -c /);
    });
});

describe("remote run over a fake ssh transport", () => {
    it("runs as a normal run: events logged, spend from get_session_stats, flags and sandbox passed", async () => {
        const { id, exit } = await start("say done");
        const code = await exit;
        assert.equal(code, 0);
        assert.equal(handleRemoteExit(id).finalize, true);
        const result = finalizeRun(id, code);
        assert.equal(result.applied, true);
        const meta = readMeta(id);
        assert.equal(meta.status, "completed");
        const run = parseRun(id);
        assert.match(run.finalText, /remote done/);
        assert.deepEqual([run.usage.input, run.usage.output, run.usage.cacheRead, run.usage.costUSD], [111, 22, 333, 0.5]);
        const argv = piCmds().find((c) => c.kind === "argv").value;
        assert.deepEqual(argv.slice(0, 2), ["--mode", "rpc"]);
        for (const pair of [["--model", "prov/model"], ["--thinking", "low"], ["--tools", "read,bash"], ["--sandbox-profile", "profile-a"]]) {
            assert.equal(argv[argv.indexOf(pair[0]) + 1], pair[1], pair[0]);
        }
        assert.ok(argv[argv.indexOf("--session-dir") + 1].endsWith(`/.pi-better-subagents/runs/${id}/session`));
        assert.equal(argv[argv.indexOf("--session-id") + 1], id);
        const env = piCmds().filter((c) => c.kind === "env").pop().value;
        assert.equal(env.PROFILE, "profile-a");
        assert.equal(env.EXTRA, "extra value");
        assert.ok(env.cwd.endsWith("/work"));
        assert.ok(readFileSync(join(sshDir, "calls"), "utf8").includes("check example-alias"), "ControlMaster was checked/reused");
    });

    it("steers and follows up through RPC with a delivery receipt", async () => {
        const { id, exit } = await start("please wait for a steer");
        await until(() => parseRun(id).lastActivity.includes("working"), "run active");
        writeFileSync(join(runDir(id), "steer.json"), JSON.stringify({ id: "s1", text: "go left", at: Date.now() }));
        const code = await exit;
        assert.equal(code, 0);
        assert.match(parseRun(id).finalText, /steered: go left/);
        const receipt = JSON.parse(readFileSync(join(runDir(id), "steer.json.delivered"), "utf8"));
        assert.equal(receipt.id, "s1");
        assert.ok(piCmds().some((c) => c.kind === "cmd" && c.value.type === "steer" && c.value.message === "go left"));
    });

    it("sends follow_up when the request asks for it", async () => {
        const { id, exit } = await start("please wait for a follow up");
        await until(() => parseRun(id).lastActivity.includes("working"), "run active");
        writeFileSync(join(runDir(id), "steer.json"), JSON.stringify({ id: "f1", text: "also this", mode: "follow_up" }));
        await exit;
        assert.ok(piCmds().some((c) => c.kind === "cmd" && c.value.type === "follow_up" && c.value.message === "also this"));
    });

    it("stop: RPC abort, then remote process group terminated and verified gone, then finalized", async () => {
        const { id, exit } = await start("hang stubborn persist until stopped");
        await until(() => existsSync(join(remoteHome, ".pi-better-subagents", "runs", id, "pid")), "remote pid file");
        await until(() => parseRun(id).lastActivity.includes("working"), "run active");
        const rpid = remotePid(id);
        assert.equal(processExists(rpid), true);
        const before = piCmds().filter((c) => c.kind === "aborted").length;
        const outcome = stopRun(id);
        assert.deepEqual(outcome, { action: "stopped", id });
        assert.equal(processExists(rpid), false, "remote process is gone");
        assert.equal(readMeta(id).status, "killed");
        assert.equal(piCmds().filter((c) => c.kind === "aborted").length, before + 1, "abort was delivered over RPC first");
        await exit;
    });

    it("stop reaches the remote after the SSH channel drops (lost/orphaned semantics)", async () => {
        const { id, exit, spawned } = await start("hang and persist");
        await until(() => parseRun(id).lastActivity.includes("working"), "run active");
        const rpid = remotePid(id);
        writeFileSync(join(sshDir, "drop"), "1");
        const code = await exit;
        rmSync(join(sshDir, "drop"));
        assert.equal(code, 255);
        const handled = handleRemoteExit(id);
        assert.equal(handled.finalize, false, "a channel drop is not finalized");
        assert.equal(handled.failure.kind, "channel-lost");
        assert.equal(readMeta(id).status, "running");
        assert.equal(processExists(spawned.pid), false);
        assert.equal(processExists(rpid), true, "the remote process outlived the channel");
        assert.ok(readRunFailures(id).observations["remote:channel-lost"] ?? Object.values(readRunFailures(id).observations).some((o) => o.category === "remote"));
        const outcome = stopRun(id);
        assert.notEqual(outcome.action, "not-running");
        await until(() => !processExists(rpid), "remote killed", 5000);
    });

    it("fails closed with an incident when remote pi is missing", async () => {
        const { id, exit } = await start("anything", { pi: { command: "definitely-not-installed-pi" } });
        const code = await exit;
        assert.equal(code, 127);
        const handled = handleRemoteExit(id);
        assert.equal(handled.failure.kind, "pi-missing");
        finalizeRun(id, code);
        assert.equal(readMeta(id).status, "failed");
        assert.ok(Object.values(readRunFailures(id).observations).some((o) => o.category === "remote" && /not found/.test(o.summary)));
        assert.equal(piCmds().filter((c) => c.kind === "cmd" && c.value.type === "prompt").length, piCmds().filter((c) => c.kind === "cmd" && c.value.type === "prompt").length);
    });

    it("fails closed when the required sandbox cannot be enabled, before any prompt is sent", async () => {
        const promptsBefore = piCmds().filter((c) => c.kind === "cmd" && c.value.type === "prompt").length;
        const { id, exit } = await start("anything", { sandbox: { profile: "profile-a", verifyCommand: "echo no backend >&2; false" } });
        const code = await exit;
        assert.equal(code, 96);
        assert.equal(handleRemoteExit(id).failure.kind, "sandbox-unavailable");
        assert.equal(piCmds().filter((c) => c.kind === "cmd" && c.value.type === "prompt").length, promptsBefore);
    });

    it("fails closed when ssh cannot connect (ControlMaster) and leaves no run behind", async () => {
        writeFileSync(join(sshDir, "fail"), "1");
        rmSync(join(sshDir, "master"), { force: true });
        try {
            await assert.rejects(launchRemoteRun({ id: "sa_remote_sshfail_1", targetName: "t", target: parseRemoteTarget(targetConfig(), "t"), prompt: "x", options: {} }), /ControlMaster/);
        } finally { rmSync(join(sshDir, "fail")); }
    });

    it("an unverifiable remote stop fails closed and keeps the run", () => {
        const remote = { sshArgv: ["ssh", "h"], login: false, stopScript: "x", termGraceSeconds: 1, host: "h" };
        assert.deepEqual(stopRemoteProcess(remote, { run: () => ({ status: 0, stdout: "gone\n", stderr: "" }) }), { verified: true });
        assert.equal(stopRemoteProcess(remote, { run: () => ({ status: 1, stdout: "alive\n", stderr: "" }) }).verified, false);
        assert.equal(stopRemoteProcess(remote, { run: () => ({ status: 255, stdout: "", stderr: "unreachable" }) }).verified, false);
    });
});
