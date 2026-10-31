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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync, symlinkSync, statSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRemoteTarget, parseRemoteTargets, selectRemoteTarget, buildLaunchScript, buildEnvPayload, buildStopScript, wrapRemoteScript, stopRemoteProcess, assertRemoteOptionsSupported, effectiveRemoteCwd } from "../remote.ts";
import { handleRemoteExit, launchRemoteRun, reconcileRemoteExit, readRemoteFailure, remoteWorkspaceLine } from "../remote-run.ts";
import { subagentResultTool } from "../tools.ts";
import { nonTempFixtureBase } from "./fixture-base.mjs";
import { finalizeRun } from "../finalization.ts";
import { parseRun } from "../parse.ts";
import { logPathFor, readMeta, runDir, writeMeta, effectiveStatus } from "../registry.ts";
import { stopRun, stopRunAsync } from "../stop.ts";
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
        sandbox: { profile: "profile-a", env: { FAKE_SANDBOX_PROFILE: "{profile}" }, args: ["--sandbox-profile", "{profile}"], verifyTimeoutMs: 20_000 },
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
    it("rejects a sandbox with no way to pass the profile to the remote pi", () => {
        const noCarrier = { profile: "p", args: ["--fixed"], env: { X: "y" }, verifyCommand: "true" };
        assert.throws(() => parseRemoteTarget(targetConfig({ sandbox: noCarrier }), "t"), /no way to pass the profile/);
        assert.doesNotThrow(() => parseRemoteTarget(targetConfig({ sandbox: { profile: "p", env: { X: "{profile}" } } }), "t"));
    });
    it("rejects options a remote run cannot honour instead of dropping them", () => {
        for (const key of ["sandbox", "sandbox_dir", "cwd", "git_clone_workspace", "allow_nested", "clean"]) {
            assert.throws(() => assertRemoteOptionsSupported({ [key]: key === "sandbox_dir" || key === "cwd" ? "/x" : false }), new RegExp(`not supported with a remote target: ${key}`));
        }
        assert.doesNotThrow(() => assertRemoteOptionsSupported({}));
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
        assert.doesNotMatch(script, /FAKE_SANDBOX_PROFILE|extra value/, "environment never rides the command line");
        assert.match(buildEnvPayload(target, "sa_x_1"), /^export FAKE_EXTRA='extra value'\nexport FAKE_SANDBOX_PROFILE='profile-a'\n__PI_REMOTE_ENV_END_sa_x_1__\n$/);
        assert.match(script, /command -v setsid/);
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
        const { id, exit } = await start("anything", { sandbox: { ...targetConfig().sandbox, verifyCommand: "echo no backend >&2; false" } });
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

const sandboxLog = () => piCmds().filter((c) => c.kind === "cmd");
const promptsSent = () => sandboxLog().filter((c) => c.value.type === "prompt").length;
const sandboxIncident = (id) => Object.values(readRunFailures(id).observations).find((o) => o.category === "remote");
const isGone = (pid) => { try { process.kill(pid, 0); } catch { return true; } return spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim().startsWith("Z"); };
const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

describe("remote sandbox is verified, not requested (confinement review #2)", () => {
    it("records policyHash/planHash from the sandbox launch entry and only then sends the prompt", async () => {
        const before = promptsSent();
        const { id, exit } = await start("say done");
        const code = await exit;
        assert.equal(code, 0);
        const handled = await reconcileRemoteExit(id, code);
        assert.equal(handled.finalize, true);
        assert.equal(promptsSent(), before + 1);
        const sandbox = readMeta(id).remote.sandbox;
        assert.equal(sandbox.profile, "profile-a");
        assert.equal(sandbox.policyHash, "policy-hash-1");
        assert.equal(sandbox.planHash, "plan-hash-1");
        assert.ok(readFileSync(logPathFor(id), "utf8").includes("remote_sandbox_verified"));
    });

    for (const [mode, expect] of [["none", /did not report a sandbox launch entry/], ["inactive", /not active/], ["wrong", /expected "profile-a"/], ["stale", /did not report a sandbox launch entry/], ["nohash", /no policyHash/]]) {
        it(`fake pi reporting "${mode}" fails closed: incident, no prompt, remote pi killed`, async () => {
            const before = promptsSent();
            const target = targetConfig({ env: { FAKE_PI_SANDBOX: mode }, sandbox: { ...targetConfig().sandbox, verifyTimeoutMs: 1500 } });
            const { id, exit } = await start("say done", target);
            const rpid = await until(() => existsSync(join(remoteHome, ".pi-better-subagents", "runs", id, "pid")) && remotePid(id), "remote pid");
            const code = await exit;
            assert.equal(code, 96);
            assert.equal(promptsSent(), before, "no prompt reached the remote");
            const handled = handleRemoteExit(id);
            assert.equal(handled.failure.kind, "sandbox-unverified");
            assert.match(handled.failure.summary, expect);
            assert.equal(handled.finalize, true, "remote verified stopped, so the run may finalize");
            assert.equal(isGone(rpid), true, "remote pi was killed");
            assert.equal(sandboxIncident(id).category, "remote");
            assert.equal(readMeta(id).remote.sandbox, undefined);
        });
    }
});

describe("entryProfile (pi-better-sandbox reports its permission profile)", () => {
    it("accepts an entry whose profile differs from the requested name when entryProfile says so, and rejects otherwise", async () => {
        const ok = await start("say done", { env: { FAKE_PI_ENTRY_PROFILE: "main" }, sandbox: { ...targetConfig().sandbox, entryProfile: "main" } });
        assert.equal(await ok.exit, 0);
        const handled = await reconcileRemoteExit(ok.id, 0);
        assert.equal(handled.finalize, true);
        assert.equal(readMeta(ok.id).remote.sandbox.profile, "main");
        const bad = await start("say done", { env: { FAKE_PI_ENTRY_PROFILE: "main" }, sandbox: { ...targetConfig().sandbox, verifyTimeoutMs: 1500 } });
        assert.equal(await bad.exit, 96);
        assert.match(handleRemoteExit(bad.id).failure.summary, /expected "profile-a"/);
    });
});

describe("stop by session id (confinement review #11)", () => {
    it("launch is refused when setsid is missing on the remote", async () => {
        const bin = join(work, "nosetsid-bin");
        mkdirSync(bin, { recursive: true });
        for (const tool of ["sh", "mkdir", "cat", "date", "chmod", "rm", "tr", "ps", "awk", "sleep"]) {
            const found = spawnSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).stdout.trim();
            if (found && !existsSync(join(bin, tool))) symlinkSync(found, join(bin, tool));
        }
        process.env.FAKE_REMOTE_PATH = bin;
        try {
            const before = piCmds().filter((c) => c.kind === "argv").length;
            const { id, exit } = await start("anything");
            const code = await exit;
            assert.equal(code, 95);
            assert.equal(handleRemoteExit(id).failure.kind, "setsid-missing");
            assert.equal(piCmds().filter((c) => c.kind === "argv").length, before, "pi was never started");
        } finally { delete process.env.FAKE_REMOTE_PATH; }
    });

    it("stop refuses to guess when the recorded pid is alive but not a session leader", async () => {
        const target = parseRemoteTarget(targetConfig(), "t");
        const id = `sa_remote_nosid_${process.pid}`;
        const rd = join(remoteHome, ".pi-better-subagents", "runs", id);
        mkdirSync(join(rd, "session"), { recursive: true });
        const victim = spawn("sh", ["-c", "sleep 300; :", "x", join(rd, "session")], { stdio: "ignore" });
        try {
            writeFileSync(join(rd, "pid"), String(victim.pid));
            const remote = { sshArgv: [], login: false, stopScript: buildStopScript(target, id), termGraceSeconds: 1, host: "h" };
            const run = (argv) => { const r = spawnSync("sh", ["-c", argv.at(-1)], { encoding: "utf8", env: { ...process.env, HOME: remoteHome } }); return { status: r.status, stdout: r.stdout, stderr: r.stderr }; };
            const result = stopRemoteProcess(remote, { run });
            assert.equal(result.verified, false);
            assert.match(result.reason, /not a session leader/);
            assert.equal(isGone(victim.pid), false, "nothing was signalled");
        } finally { spawnSync("pkill", ["-KILL", "-P", String(victim.pid)]); victim.kill("SIGKILL"); rmSync(rd, { recursive: true, force: true }); }
    });

    it("kills a grandchild detached into its own process group (same session)", async () => {
        const file = join(work, "grandchild.pid");
        rmSync(file, { force: true });
        const { id, exit } = await start("hang grandchild persist", { env: { FAKE_GRANDCHILD_FILE: file } });
        const gc = Number(await until(() => existsSync(file) && readFileSync(file, "utf8").trim(), "grandchild pid"));
        const rpid = remotePid(id);
        const [pgid, sid] = spawnSync("ps", ["-o", "pgid=,sid=", "-p", String(gc)], { encoding: "utf8" }).stdout.trim().split(/\s+/).map(Number);
        assert.notEqual(pgid, rpid, "the grandchild is in its own process group");
        assert.equal(sid, rpid, "but in the run's session");
        assert.equal(isGone(gc), false);
        assert.deepEqual(stopRun(id), { action: "stopped", id });
        await until(() => isGone(gc), "grandchild gone", 3000);
        assert.equal(isGone(rpid), true);
        await exit;
    });
});

describe("abnormal bridge exit (confinement review #12)", () => {
    it("SIGKILLed bridge: the remote is stopped and verified before the run is finalized", async () => {
        const { id, exit, spawned } = await start("hang and persist");
        await until(() => parseRun(id).lastActivity.includes("working"), "run active");
        const rpid = remotePid(id);
        process.kill(spawned.pid, "SIGKILL");
        const code = await exit;
        assert.equal(code, null);
        assert.equal(isGone(rpid), false, "the remote outlived its bridge");
        const handled = await reconcileRemoteExit(id, code);
        assert.deepEqual([handled.finalize, handled.abnormal], [true, true]);
        assert.equal(isGone(rpid), true, "remote stopped before finalizing");
        assert.ok(Object.values(readRunFailures(id).observations).some((o) => /ended abnormally/.test(o.summary)));
    });

    it("SIGKILLed bridge with an unverifiable remote stop is NOT finalized and stays stoppable", async () => {
        const { id, exit, spawned } = await start("hang and persist");
        await until(() => parseRun(id).lastActivity.includes("working"), "run active");
        const rpid = remotePid(id);
        process.kill(spawned.pid, "SIGKILL");
        const code = await exit;
        const handled = await reconcileRemoteExit(id, code, { stop: async () => ({ verified: false, reason: "ssh down" }) });
        assert.deepEqual([handled.finalize, handled.abnormal], [false, true]);
        assert.equal(readMeta(id).status, "running");
        assert.equal(isGone(rpid), false);
        assert.ok(Object.values(readRunFailures(id).observations).some((o) => /orphaned/.test(o.summary)));
        assert.notEqual(stopRun(id).action, "not-running");
        assert.equal(isGone(rpid), true);
    });
});

describe("non-blocking stop and exited runs (review #19)", () => {
    it("stopRunAsync keeps the event loop running while the remote stop works", async () => {
        const { id, exit } = await start("hang stubborn persist until stopped");
        await until(() => parseRun(id).lastActivity.includes("working"), "run active");
        let ticks = 0;
        const timer = setInterval(() => { ticks += 1; }, 5);
        const outcome = await stopRunAsync(id);
        clearInterval(timer);
        assert.deepEqual(outcome, { action: "stopped", id });
        assert.ok(ticks >= 10, `event loop kept ticking (${ticks})`);
        assert.equal(readMeta(id).status, "killed");
        await exit;
    });

    it("stopping a settled, exited run needs no ssh", async () => {
        const { id, exit } = await start("say done");
        await exit;
        assert.equal(existsSync(join(runDir(id), "remote-settled.json")), true);
        const calls = () => readFileSync(join(sshDir, "calls"), "utf8");
        const before = calls();
        writeFileSync(join(sshDir, "fail"), "1");
        try {
            assert.equal(effectiveStatus(readMeta(id)), "exited");
            const outcome = stopRun(id, { remoteStop: () => { throw new Error("ssh must not be used"); } });
            assert.notEqual(outcome.action, "not-running");
            assert.equal(calls(), before);
        } finally { rmSync(join(sshDir, "fail")); }
    });
});

describe("environment handling (confinement review #14)", () => {
    it("env values never appear on the ssh command line or in the bridge configuration; the staging file is gone", async () => {
        const secret = "very-secret-value-1234";
        const target = parseRemoteTarget(targetConfig({ env: { FAKE_EXTRA: secret } }), "t");
        const { id, exit } = await (async () => {
            const id = `sa_remote_env_${process.pid}`;
            ids.push(id);
            mkdirSync(runDir(id), { recursive: true });
            const { spawned, remote } = await launchRemoteRun({ id, targetName: "t", target, prompt: "say done", options: {} });
            writeMeta({ id, status: "running", pid: spawned.pid, spawnPid: process.pid, cwd: "~", promptPreview: "x", startedAt: Date.now(), logPath: logPathFor(id), sessionId: id, callback: false, remote });
            const envFile = join(runDir(id), "remote-env");
            const mode = existsSync(envFile) ? statSync(envFile).mode & 0o777 : undefined;
            assert.ok(mode === undefined || mode === 0o600, `local env file mode ${mode?.toString(8)}`);
            assert.equal(statSync(join(runDir(id), "remote-bridge.json")).mode & 0o777, 0o600);
            const config = readFileSync(join(runDir(id), "remote-bridge.json"), "utf8");
            assert.equal(config.includes(secret), false, "bridge config has no env values");
            assert.equal(JSON.stringify(remote).includes(secret), false, "run metadata has no env values");
            return { id, exit: spawned.exit };
        })();
        await exit;
        assert.equal(piCmds().filter((c) => c.kind === "env").pop().value.EXTRA, secret, "the remote still received it");
        assert.equal(existsSync(join(runDir(id), "remote-env")), false, "local payload deleted once sent");
        assert.deepEqual(spawnSync("sh", ["-c", `ls "${join(remoteHome, ".pi-better-subagents", "runs", id)}" | grep -c '^env'`], { encoding: "utf8" }).stdout.trim(), "0", "remote staging file removed");
    });
});

describe("resume by run id", () => {
    it("a new remote pi continues the kept session and the sandbox is verified again", async () => {
        const first = await start("say done");
        await first.exit;
        const promptsBefore = promptsSent();
        const resumed = await start("follow up please", {}, { resumeSessionOf: first.id });
        const code = await resumed.exit;
        assert.equal(code, 0);
        const handled = await reconcileRemoteExit(resumed.id, code);
        assert.equal(handled.finalize, true);
        const argv = piCmds().filter((c) => c.kind === "argv").pop().value;
        assert.ok(argv.includes("--continue"));
        assert.equal(argv.includes("--session-id"), false);
        assert.ok(argv[argv.indexOf("--session-dir") + 1].endsWith(`/runs/${first.id}/session`));
        assert.equal(promptsSent(), promptsBefore + 1);
        assert.equal(readMeta(resumed.id).remote.sandbox.planHash, "plan-hash-1", "re-verified for the new process");
        assert.equal(readMeta(resumed.id).remote.resumedFrom, first.id);
    });

    it("a stale sandbox entry from the earlier process does not satisfy the new process", async () => {
        const first = await start("say done");
        await first.exit;
        const before = promptsSent();
        const resumed = await start("again", { env: { FAKE_PI_SANDBOX: "stale" }, sandbox: { ...targetConfig().sandbox, verifyTimeoutMs: 1500 } }, { resumeSessionOf: first.id });
        assert.equal(await resumed.exit, 96);
        assert.equal(handleRemoteExit(resumed.id).failure.kind, "sandbox-unverified");
        assert.equal(promptsSent(), before);
    });

    it("fails closed when the session to resume does not exist on the remote", async () => {
        const resumed = await start("again", {}, { resumeSessionOf: "sa_no_such_run" });
        assert.equal(await resumed.exit, 94);
        assert.equal(handleRemoteExit(resumed.id).failure.kind, "session-missing");
    });
});

describe("review 2: N6 ordering and prompt tracking, N7 policyHash pin", () => {
    it("failClosed writes remote-unstopped before the stop is attempted (a SIGKILLed bridge leaves the may-run marker)", async () => {
        const hold = join(sshDir, "stop-hold");
        writeFileSync(hold, "1");
        try {
            const target = { env: { FAKE_PI_SANDBOX: "none" }, sandbox: { ...targetConfig().sandbox, verifyTimeoutMs: 800 } };
            const { id, spawned } = await start("say done", target);
            await until(() => readRemoteFailure(id)?.kind === "remote-unstopped", "remote-unstopped written while the stop is still held");
            await until(() => existsSync(join(remoteHome, ".pi-better-subagents", "runs", id, "pid")), "remote pid file");
            const rpid = remotePid(id);
            process.kill(spawned.pid, "SIGKILL");
            await spawned.exit;
            const handled = handleRemoteExit(id);
            assert.equal(handled.failure.kind, "remote-unstopped");
            assert.equal(handled.finalize, false, "never finalized while the remote may still run");
            rmSync(hold, { force: true });
            const outcome = stopRun(id);
            assert.notEqual(outcome.action, "not-running");
            await until(() => isGone(rpid), "remote killed by the retried stop", 8000);
        } finally { rmSync(hold, { force: true }); }
    });

    it("after a verified stop the marker becomes sandbox-unverified (finalizable)", async () => {
        const { id, exit } = await start("say done", { env: { FAKE_PI_SANDBOX: "none" }, sandbox: { ...targetConfig().sandbox, verifyTimeoutMs: 800 } });
        assert.equal(await exit, 96);
        assert.equal(readRemoteFailure(id).kind, "sandbox-unverified");
        assert.equal(handleRemoteExit(id).finalize, true);
    });

    it("an ssh drop after the prompt was sent but before any event is lost (not finalized), not ssh-failed", async () => {
        const received = () => piCmds().filter((c) => c.kind === "prompt-received").length;
        const seen = received();
        const { id, exit } = await start("silent hang persist");
        await until(() => received() > seen, "prompt reached the remote");
        await until(() => existsSync(join(remoteHome, ".pi-better-subagents", "runs", id, "pid")), "remote pid file");
        const rpid = remotePid(id);
        writeFileSync(join(sshDir, "drop"), "1");
        const code = await exit;
        rmSync(join(sshDir, "drop"));
        assert.equal(code, 255);
        const handled = handleRemoteExit(id);
        assert.equal(handled.failure.kind, "channel-lost");
        assert.equal(handled.finalize, false);
        stopRun(id);
        await until(() => isGone(rpid), "remote killed", 8000);
    });

    it("a drop before the prompt (no verification yet) is still ssh-failed and finalizable", async () => {
        const { id, exit } = await start("say done", { env: { FAKE_PI_SANDBOX: "none" }, sandbox: { ...targetConfig().sandbox, verifyTimeoutMs: 20_000 } });
        writeFileSync(join(sshDir, "drop"), "1");
        const code = await exit;
        rmSync(join(sshDir, "drop"));
        assert.equal(code, 255);
        const handled = handleRemoteExit(id);
        assert.equal(handled.failure.kind, "ssh-failed");
        assert.equal(handled.finalize, true);
    });

    it("sandbox.policyHash pins the remote policy: a mismatch fails closed, a match passes, absent only records", async () => {
        assert.throws(() => parseRemoteTarget(targetConfig({ sandbox: { ...targetConfig().sandbox, policyHash: "nothex" } }), "t"), /64-character hex/);
        const before = promptsSent();
        const bad = await start("say done", { sandbox: { ...targetConfig().sandbox, policyHash: "a".repeat(64), verifyTimeoutMs: 1500 } });
        assert.equal(await bad.exit, 96);
        const failure = handleRemoteExit(bad.id).failure;
        assert.equal(failure.kind, "sandbox-unverified");
        assert.match(failure.summary, /does not match the pinned sandbox.policyHash/);
        assert.equal(promptsSent(), before, "no prompt on a mismatch");
        // The fake reports policy-hash-1; a pin must be a sha256, so give the fake a matching hash.
        const pin = "b".repeat(64);
        const good = await start("say done", { env: { FAKE_PI_POLICY_HASH: pin }, sandbox: { ...targetConfig().sandbox, policyHash: pin.toUpperCase() } });
        assert.equal(await good.exit, 0);
        assert.equal((await reconcileRemoteExit(good.id, 0)).finalize, true);
        assert.equal(readMeta(good.id).remote.sandbox.policyHash, pin);
    });
});

// ---- workspace binding: per-spawn working folder, agent dir, owner comparison ----------------------------

describe("workspace binding: per-spawn working folder (cwdRoots)", () => {
    // Roots live under an explicit non-temp base (absolute paths on the "remote"), not under the fake HOME.
    const base = mkdtempSync(join(nonTempFixtureBase(here), "remote-cwd-roots-"));
    const rootA = join(base, "allowed");
    const rootEvil = join(base, "allowed-evil");
    const outside = join(base, "elsewhere");
    for (const dir of [join(rootA, "proj1"), join(rootA, "proj2"), join(rootEvil, "p"), outside]) mkdirSync(dir, { recursive: true });
    symlinkSync(outside, join(rootA, "escape"));
    after(() => rmSync(base, { recursive: true, force: true }));
    const roots = { cwd: undefined, cwdRoots: [rootA] };
    const argvCount = () => piCmds().filter((c) => c.kind === "argv").length;
    const lastEnv = () => piCmds().filter((c) => c.kind === "env").pop().value;

    it("validates cwdRoots and agentDir; a spawn cwd needs roots; the fixed form keeps working", () => {
        assert.deepEqual(parseRemoteTarget(targetConfig(roots), "t").cwdRoots, [rootA]);
        assert.throws(() => parseRemoteTarget(targetConfig({ cwdRoots: [] }), "t"), /at least one root/);
        assert.throws(() => parseRemoteTarget(targetConfig({ cwdRoots: ["relative/x"] }), "t"), /absolute or start with/);
        assert.throws(() => parseRemoteTarget(targetConfig({ cwdRoots: ["/"] }), "t"), /filesystem root/);
        assert.throws(() => parseRemoteTarget(targetConfig({ cwdRoots: ["~"] }), "t"), /whole home/);
        assert.throws(() => parseRemoteTarget(targetConfig({ agentDir: "rel" }), "t"), /absolute or start with/);
        assert.throws(() => parseRemoteTarget(targetConfig({ agentDir: "/a", env: { PI_CODING_AGENT_DIR: "/b" } }), "t"), /set by agentDir/);
        assert.throws(() => parseRemoteTarget(targetConfig({ agentDir: "/a", sandbox: { ...targetConfig().sandbox, env: { PI_CODING_AGENT_DIR: "{profile}" } } }), "t"), /set by agentDir/);
        const fixed = parseRemoteTarget(targetConfig(), "t");
        assert.equal(effectiveRemoteCwd(fixed, undefined), "~/work");
        assert.throws(() => effectiveRemoteCwd(fixed, "/x"), /declares no cwdRoots/);
        assert.throws(() => assertRemoteOptionsSupported({ cwd: "/x" }, fixed), /not supported with a remote target: cwd/);
        assert.doesNotThrow(() => assertRemoteOptionsSupported({ cwd: "/x" }, parseRemoteTarget(targetConfig(roots), "t")));
        assert.throws(() => effectiveRemoteCwd(parseRemoteTarget(targetConfig(roots), "t"), "relative"), /absolute or start with/);
    });

    it("the launch script resolves the cwd and the roots on the remote and fails closed", () => {
        const target = parseRemoteTarget(targetConfig(roots), "t");
        const script = buildLaunchScript(target, "sa_x_1", { cwd: join(rootA, "proj1") });
        assert.match(script, /CWD_REAL=\$\(pwd -P\)/);
        assert.match(script, /ROOT_REAL=\$\(cd .*&& pwd -P\) && case "\$CWD_REAL" in "\$ROOT_REAL"\|"\$ROOT_REAL"\/\*\)/);
        assert.match(script, /exit 99/);
        assert.doesNotMatch(buildLaunchScript(parseRemoteTarget(targetConfig(), "t"), "sa_x_1", {}), /cwd_ok/, "the fixed form has no roots check");
    });

    it("each spawn runs in its own folder and its own session", async () => {
        const one = await start("say done", roots, { cwd: join(rootA, "proj1") });
        assert.equal(await one.exit, 0);
        const envOne = lastEnv();
        const argvOne = piCmds().filter((c) => c.kind === "argv").pop().value;
        const two = await start("say done", roots, { cwd: join(rootA, "proj2") });
        assert.equal(await two.exit, 0);
        const envTwo = lastEnv();
        const argvTwo = piCmds().filter((c) => c.kind === "argv").pop().value;
        assert.equal(envOne.cwd, join(rootA, "proj1"));
        assert.equal(envTwo.cwd, join(rootA, "proj2"));
        assert.notEqual(one.id, two.id);
        const sessionOf = (argv) => argv[argv.indexOf("--session-id") + 1];
        assert.equal(sessionOf(argvOne), one.id);
        assert.equal(sessionOf(argvTwo), two.id);
        assert.notEqual(argvOne[argvOne.indexOf("--session-dir") + 1], argvTwo[argvTwo.indexOf("--session-dir") + 1]);
        assert.equal(readMeta(one.id).remote.cwd, join(rootA, "proj1"), "the run records the working folder it used");
        assert.equal(one.remote.cwd, join(rootA, "proj1"));
    });

    for (const [label, cwd] of [
        ["a sibling that only shares the prefix", join(rootEvil, "p")],
        ["a symlink inside a root that escapes it", join(rootA, "escape")],
        ["a dot-dot traversal out of the root", join(rootA, "..", "elsewhere")],
        ["the root's parent", base],
    ]) {
        it(`refuses ${label} before pi starts`, async () => {
            const before = argvCount();
            const { id, exit } = await start("say done", roots, { cwd });
            assert.equal(await exit, 99);
            const handled = handleRemoteExit(id);
            assert.equal(handled.failure.kind, "cwd-denied");
            assert.equal(argvCount(), before, "pi was never started");
        });
    }

    it("a missing folder is cwd-missing, and with roots the login directory is checked too", async () => {
        const missing = await start("say done", roots, { cwd: join(rootA, "nope") });
        assert.equal(await missing.exit, 97);
        assert.equal(handleRemoteExit(missing.id).failure.kind, "cwd-missing");
        const before = argvCount();
        const login = await start("say done", { cwd: undefined, cwdRoots: [rootA] });
        assert.equal(await login.exit, 99, "no cwd: the remote login directory is outside the roots");
        assert.equal(argvCount(), before);
    });

    it("the target's fixed cwd is also held to the roots", async () => {
        const inside = await start("say done", { cwd: join(rootA, "proj1"), cwdRoots: [rootA] });
        assert.equal(await inside.exit, 0);
        const outsideRun = await start("say done", { cwd: outside, cwdRoots: [rootA] });
        assert.equal(await outsideRun.exit, 99);
    });

    it("a spawn cwd for a target without cwdRoots is rejected, never ignored", async () => {
        await assert.rejects(start("say done", {}, { cwd: join(rootA, "proj1") }), /declares no cwdRoots/);
    });
});

describe("workspace binding: agent dir and owner comparison", () => {
    it("exports PI_CODING_AGENT_DIR for the remote pi (not on the command line), expanding ~/ remotely", async () => {
        const target = parseRemoteTarget(targetConfig({ agentDir: "~/agents/ws one" }), "t");
        assert.match(buildEnvPayload(target, "sa_x_1"), /export PI_CODING_AGENT_DIR="\$HOME"\/'agents\/ws one'\n/);
        assert.doesNotMatch(buildLaunchScript(target, "sa_x_1", {}), /agents\/ws one/);
        const run = await start("say done", { agentDir: "~/agents/ws1" });
        assert.equal(await run.exit, 0);
        const env = piCmds().filter((c) => c.kind === "env").pop().value;
        assert.equal(env.AGENT_DIR, join(remoteHome, "agents", "ws1"));
        assert.equal(run.remote.agentDir, "~/agents/ws1");
        const absolute = await start("say done", { agentDir: "/absolute/agent-dir" });
        await absolute.exit;
        assert.equal(piCmds().filter((c) => c.kind === "env").pop().value.AGENT_DIR, "/absolute/agent-dir");
    });

    it("a target without agentDir leaves the remote's own agent dir alone", async () => {
        const run = await start("say done");
        await run.exit;
        assert.equal(piCmds().filter((c) => c.kind === "env").pop().value.AGENT_DIR, process.env.PI_CODING_AGENT_DIR, "only what the remote login environment already had");
    });

    it("subagent_result names the workspace and the verified policyHash/planHash for comparison", async () => {
        const { id, exit } = await start("say done", { agentDir: "~/agents/ws1", cwd: "~/work" });
        const code = await exit;
        assert.equal((await reconcileRemoteExit(id, code)).finalize, true);
        finalizeRun(id, code);
        const meta = readMeta(id);
        const line = remoteWorkspaceLine(id, meta.remote);
        assert.match(line, /^Remote workspace \(t\): cwd ~\/work · agent dir ~\/agents\/ws1 · policyHash policy-hash-1 · planHash plan-hash-1$/);
        const TypeStub = { Object: (v) => v, String: (v) => v, Number: (v) => v, Boolean: (v) => v, Array: (v) => v, Optional: (v) => v };
        const out = (await subagentResultTool(TypeStub).execute("tc", { id })).content[0].text.split("\n");
        assert.match(out[0], /^\[/, "the head line stays first");
        assert.equal(out[1], line);
        assert.equal(remoteWorkspaceLine("none", undefined), undefined);
    });
});
