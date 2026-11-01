/**
 * Remote session limits (`resources.session`), run cases, on the
 * local launch-script path: the real bridge, launch script and stop script run over the fake ssh
 * transport (tests/fixtures/remote), so the "remote" command runs locally.
 *
 *   1. With a stand-in systemd-run (no systemd needed): the run record and the result tool show the
 *      configured limits, unset limits show nothing, a failed scope fails the run closed with a
 *      recorded reason, and the RPC session survives the scope wrapper.
 *   2. With real `systemd-run --user` and SMALL caps (skipped with a reason when no user manager or
 *      controller is available): pi and a child it starts share one transient scope carrying the
 *      configured properties; stop and kill leave no process and no scope; RuntimeMaxSec ends a
 *      hanging run; an unreachable user manager fails closed with a recorded reason.
 *
 * Expectations come from the documented limit keys and from systemd/kernel semantics, not from product output.
 * These real-systemd skips are not turned into failures by PI_SANDBOX_REQUIRE_BACKEND (it names sandbox
 * backends, and a systemd user manager is not one); no case here uses bubblewrap.
 * Every scope the tests create is stopped in a finally/after hook.
 *
 * // @level integration
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, join } from "node:path";
import { parseRemoteTarget } from "../remote.ts";
import { handleRemoteExit, launchRemoteRun, readRemoteFailure, reconcileRemoteExit } from "../remote-run.ts";
import { subagentResultTool } from "../tools.ts";
import { finalizeRun } from "../finalization.ts";
import { logPathFor, readMeta, runDir, writeMeta } from "../registry.ts";
import { stopRun, stopRunAsync } from "../stop.ts";
import { readRunFailures } from "../failures.ts";
import { nonTempFixtureBase } from "./fixture-base.mjs";
import { expectedProperties, fixtures, here, mentionsValue, propertyMap, readStubCalls, spanSeconds, stubBin, targetConfig } from "./remote-session-support.mjs";

const work = mkdtempSync(join(nonTempFixtureBase(here), "remote-session-run-"));
const sshDir = join(work, "ssh");
const remoteHome = join(work, "home");
const piLog = join(work, "pi.log");
const stubLog = join(work, "systemd.log");
const noManagerDir = join(work, "no-user-manager");
const savedEnv = { ...process.env };

const scopes = new Set(); // unit names of every scope a test saw, stopped again in `after`
const ids = [];
let counter = 0;

before(() => {
    mkdirSync(sshDir, { recursive: true });
    mkdirSync(join(remoteHome, "work"), { recursive: true });
    mkdirSync(noManagerDir, { recursive: true });
    chmodSync(join(stubBin, "systemd-run"), 0o755);
    process.env.PATH = `${join(fixtures, "bin")}:${process.env.PATH}`;
    process.env.FAKE_SSH_DIR = sshDir;
    process.env.FAKE_REMOTE_HOME = remoteHome;
    process.env.FAKE_PI_LOG = piLog;
    process.env.PI_CODING_AGENT_DIR = join(work, "agent");
});
after(() => {
    for (const unit of scopes) releaseScope(unit);
    for (const id of ids) { try { rmSync(runDir(id), { recursive: true, force: true }); } catch { /* */ } }
    for (const key of ["PATH", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "FAKE_REMOTE_PATH", "STUB_SYSTEMD_LOG", "STUB_SYSTEMD_FAIL"]) {
        if (savedEnv[key] === undefined) delete process.env[key]; else process.env[key] = savedEnv[key];
    }
    rmSync(work, { recursive: true, force: true });
});

// ---- helpers ------------------------------------------------------------------------------------

async function start(prompt, over = {}, options = {}) {
    counter += 1;
    const id = `sa_sesslim_${process.pid}_${counter}`;
    ids.push(id);
    mkdirSync(runDir(id), { recursive: true });
    const target = parseRemoteTarget(targetConfig(over), "t");
    const { spawned, remote } = await launchRemoteRun({ id, targetName: "t", target, prompt, options: { model: "prov/model", thinking: "low", tools: "read,bash", ...options } });
    writeMeta({ id, status: "running", pid: spawned.pid, spawnPid: process.pid, cwd: target.cwd, promptPreview: prompt.slice(0, 50), startedAt: Date.now(), logPath: logPathFor(id), sessionId: id, callback: false, remote });
    return { id, spawned, remote, exit: spawned.exit };
}
async function until(check, label, ms = 15_000) {
    const end = Date.now() + ms;
    while (Date.now() < end) { const v = check(); if (v) return v; await new Promise((r) => setTimeout(r, 50)); }
    throw new Error(`timed out: ${label}`);
}
const piCmds = () => (existsSync(piLog) ? readFileSync(piLog, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []);
const argvCount = () => piCmds().filter((c) => c.kind === "argv").length;
const promptsSent = () => piCmds().filter((c) => c.kind === "cmd" && c.value.type === "prompt").length;
const pidPath = (id) => join(remoteHome, ".pi-better-subagents", "runs", id, "pid");
const remotePid = (id) => Number(readFileSync(pidPath(id), "utf8"));
const isGone = (pid) => { try { process.kill(pid, 0); } catch { return true; } return spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim().startsWith("Z"); };
const sessionIdOf = (pid) => Number(spawnSync("ps", ["-o", "sid=", "-p", String(pid)], { encoding: "utf8" }).stdout.trim());

/** cgroup v2 path of a process (the `0::` line of /proc/<pid>/cgroup). */
function cgroupPath(pid) {
    const line = readFileSync(`/proc/${pid}/cgroup`, "utf8").split("\n").find((l) => l.startsWith("0::"));
    assert.ok(line, `pid ${pid} has a cgroup v2 path`);
    return line.slice(3);
}
function systemctlShow(unit, props) {
    const r = spawnSync("systemctl", ["--user", "show", unit, ...props.flatMap((p) => ["-p", p])], { encoding: "utf8", timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    return Object.fromEntries(r.stdout.trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
}
function releaseScope(unit) {
    spawnSync("systemctl", ["--user", "stop", unit], { encoding: "utf8", timeout: 20_000 });
    spawnSync("systemctl", ["--user", "reset-failed", unit], { encoding: "utf8", timeout: 20_000 });
}
/** The scope must not be running any more (inactive and unloaded, or merely failed-and-collected). */
function assertScopeGone(unit, { allowFailed = false } = {}) {
    const state = systemctlShow(unit, ["ActiveState", "LoadState"]);
    const ok = state.ActiveState === "inactive" || (allowFailed && state.ActiveState === "failed");
    assert.ok(ok, `scope ${unit} must not stay behind (ActiveState=${state.ActiveState}, LoadState=${state.LoadState})`);
}
/** Stop a run and its scope no matter what the test did. */
function cleanup(id, unit) {
    try { stopRun(id); } catch { /* */ }
    if (unit) releaseScope(unit);
}

/** Anything that would mean a limit (or its scope) leaked into a run that configured none. */
const LIMIT_TRACES = /resources|memoryMax|MemoryMax|memorySwap|MemorySwap|tasksMax|TasksMax|cpuQuota|CPUQuota|runtimeMaxSec|RuntimeMaxSec|systemd|--scope/;

const TypeStub = { Object: (v) => v, String: (v) => v, Number: (v) => v, Boolean: (v) => v, Array: (v) => v, Optional: (v) => v };
const resultText = async (id) => (await subagentResultTool(TypeStub).execute("tc", { id })).content[0].text;

// ---- 1. stand-in systemd-run: record, result line, fail closed -------------------------------------------

describe("session limits through the real bridge with a stand-in systemd-run", () => {
    // Values chosen so that they are not mistaken for ids, pids or hashes in the text.
    const SESSION = { memoryMax: "320M", memorySwapMax: "96M", tasksMax: 77, cpuQuota: 133, runtimeMaxSec: 4321 };
    before(() => { process.env.FAKE_REMOTE_PATH = `${stubBin}:${process.env.PATH}`; process.env.STUB_SYSTEMD_LOG = stubLog; });
    after(() => { delete process.env.FAKE_REMOTE_PATH; delete process.env.STUB_SYSTEMD_LOG; delete process.env.STUB_SYSTEMD_FAIL; });

    it("a scoped run still behaves as a normal run: RPC through the wrapper, events, spend, completion", async () => {
        rmSync(stubLog, { force: true });
        const { id, exit } = await start("say done", { resources: { session: SESSION } });
        const code = await exit;
        assert.equal(code, 0);
        assert.equal((await reconcileRemoteExit(id, code)).finalize, true);
        assert.equal(finalizeRun(id, code).applied, true);
        assert.equal(readMeta(id).status, "completed");
        const scoped = readStubCalls(stubLog).filter((c) => c.cmd.includes("fake-pi.mjs"));
        assert.equal(scoped.length, 1, "one scope for the one remote pi");
        assert.deepEqual(propertyMap(scoped[0]), expectedProperties(SESSION));
        assert.deepEqual(scoped[0].flags.sort(), ["scope", "user"]);
        assert.ok(existsSync(pidPath(id)), "setsid's pid file is still written");
    });

    it("the run record shows every configured limit", async () => {
        const { id, exit, remote } = await start("say done", { resources: { session: SESSION } });
        await exit;
        const record = JSON.stringify(readMeta(id).remote);
        assert.equal(JSON.stringify(remote), record, "the launch metadata is what was recorded");
        for (const [key, value] of Object.entries(SESSION)) assert.ok(mentionsValue(record, key, value), `run record shows ${key}=${value}: ${record}`);
        assert.equal(record.includes("example value"), false, "and still no environment value");
    });

    it("subagent_result shows every configured limit, and the existing first lines are unchanged", async () => {
        const { id, exit } = await start("say done", { resources: { session: SESSION } });
        const code = await exit;
        await reconcileRemoteExit(id, code);
        finalizeRun(id, code);
        const text = await resultText(id);
        for (const [key, value] of Object.entries(SESSION)) assert.ok(mentionsValue(text, key, value), `result shows ${key}=${value}:\n${text}`);
        const lines = text.split("\n");
        assert.match(lines[0], /^\[/, "the head line stays first");
        assert.match(lines[1], /^Remote workspace \(t\): cwd ~\/work · policyHash policy-hash-1 · planHash plan-hash-1/, "the workspace line keeps its form");
    });

    it("only the configured limits are shown", async () => {
        const { id, exit } = await start("say done", { resources: { session: { tasksMax: 77 } } });
        const code = await exit;
        await reconcileRemoteExit(id, code);
        finalizeRun(id, code);
        const record = JSON.stringify(readMeta(id).remote);
        const text = await resultText(id);
        for (const shown of [record, text]) {
            assert.ok(mentionsValue(shown, "tasksMax", 77));
            assert.doesNotMatch(shown, /memoryMax|MemoryMax|memorySwap|MemorySwap|cpuQuota|CPUQuota|runtimeMax|RuntimeMax/);
        }
    });

    it("unset limits change nothing: no scope, no limit in the record or the result", async () => {
        for (const over of [{}, { resources: {} }, { resources: { session: {} } }]) {
            rmSync(stubLog, { force: true });
            const { id, exit } = await start("say done", over);
            const code = await exit;
            assert.equal(code, 0);
            await reconcileRemoteExit(id, code);
            finalizeRun(id, code);
            assert.equal(readStubCalls(stubLog).length, 0, "systemd-run is never called");
            assert.doesNotMatch(JSON.stringify(readMeta(id).remote), LIMIT_TRACES);
            const text = await resultText(id);
            assert.equal(text.split("\n")[1], "Remote workspace (t): cwd ~/work · policyHash policy-hash-1 · planHash plan-hash-1");
            assert.doesNotMatch(text, LIMIT_TRACES);
        }
    });

    it("a scope that cannot be created fails the run closed with a recorded reason, before pi starts or any prompt", async () => {
        process.env.STUB_SYSTEMD_FAIL = "1";
        try {
            const starts = argvCount();
            const prompts = promptsSent();
            const { id, exit } = await start("say done", { resources: { session: SESSION } });
            const code = await exit;
            assert.notEqual(code, 0);
            assert.equal(argvCount(), starts, "pi was never started without the bound");
            assert.equal(promptsSent(), prompts, "no prompt was sent");
            const failure = readRemoteFailure(id);
            assert.ok(failure, "the failure is recorded");
            assert.match(failure.summary, /systemd|scope|user manager|resource|limit/i, `reason: ${failure.summary}`);
            const handled = handleRemoteExit(id);
            assert.ok(handled.failure);
            assert.ok(Object.values(readRunFailures(id).observations).some((o) => o.category === "remote" && o.summary.length > 0), "an incident carries the reason");
            finalizeRun(id, code);
            assert.notEqual(readMeta(id).status, "completed");
        } finally { delete process.env.STUB_SYSTEMD_FAIL; }
    });
});

// ---- 2. real systemd --user ---------------------------------------------------------------------------

/** One probe scope with all five properties; reports why the real-systemd cases cannot run here. */
function probeSystemd() {
    if (process.platform !== "linux") return { reason: "not Linux" };
    const run = spawnSync("systemd-run", ["--user", "--scope", "--quiet", "-p", "MemoryMax=64M", "-p", "MemorySwapMax=64M", "-p", "TasksMax=64", "-p", "CPUQuota=50%", "-p", "RuntimeMaxSec=60", "cat", "/proc/self/cgroup"], { encoding: "utf8", timeout: 20_000 });
    if (run.error) return { reason: `systemd-run is not usable: ${run.error.message}` };
    if (run.status !== 0) return { reason: `no reachable systemd user manager (systemd-run --user --scope failed: ${(run.stderr || "").trim().split("\n").pop()})` };
    const line = run.stdout.split("\n").find((l) => l.startsWith("0::"));
    if (!line) return { reason: "no cgroup v2 hierarchy" };
    const read = (file) => { try { return readFileSync(`/sys/fs/cgroup${line.slice(3)}/${file}`, "utf8").trim(); } catch { return undefined; } };
    if (read("memory.max") !== "67108864") return { reason: "the memory controller is not delegated to the user manager" };
    if (read("pids.max") !== "64") return { reason: "the pids controller is not delegated to the user manager" };
    if (!read("cpu.max")?.startsWith("50000 ")) return { reason: "the cpu controller is not delegated to the user manager" };
    return { swapFile: read("memory.swap.max") !== undefined };
}
const probe = probeSystemd();
const SKIP = probe.reason;

describe("session limits with real systemd --user scopes", { skip: SKIP }, () => {
    const SESSION = { memoryMax: "256M", memorySwapMax: "128M", tasksMax: 64, cpuQuota: 50, runtimeMaxSec: 600 };

    async function scopedRun(prompt, over = {}) {
        const run = await start(prompt, { resources: { session: SESSION }, ...over });
        await until(() => existsSync(pidPath(run.id)), "remote pid file");
        await until(() => readFileSync(logPathFor(run.id), "utf8").includes("working"), "run active");
        const rpid = remotePid(run.id);
        const cgroup = cgroupPath(rpid);
        const unit = basename(cgroup);
        scopes.add(unit);
        return { ...run, rpid, cgroup, unit };
    }

    it("pi and a child it starts share one transient scope carrying the configured properties; stop leaves nothing behind", async () => {
        const file = join(work, "grandchild-1.pid");
        rmSync(file, { force: true });
        let run;
        try {
            run = await scopedRun("hang grandchild persist", { env: { FAKE_GRANDCHILD_FILE: file } });
            const gc = Number(await until(() => existsSync(file) && readFileSync(file, "utf8").trim(), "grandchild pid"));
            // one scope for pi and its child, and it is not the test process's own cgroup
            assert.equal(cgroupPath(gc), run.cgroup, "the child shares pi's scope");
            assert.notEqual(run.cgroup, cgroupPath(process.pid), "pi is bounded by its own scope, not the caller's cgroup");
            assert.match(run.unit, /\.scope$/);
            // setsid semantics kept: pi is the session leader whose id the stop script uses
            assert.equal(sessionIdOf(run.rpid), run.rpid, "the recorded pid is a session leader");
            assert.equal(sessionIdOf(gc), run.rpid, "and the child is in that session");
            // the scope carries the properties (systemd's view)
            const shown = systemctlShow(run.unit, ["ActiveState", "MemoryMax", "MemorySwapMax", "TasksMax", "CPUQuotaPerSecUSec", "RuntimeMaxUSec"]);
            assert.equal(shown.ActiveState, "active");
            assert.equal(shown.MemoryMax, String(256 * 1024 ** 2));
            assert.equal(shown.MemorySwapMax, String(128 * 1024 ** 2));
            assert.equal(shown.TasksMax, "64");
            assert.equal(spanSeconds(shown.CPUQuotaPerSecUSec), 0.5, `CPUQuota=50% is ${shown.CPUQuotaPerSecUSec} per second`);
            assert.equal(spanSeconds(shown.RuntimeMaxUSec), 600, `RuntimeMaxSec=600 is ${shown.RuntimeMaxUSec}`);
            // and the kernel enforces them on that cgroup
            const kernel = (file) => readFileSync(`/sys/fs/cgroup${run.cgroup}/${file}`, "utf8").trim();
            assert.equal(kernel("memory.max"), String(256 * 1024 ** 2));
            assert.equal(kernel("pids.max"), "64");
            assert.equal(kernel("cpu.max"), "50000 100000");
            if (probe.swapFile) assert.equal(kernel("memory.swap.max"), String(128 * 1024 ** 2));
            // subagent_stop: no process, no scope
            assert.deepEqual(stopRun(run.id), { action: "stopped", id: run.id });
            await until(() => isGone(gc), "child gone", 5000);
            assert.equal(isGone(run.rpid), true, "pi is gone");
            await run.exit;
            assertScopeGone(run.unit);
            assert.equal(readMeta(run.id).status, "killed");
        } finally { try { process.kill(Number(readFileSync(file, "utf8")), "SIGKILL"); } catch { /* */ } if (run) cleanup(run.id, run.unit); }
    });

    for (const [label, stop] of [["stopRunAsync", stopRunAsync], ["stopRun on a pi that ignores the RPC abort", async (id) => stopRun(id)]]) {
        it(`${label}: TERM then KILL reach everything in the scope, none is left`, async () => {
            let run;
            try {
                run = await scopedRun("hang stubborn persist");
                assert.deepEqual(await stop(run.id), { action: "stopped", id: run.id });
                assert.equal(isGone(run.rpid), true);
                await run.exit;
                assertScopeGone(run.unit);
            } finally { if (run) cleanup(run.id, run.unit); }
        });
    }

    it("a bridge killed outright: the verified remote stop still ends pi and its scope", async () => {
        let run;
        try {
            run = await scopedRun("hang persist");
            process.kill(run.spawned.pid, "SIGKILL");
            const code = await run.exit;
            assert.equal(isGone(run.rpid), false, "pi outlived its bridge");
            const handled = await reconcileRemoteExit(run.id, code);
            assert.deepEqual([handled.finalize, handled.abnormal], [true, true]);
            assert.equal(isGone(run.rpid), true, "the remote was stopped and verified before finalizing");
            assertScopeGone(run.unit);
        } finally { if (run) cleanup(run.id, run.unit); }
    });

    it("a scoped run that finishes normally completes (RPC survives the scope) and its scope is released", async () => {
        const { id, exit } = await start("say done", { resources: { session: SESSION } });
        const code = await exit;
        assert.equal(code, 0);
        assert.equal((await reconcileRemoteExit(id, code)).finalize, true);
        finalizeRun(id, code);
        assert.equal(readMeta(id).status, "completed");
        // The unit name is unknown after exit; a leftover is any active scope whose cgroup holds a process of this run.
        const survivors = spawnSync("sh", ["-c", `ps -eo pid=,args= | grep -F -- "${join(remoteHome, ".pi-better-subagents", "runs", id)}" | grep -v grep || true`], { encoding: "utf8" }).stdout.trim();
        assert.equal(survivors, "", "no process of the run is left");
    });

    it("RuntimeMaxSec ends a hanging run: systemd stops the scope, nothing is left", async () => {
        const file = join(work, "grandchild-2.pid");
        rmSync(file, { force: true });
        let run;
        try {
            run = await scopedRun("hang grandchild persist", { env: { FAKE_GRANDCHILD_FILE: file }, resources: { session: { runtimeMaxSec: 6 } } });
            const gc = Number(await until(() => existsSync(file) && readFileSync(file, "utf8").trim(), "grandchild pid"));
            assert.equal(isGone(run.rpid), false, "alive at the start");
            assert.equal(spanSeconds(systemctlShow(run.unit, ["RuntimeMaxUSec"]).RuntimeMaxUSec), 6, "the bound is 6 seconds");
            await until(() => isGone(run.rpid), "pi ended by RuntimeMaxSec", 30_000);
            await until(() => isGone(gc), "child ended with the scope", 10_000);
            await run.exit;
            assertScopeGone(run.unit, { allowFailed: true });
        } finally { try { process.kill(Number(readFileSync(file, "utf8")), "SIGKILL"); } catch { /* */ } if (run) cleanup(run.id, run.unit); }
    });
});

// ---- 3. no reachable user manager ---------------------------------------------------------------------

describe("a configured limit with no reachable user manager fails closed", () => {
    const SESSION = { memoryMax: "256M", tasksMax: 64, runtimeMaxSec: 600 };
    const unreachable = { XDG_RUNTIME_DIR: noManagerDir, DBUS_SESSION_BUS_ADDRESS: `unix:path=${join(noManagerDir, "no-bus")}` };
    const withoutManager = async (fn) => {
        const saved = Object.fromEntries(Object.keys(unreachable).map((k) => [k, process.env[k]]));
        Object.assign(process.env, unreachable);
        try { return await fn(); } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
    };

    it("pi is never started, no prompt is sent, and the reason is recorded", async (t) => {
        await withoutManager(async () => {
            const raw = spawnSync("systemd-run", ["--user", "--scope", "--quiet", "true"], { encoding: "utf8", timeout: 20_000, env: process.env });
            if (raw.status === 0) return t.skip("systemd-run still reaches a user manager with the manager variables removed");
            const starts = argvCount();
            const prompts = promptsSent();
            const { id, exit } = await start("say done", { resources: { session: SESSION } });
            const code = await exit;
            assert.notEqual(code, 0);
            assert.equal(argvCount(), starts, "pi was never started without the bound");
            assert.equal(promptsSent(), prompts);
            const failure = readRemoteFailure(id);
            assert.ok(failure, "a failure is recorded");
            assert.match(failure.summary, /systemd|scope|user manager|resource|limit/i, `reason: ${failure.summary}`);
            assert.ok(handleRemoteExit(id).failure);
            assert.ok(Object.values(readRunFailures(id).observations).some((o) => o.category === "remote" && o.summary.length > 0));
            finalizeRun(id, code);
            assert.notEqual(readMeta(id).status, "completed");
        });
    });

    it("the same unreachable manager does not matter when no limit is configured", async () => {
        await withoutManager(async () => {
            const { id, exit } = await start("say done");
            const code = await exit;
            assert.equal(code, 0);
            assert.equal((await reconcileRemoteExit(id, code)).finalize, true);
            finalizeRun(id, code);
            assert.equal(readMeta(id).status, "completed");
            assert.doesNotMatch(JSON.stringify(readMeta(id).remote), LIMIT_TRACES);
        });
    });
});

describe("real systemd cases: availability", () => {
    it(SKIP ? `skipped: ${SKIP}` : "user manager, cgroup v2 and the cpu, memory and pids controllers are available", (t) => {
        if (SKIP) return t.skip(SKIP);
        assert.ok(true);
    });
});
