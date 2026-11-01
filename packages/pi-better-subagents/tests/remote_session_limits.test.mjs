/**
 * Remote session limits (`resources.session`): target parser and generated
 * launch script. Pure unit tests plus runs of the generated script against stand-in `systemd-run`
 * and pi executables (no real systemd here; see remote_session_limits_run.test.mjs for that).
 *
 * Expectations derive from the five documented limit keys (memoryMax, memorySwapMax, tasksMax,
 * cpuQuota, runtimeMaxSec) and from systemd semantics, not from product output. "Unset changes nothing" is checked against the launch and stop
 * scripts and run record as they were at the baseline commit b853864 (read with `git show`).
 *
 * // @level unit
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { buildEnvPayload, buildLaunchScript, buildRemotePlan, buildStopScript, parseRemoteTarget, parseRemoteTargets, selectRemoteTarget } from "../remote.ts";
import { nonTempFixtureBase } from "./fixture-base.mjs";
import { expectedProperties, here, piStub, propertyMap, readStubCalls, SESSION_KEYS, stubBin, targetConfig } from "./remote-session-support.mjs";

const BASELINE = "b853864";
const work = mkdtempSync(join(nonTempFixtureBase(here), "remote-session-unit-"));
const fakeHome = join(work, "home");
const noSystemdBin = join(work, "bin-without-systemd");
const stubLog = join(work, "systemd.log");
const piOut = join(work, "pi.out");
let baseline;

before(async () => {
    mkdirSync(join(fakeHome, "work"), { recursive: true });
    for (const file of [join(stubBin, "systemd-run"), piStub]) chmodSync(file, 0o755);
    // A PATH that has everything a launch needs except systemd tooling.
    mkdirSync(noSystemdBin, { recursive: true });
    const tools = ["sh", "mkdir", "cat", "date", "chmod", "rm", "tr", "ps", "awk", "sleep", "setsid", "grep", "sed", "head", "tail", "cut", "dirname", "basename", "env", "test", "printf", "echo", "kill", "id", "readlink", "ls", "uname", "wc", "sort", "true", "false", "expr", "pwd", "cd", "umask", "read", "mktemp", "tee", "mv", "cp", "touch", "which", "whoami"];
    for (const tool of tools) {
        let found = spawnSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).stdout.trim();
        if (!found.startsWith("/")) found = ["/usr/bin", "/bin"].map((dir) => join(dir, tool)).find((path) => existsSync(path)) ?? "";
        if (found.startsWith("/") && !existsSync(join(noSystemdBin, tool))) symlinkSync(found, join(noSystemdBin, tool));
    }
    // The launch script as it was at the baseline commit, for "unset changes nothing".
    try {
        const source = execFileSync("git", ["show", `${BASELINE}:packages/pi-better-subagents/remote.ts`], { cwd: here, encoding: "utf8", maxBuffer: 1 << 26, stdio: ["ignore", "pipe", "ignore"] });
        const sshCore = join(here, "..", "shared-ssh-core", "index.ts");
        const file = join(work, "baseline-remote.ts");
        writeFileSync(file, source.replace('"./shared-ssh-core/index.ts"', JSON.stringify(sshCore)));
        baseline = await import(pathToFileURL(file).href);
    } catch { baseline = undefined; }
});
after(() => rmSync(work, { recursive: true, force: true }));

const SESSION = { memoryMax: "64M", memorySwapMax: "32M", tasksMax: 32, cpuQuota: 150, runtimeMaxSec: 90 };
const withSession = (session, over = {}) => targetConfig({ resources: { session }, ...over });
const parse = (config) => parseRemoteTarget(config, "t");
/** A refusal only means something when the same shape with a valid value is accepted. */
const control = () => assert.ok(parse(withSession({ tasksMax: 8 })).resources.session, "control: a valid resources.session parses");

// ---- (a) parser ----------------------------------------------------------------------------------

describe("resources.session: target parser", () => {
    it("accepts each key on its own and all together", () => {
        for (const [key, value] of Object.entries(SESSION)) {
            const target = parse(withSession({ [key]: value }));
            assert.ok(target.resources?.session, `${key} accepted and kept`);
        }
        assert.ok(parse(withSession(SESSION)).resources.session);
    });

    it("accepts size strings: a decimal integer with optional K, M, G or T", () => {
        for (const value of ["4096", "1048576", "512K", "64M", "2G", "1T"]) {
            for (const key of ["memoryMax", "memorySwapMax"]) assert.doesNotThrow(() => parse(withSession({ [key]: value })), `${key}=${value}`);
        }
    });

    it("accepts positive integers for tasksMax, cpuQuota (percent of one CPU, above 100 allowed) and runtimeMaxSec", () => {
        for (const value of [1, 2, 32, 4096]) assert.doesNotThrow(() => parse(withSession({ tasksMax: value })), `tasksMax=${value}`);
        for (const value of [1, 50, 100, 200, 1600]) assert.doesNotThrow(() => parse(withSession({ cpuQuota: value })), `cpuQuota=${value}`);
        for (const value of [1, 3, 600, 86400]) assert.doesNotThrow(() => parse(withSession({ runtimeMaxSec: value })), `runtimeMaxSec=${value}`);
    });

    it("every key is optional: no resources, an empty resources object and an empty session are all valid", () => {
        assert.doesNotThrow(() => parse(targetConfig()));
        assert.doesNotThrow(() => parse(targetConfig({ resources: {} })));
        assert.doesNotThrow(() => parse(targetConfig({ resources: { session: {} } })));
    });

    it("refuses an unknown key inside resources.session (fail closed), naming it", () => {
        control();
        for (const key of ["memoryHigh", "cpuWeight", "ioWeight", "tmpSize", "memorymax", "MemoryMax", "tasks", "extra"]) {
            assert.throws(() => parse(withSession({ memoryMax: "64M", [key]: "1" })), new RegExp(key), `key ${key}`);
        }
    });

    it("refuses any other key under resources (only `session` exists on a remote target)", () => {
        control();
        assert.throws(() => parse(targetConfig({ resources: { command: { tasksMax: 8 } } })), /command/);
        assert.throws(() => parse(targetConfig({ resources: { tmpSize: "64M" } })), /tmpSize/);
        assert.throws(() => parse(targetConfig({ resources: { session: { tasksMax: 8 }, other: {} } })), /other/);
    });

    it("refuses resources and resources.session that are not plain objects", () => {
        control();
        for (const bad of ["64M", 32, true, null, [], [{ tasksMax: 8 }]]) {
            assert.throws(() => parse(targetConfig({ resources: bad })), /resources/, `resources=${JSON.stringify(bad)}`);
            assert.throws(() => parse(targetConfig({ resources: { session: bad } })), /session|resources/, `session=${JSON.stringify(bad)}`);
        }
    });

    it("refuses malformed size strings for memoryMax and memorySwapMax", () => {
        control();
        const bad = ["", " ", "M", "64MB", "64MiB", "64 M", " 64M", "64M ", "1.5G", "0.5M", "-1M", "-64", "+64M", "1e3", "1e3M", "0x40", "64P", "64KK", "six", "64M\n", "64;M", "infinity", "max", "50%"];
        for (const key of ["memoryMax", "memorySwapMax"]) {
            for (const value of bad) assert.throws(() => parse(withSession({ [key]: value })), new RegExp(key), `${key}=${JSON.stringify(value)}`);
        }
    });

    it("refuses wrong types for the size keys (they are size strings)", () => {
        control();
        for (const key of ["memoryMax", "memorySwapMax"]) {
            for (const value of [67108864, 1.5, -1, 0, true, null, [], {}, ["64M"]]) assert.throws(() => parse(withSession({ [key]: value })), new RegExp(key), `${key}=${JSON.stringify(value)}`);
        }
    });

    it("refuses zero, negative, fractional, non-finite and wrong-typed values for the positive-integer keys", () => {
        control();
        const bad = [0, -1, -32, 0.5, 1.5, 31.9, NaN, Infinity, -Infinity, "32", "0", "1.5", "", "50%", "10s", "1h", "abc", true, false, null, [], [32], {}];
        for (const key of ["tasksMax", "cpuQuota", "runtimeMaxSec"]) {
            for (const value of bad) assert.throws(() => parse(withSession({ [key]: value })), new RegExp(key), `${key}=${String(JSON.stringify(value) ?? value)}`);
        }
    });

    it("refuses at load through parseRemoteTargets and selectRemoteTarget, not only on a direct parse", () => {
        const bad = withSession({ tasksMax: 0 });
        assert.throws(() => parseRemoteTargets({ t: bad }), /tasksMax/);
        assert.throws(() => selectRemoteTarget({ remoteTargets: { t: bad } }, { remote: "t" }), /tasksMax/);
        const good = parseRemoteTargets({ t: withSession(SESSION) });
        assert.ok(good.t.resources.session);
    });

    it("does not disturb the existing schema: unknown top-level fields are still refused", () => {
        control();
        assert.throws(() => parse({ ...withSession(SESSION), extra: 1 }), /unknown field "extra"/);
    });
});

// ---- (b) generated launch script: text ------------------------------------------------------------

const RUN_ID = "sa_sess_1";
const script = (config, options = {}) => buildLaunchScript(parse(config), RUN_ID, options);
const scopeCommandsIn = (text) => text.match(/systemd-run/g)?.length ?? 0;

describe("launch script without resources.session is unchanged", () => {
    const variants = [
        ["a plain target", () => targetConfig(), {}],
        ["a target with a login shell and a quoted cwd", () => targetConfig({ pi: { command: "pi", login: true }, cwd: "~/it's here" }), { model: "m'1" }],
        ["a target with cwdRoots and a spawn cwd", () => targetConfig({ cwd: undefined, cwdRoots: ["/example/root"] }), { cwd: "/example/root/p" }],
        ["a resumed run", () => targetConfig(), { resumeSessionOf: "sa_prev_1" }],
        ["a target with a verifyCommand", () => targetConfig({ sandbox: { ...targetConfig().sandbox, verifyCommand: "true" } }), { thinking: "low", tools: "read,bash" }],
    ];
    for (const [label, config, options] of variants) {
        it(`${label}: identical to the baseline script, no scope in sight`, (t) => {
            const s = script(config(), options);
            assert.equal(scopeCommandsIn(s), 0);
            assert.doesNotMatch(s, /--scope|MemoryMax|TasksMax|CPUQuota|RuntimeMaxSec|MemorySwapMax/);
            if (!baseline) return t.skip(`baseline ${BASELINE} not readable`);
            const target = parse(config());
            assert.equal(s, baseline.buildLaunchScript(target, RUN_ID, options));
            assert.equal(buildStopScript(target, RUN_ID), baseline.buildStopScript(target, RUN_ID), "stop script unchanged too");
        });
    }

    it("an empty resources object and an empty session are the same as no resources", (t) => {
        const plain = script(targetConfig());
        assert.equal(script(targetConfig({ resources: {} })), plain);
        assert.equal(script(targetConfig({ resources: { session: {} } })), plain);
        if (baseline) assert.equal(plain, baseline.buildLaunchScript(parse(targetConfig()), RUN_ID, {}));
        else t.skip(`baseline ${BASELINE} not readable`);
    });

    it("the run record is the baseline run record when nothing is configured", (t) => {
        if (!baseline) return t.skip(`baseline ${BASELINE} not readable`);
        const target = parse(targetConfig());
        const input = { target, targetName: "t", runId: RUN_ID, runDirPath: join(work, "run"), options: {}, sshArgv: ["ssh", "h"] };
        const now = buildRemotePlan(input);
        const then = baseline.buildRemotePlan(input);
        assert.deepEqual(JSON.parse(JSON.stringify(now)), JSON.parse(JSON.stringify(then)));
    });
});

describe("launch script with resources.session: one scope around the remote pi", () => {
    it("starts pi through `systemd-run --user --scope` carrying every configured property", () => {
        const s = script(withSession(SESSION));
        assert.match(s, /systemd-run/);
        assert.match(s, /--user/);
        assert.match(s, /--scope/);
        assert.match(s, /MemoryMax=(64M|67108864)(?![0-9A-Za-z])/);
        assert.match(s, /MemorySwapMax=(32M|33554432)(?![0-9A-Za-z])/);
        assert.match(s, /TasksMax=32(?![0-9])/);
        assert.match(s, /CPUQuota=150%/);
        assert.match(s, /RuntimeMaxSec=90(s)?(?![0-9A-Za-z])/);
    });

    it("sets only the properties that are configured", () => {
        for (const [key, name] of Object.entries(SESSION_KEYS)) {
            const s = script(withSession({ [key]: SESSION[key] }));
            assert.match(s, new RegExp(`${name}=`), `${name} present`);
            for (const other of Object.values(SESSION_KEYS)) if (other !== name) assert.doesNotMatch(s, new RegExp(`${other}=`), `${other} absent when only ${key} is set`);
        }
    });

    it("keeps setsid, the setsid-missing refusal and the pid file that stop relies on", () => {
        const s = script(withSession(SESSION));
        assert.match(s, /command -v setsid/);
        assert.match(s, /exit 95/);
        assert.match(s, /setsid -w/);
        assert.match(s, /echo \$\$ > "\$0\/pid"/);
        assert.match(s, /pi-remote-started/);
        // the stop script (session-id based) still applies to a scoped run
        assert.match(buildStopScript(parse(withSession(SESSION)), RUN_ID), /ps -eo pid=,sid=,stat=/);
    });

    it("sources the staged environment before the scope starts, and keeps it off every command line", () => {
        const config = withSession(SESSION, { env: { EXAMPLE_VAR: "very-secret-value-1234" } });
        const s = script(config);
        assert.doesNotMatch(s, /very-secret-value-1234/);
        assert.ok(s.lastIndexOf("systemd-run") > s.indexOf('. "$EF"'), "environment is sourced before the scope is launched");
        assert.match(buildEnvPayload(parse(config), RUN_ID), /export EXAMPLE_VAR='very-secret-value-1234'/);
    });

    it("keeps every pre-launch refusal (pi missing, cwd checks) ahead of the scope", () => {
        const s = script(withSession(SESSION, { cwd: undefined, cwdRoots: ["/example/root"] }), { cwd: "/example/root/p" });
        for (const guard of ["exit 127", "exit 95", "exit 99"]) assert.ok(s.indexOf(guard) < s.lastIndexOf("systemd-run"), `${guard} before the scope`);
    });

    it("composes with resume, cwdRoots, login shell and tool flags", () => {
        const s = script(withSession({ tasksMax: 16 }, { pi: { command: "pi", login: true } }), { resumeSessionOf: "sa_prev_1", model: "m", tools: "read" });
        assert.match(s, /TasksMax=16/);
        assert.match(s, /--continue/);
        assert.match(s, /--model 'm'/);
    });
});

// ---- (b) generated launch script: behaviour against stand-ins -----------------------------------------

function runScript(config, { pathDirs, env = {}, options = {} } = {}) {
    rmSync(stubLog, { force: true });
    rmSync(piOut, { force: true });
    const target = parse(config);
    const result = spawnSync("sh", ["-c", buildLaunchScript(target, RUN_ID, options)], {
        input: buildEnvPayload(target, RUN_ID), encoding: "utf8", timeout: 30_000,
        env: { PATH: pathDirs.join(":"), HOME: fakeHome, LANG: "C", STUB_SYSTEMD_LOG: stubLog, STUB_PI_OUT: piOut, ...env },
    });
    return { ...result, calls: readStubCalls(stubLog), piRan: existsSync(piOut), piOutput: existsSync(piOut) ? readFileSync(piOut, "utf8") : "" };
}
const piConfig = (resources) => targetConfig({ ...(resources ? { resources: { session: resources } } : {}) }, { command: piStub });
const stubPath = [stubBin, noSystemdBin];
const pidFile = () => join(fakeHome, ".pi-better-subagents", "runs", RUN_ID, "pid");

describe("generated launch script run against a stand-in systemd-run", () => {
    it("starts the remote pi exactly once inside one `--user --scope` carrying exactly the configured properties", () => {
        const r = runScript(piConfig(SESSION), { pathDirs: stubPath });
        assert.equal(r.status, 0, r.stderr);
        const scoped = r.calls.filter((c) => c.cmd.includes(piStub));
        assert.equal(scoped.length, 1, "pi is started by exactly one systemd-run");
        assert.deepEqual(scoped[0].flags.sort(), ["scope", "user"]);
        assert.deepEqual(propertyMap(scoped[0]), expectedProperties(SESSION));
        assert.ok(r.calls.every((c) => c === scoped[0] || !c.cmd.includes(piStub)), "any other systemd-run call (a probe) does not run pi");
        assert.equal(r.piRan, true);
        assert.match(r.piOutput, /--mode rpc/);
    });

    it("passes the environment (sourced before the scope) and the working folder through to pi, and keeps setsid's pid file", () => {
        const r = runScript(piConfig({ tasksMax: 8 }), { pathDirs: stubPath });
        assert.equal(r.status, 0, r.stderr);
        assert.match(r.piOutput, /EXAMPLE_VAR example value/);
        assert.ok(existsSync(pidFile()), "pid file written by the process that becomes pi");
        assert.match(readFileSync(pidFile(), "utf8").trim(), /^\d+$/);
        assert.match(r.stdout, /^pi-remote-started \d+$/m);
        assert.equal(r.calls.some((c) => c.cmd.includes("example value")), false, "no environment value on a command line");
    });

    for (const key of Object.keys(SESSION_KEYS)) {
        it(`with only ${key} set the scope carries only that property`, () => {
            const r = runScript(piConfig({ [key]: SESSION[key] }), { pathDirs: stubPath });
            assert.equal(r.status, 0, r.stderr);
            const scoped = r.calls.filter((c) => c.cmd.includes(piStub));
            assert.equal(scoped.length, 1);
            assert.deepEqual(propertyMap(scoped[0]), expectedProperties({ [key]: SESSION[key] }));
        });
    }

    it("with no limits configured systemd-run is never invoked and pi still starts", () => {
        for (const resources of [undefined, {}]) {
            const r = runScript(piConfig(resources), { pathDirs: stubPath });
            assert.equal(r.status, 0, r.stderr);
            assert.equal(r.calls.length, 0);
            assert.equal(r.piRan, true);
        }
    });

    it("with no limits configured a host without systemd tooling is no obstacle", () => {
        const r = runScript(piConfig(undefined), { pathDirs: [noSystemdBin] });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(r.piRan, true);
    });
});

describe("a configured limit that cannot be applied fails closed", () => {
    it("scope creation fails (no user manager, missing controller): non-zero exit, pi never started, no unscoped fallback", () => {
        const r = runScript(piConfig(SESSION), { pathDirs: stubPath, env: { STUB_SYSTEMD_FAIL: "1" } });
        assert.notEqual(r.status, 0);
        assert.equal(r.piRan, false, "pi must not run without the bound");
        assert.ok(r.stderr.trim().length > 0, "a reason is printed for the bridge to record");
        assert.ok(r.calls.length >= 1, "creating the scope was attempted");
    });

    it("no systemd-run on the host: non-zero exit, pi never started, the reason names systemd", () => {
        const r = runScript(piConfig({ tasksMax: 8 }), { pathDirs: [noSystemdBin] });
        assert.notEqual(r.status, 0);
        assert.equal(r.piRan, false);
        assert.match(r.stderr, /systemd|scope|user manager|resource limit/i);
    });
});
