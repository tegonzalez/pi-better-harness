/**
 * Implementer tests for the resource limits of confined launches (decision D5, wave P1.2): the limit-key
 * parser, the scope arguments, the plan audit, the launch builder, and a few real systemd user scopes with
 * small capped values. Not the acceptance tests (those are the test author's).
 */
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";

import {
    buildSandboxCommand, commandLimitProperties, compileWritePolicy, describeSandboxSupport, parseCommandLimits,
    resourceScopeArguments, resourceScopeCheckScript, sizeToBytes, userManagerEnvironment,
    type CommandLimits, type SandboxCommandArgs, type SandboxSeams,
} from "./index.ts";
import {
    formatReadConfinementAudit, hashPolicy, parseReadConfinementPolicy, planReadConfinement,
    type ReadConfinementPolicy,
} from "./read-confinement.ts";

const HELP = "--unshare-pid --unshare-ipc --unshare-uts --hostname NAME --unshare-user --uid UID --gid GID --disable-userns --seccomp FD --size BYTES";

describe("limit keys", () => {
    const parse = (resources: unknown) => parseReadConfinementPolicy({ version: 1, resources }).resources;
    it("accepts every key in its documented form", () => {
        assert.deepEqual(parse({ command: { memoryMax: "512M", memorySwapMax: "0", tasksMax: 64, cpuQuota: 200, runtimeMaxSec: 600 }, tmpSize: "64M" }),
            { command: { memoryMax: "512M", memorySwapMax: "0", tasksMax: 64, cpuQuota: 200, runtimeMaxSec: 600 }, tmpSize: "64M" });
        assert.deepEqual(parse({}), {});
        assert.deepEqual(parse({ command: {} }), { command: {} });
    });
    it("converts size strings to bytes with powers of 1024", () => {
        assert.equal(sizeToBytes("7"), 7);
        assert.equal(sizeToBytes("2K"), 2048);
        assert.equal(sizeToBytes("3M"), 3 * 1024 ** 2);
        assert.equal(sizeToBytes("1G"), 1024 ** 3);
        assert.equal(sizeToBytes("1T"), 1024 ** 4);
    });
    it("refuses any other key, form or value", () => {
        const bad: [unknown, RegExp][] = [
            [[], /resources: expected an object/],
            [{ session: {} }, /resources\.session: unknown key/],
            [{ command: { memoryHigh: "1G" } }, /memoryHigh: unknown key/],
            [{ command: [] }, /expected an object/],
            [{ command: { memoryMax: 512 } }, /size string/],
            [{ command: { memoryMax: "512m" } }, /size string/],
            [{ command: { memoryMax: "1.5G" } }, /size string/],
            [{ command: { memoryMax: "G" } }, /size string/],
            [{ command: { memoryMax: "-1M" } }, /size string/],
            [{ command: { memoryMax: " 1M" } }, /size string/],
            [{ command: { memoryMax: "0" } }, /greater than zero/],
            [{ command: { memoryMax: "99999999999T" } }, /size string/],
            [{ command: { memorySwapMax: "infinity" } }, /size string/],
            [{ command: { tasksMax: 0 } }, /positive integer/],
            [{ command: { tasksMax: "8" } }, /positive integer/],
            [{ command: { tasksMax: 1.5 } }, /positive integer/],
            [{ command: { cpuQuota: -5 } }, /positive integer/],
            [{ command: { cpuQuota: "50%" } }, /positive integer/],
            [{ command: { runtimeMaxSec: 0 } }, /positive integer/],
            [{ command: { runtimeMaxSec: "10s" } }, /positive integer/],
            [{ command: { runtimeMaxSec: null } }, /positive integer/],
            [{ tmpSize: 64 }, /size string/],
            [{ tmpSize: "0" }, /greater than zero/],
            [{ tmpSize: "64MB" }, /size string/],
        ];
        for (const [resources, message] of bad) assert.throws(() => parse(resources), message, JSON.stringify(resources));
        assert.throws(() => parseReadConfinementPolicy({ version: 1, resources: null }), /expected an object/);
    });
    it("is reusable on its own with the caller's error", () => {
        class Refused extends Error {}
        const fail = (path: string, message: string): never => { throw new Refused(`${path}: ${message}`); };
        assert.deepEqual(parseCommandLimits({ tasksMax: 3 }, "$.target.resources.session", fail), { tasksMax: 3 });
        assert.throws(() => parseCommandLimits({ tasksMax: 0 }, "$.target.resources.session", fail), Refused);
    });
    it("is part of the policy hash", () => {
        const base = hashPolicy(parseReadConfinementPolicy({ version: 1 }));
        const hashes = new Set([base, ...[{ command: { tasksMax: 8 } }, { command: { tasksMax: 9 } }, { tmpSize: "8M" }, { tmpSize: "9M" }]
            .map((resources) => hashPolicy(parseReadConfinementPolicy({ version: 1, resources })))]);
        assert.equal(hashes.size, 5);
    });
});

describe("scope arguments", () => {
    const all: CommandLimits = { memoryMax: "64M", memorySwapMax: "0", tasksMax: 20, cpuQuota: 50, runtimeMaxSec: 30 };
    it("maps each key to its systemd property, sizes in bytes", () => {
        assert.deepEqual(commandLimitProperties(all), ["MemoryMax=67108864", "MemorySwapMax=0", "TasksMax=20", "CPUQuota=50%", "RuntimeMaxSec=30"]);
        assert.deepEqual(commandLimitProperties({ tasksMax: 5 }), ["TasksMax=5"]);
    });
    it("starts a quiet user scope with one -p per property and a bounded stop for a time limit", () => {
        const args = resourceScopeArguments(all);
        assert.deepEqual(args.slice(0, 2), ["--user", "--scope"]);
        for (const property of commandLimitProperties(all)) assert.ok(args.some((arg, i) => arg === property && args[i - 1] === "-p"), property);
        assert.ok(args.includes("--quiet") && args.includes("--collect"));
        assert.ok(args.includes("TimeoutStopSec=5"));
        assert.ok(!resourceScopeArguments({ tasksMax: 5 }).some((arg) => arg.startsWith("TimeoutStopSec")));
    });
    it("checks only the control files the limits need", () => {
        assert.match(resourceScopeCheckScript({ memoryMax: "1M", memorySwapMax: "0" }), /memory\.max.*\n.*memory\.swap\.max/);
        const pids = resourceScopeCheckScript({ tasksMax: 3 });
        assert.match(pids, /pids\.max/);
        assert.doesNotMatch(pids, /memory\.max|cpu\.max/);
        assert.doesNotMatch(resourceScopeCheckScript({ runtimeMaxSec: 3 }), /\/sys\/fs\/cgroup\$cg\//);
        assert.match(resourceScopeCheckScript({ cpuQuota: 10 }), /cpu\.max.*\n.*exec "\$@"$/);
    });
    it("finds the user manager from the launching environment, or the standard runtime directory", () => {
        const present = (...paths: string[]) => ({ uid: 1234, userManagerPathExists: (path: string) => paths.includes(path) });
        assert.deepEqual(userManagerEnvironment({ XDG_RUNTIME_DIR: "/run/x", DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/x/bus" }, present()),
            { env: { XDG_RUNTIME_DIR: "/run/x", DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/x/bus" } });
        assert.deepEqual(userManagerEnvironment({}, present("/run/user/1234/bus")), { env: { XDG_RUNTIME_DIR: "/run/user/1234" } });
        assert.deepEqual(userManagerEnvironment({ XDG_RUNTIME_DIR: "relative" }, present("/run/user/1234/systemd/private")), { env: { XDG_RUNTIME_DIR: "/run/user/1234" } });
        const none = userManagerEnvironment({}, present());
        assert.ok("reason" in none && /no systemd user manager is reachable/.test(none.reason));
    });
});

const bwrapUsable = (() => {
    const support = describeSandboxSupport();
    if (!support.supported || support.backend !== "linux-bubblewrap") return false;
    return spawnSync(support.executable, ["--ro-bind", "/", "/", "--unshare-net", "true"]).status === 0;
})();

let root: string;
let home: string;
let project: string;
const syntheticDirs: (string | undefined)[] = [];
before(() => {
    const base = process.env.PI_READ_CONFINEMENT_TEST_BASE ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
    root = realpathSync(mkdtempSync(join(base, "resources-impl-")));
    home = join(root, "home");
    project = join(root, "project");
    mkdirSync(home, { recursive: true });
    mkdirSync(project, { recursive: true });
});
after(() => {
    for (const dir of syntheticDirs) if (dir) rmSync(dir, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
});

const baseSeams: SandboxSeams = { bwrapHelp: () => HELP, commandScopeProbe: () => undefined };

function planFor(policy: ReadConfinementPolicy, seams: Partial<SandboxSeams> = {}) {
    const plan = planReadConfinement({ policy: parseReadConfinementPolicy(policy), source: "test-fixture", sha256: "x" }, project, {
        home, env: { PATH: "/usr/bin:/bin" }, passwdHomes: () => [], hardening: { ...baseSeams, ...seams },
    });
    syntheticDirs.push(plan.syntheticDir);
    return plan;
}

function launch(plan: ReturnType<typeof planFor>, script: string, seams: SandboxSeams = baseSeams, env: NodeJS.ProcessEnv = { HOME: home }) {
    const args: SandboxCommandArgs = {
        profilePath: join(root, "unused.sb"), execPath: "/bin/sh", execArgs: ["-c", script],
        policy: {
            writableRoot: project, home, denyWrite: [],
            permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
            readConfinement: plan,
        },
    };
    return buildSandboxCommand(args, { ...seams, env });
}

const withoutResources = { version: 1 as const, tools: { approved: ["sh"], builtinDefaults: false } };

describe("plan and launch builder", () => {
    it("changes nothing when no limit is set", () => {
        const plain = planFor(withoutResources);
        assert.equal(plain.audit.resources, undefined);
        assert.equal("resources" in plain, false);
        const empty = planFor({ ...withoutResources, resources: { command: {} } });
        assert.deepEqual(empty.audit.resources, undefined);
        const a = launch(plain, "true"), b = launch(empty, "true");
        const normal = (plan: typeof plain, args: string[]) => args.map((arg) => arg === plan.syntheticDir ? "<synthetic>" : arg);
        assert.deepEqual(normal(plain, a.fileArgs), normal(empty, b.fileArgs));
        assert.ok(!a.fileArgs.includes("--size"));
        const launcherText = readFileSync(a.file, "utf8");
        assert.doesNotMatch(launcherText, /systemd-run/);
    });
    it("sizes the private /tmp with --size directly before its --tmpfs, in bytes", () => {
        const plan = planFor({ ...withoutResources, resources: { tmpSize: "3M" } });
        const command = launch(plan, "true");
        const at = command.fileArgs.findIndex((arg, i) => arg === "--tmpfs" && command.fileArgs[i + 1] === "/tmp");
        assert.ok(at >= 2);
        assert.deepEqual(command.fileArgs.slice(at - 2, at + 2), ["--size", String(3 * 1024 ** 2), "--tmpfs", "/tmp"]);
        assert.equal(command.fileArgs.filter((arg) => arg === "--size").length, 1);
        assert.deepEqual(plan.audit.resources, { tmpSize: { size: "3M", bytes: 3 * 1024 ** 2, state: { state: "on" } } });
    });
    it("runs the launch in a scope through the launcher's prefix, with the bus location baked in", () => {
        const plan = planFor({ ...withoutResources, resources: { command: { tasksMax: 20, runtimeMaxSec: 30 } } });
        const command = launch(plan, "true", baseSeams, { HOME: home, XDG_RUNTIME_DIR: "/run/user/777", DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/777/bus" });
        const text = readFileSync(command.file, "utf8");
        for (const part of ["systemd-run", "--user", "--scope", "TasksMax=20", "RuntimeMaxSec=30", "XDG_RUNTIME_DIR=/run/user/777", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/777/bus"]) {
            assert.ok(text.includes(part), part);
        }
        assert.ok(text.indexOf("systemd-run") > text.indexOf("exec "));
        assert.ok(command.fileArgs.includes("--unshare-pid"), "bubblewrap's own arguments are unchanged");
        assert.deepEqual(plan.audit.resources, { command: { limits: { tasksMax: 20, runtimeMaxSec: 30 }, state: { state: "on" } } });
    });
    it("records an unavailable limit in the audit and refuses the launch", () => {
        const plan = planFor({ ...withoutResources, resources: { command: { memoryMax: "64M" }, tmpSize: "1M" } },
            { commandScopeProbe: () => "no systemd user manager is reachable", bwrapHelp: () => HELP.replace("--size BYTES", "") });
        assert.deepEqual(plan.audit.resources?.command?.state, { state: "unavailable", reason: "no systemd user manager is reachable" });
        assert.equal(plan.audit.resources?.tmpSize?.state.state, "unavailable");
        const text = formatReadConfinementAudit(plan.audit);
        assert.match(text, /resources:\n\s+command: memoryMax=64M — unavailable \(inactive, launches fail closed\) — no systemd user manager is reachable/);
        assert.match(text, /tmpSize: 1M \(1048576 bytes\) — unavailable/);
        assert.throws(() => launch(plan, "true", { bwrapHelp: () => HELP, commandScopeProbe: () => "no systemd user manager is reachable" }), /resources\.command is set but unavailable: no systemd user manager is reachable/);
        assert.throws(() => launch(plan, "true", { bwrapHelp: () => HELP.replace("--size BYTES", ""), commandScopeProbe: () => undefined }), /resources\.tmpSize is set but unavailable: .*--size is not supported/);
    });
    it("shows configured limits in the audit summary", () => {
        const plan = planFor({ ...withoutResources, resources: { command: { memoryMax: "64M", cpuQuota: 50 }, tmpSize: "1M" } });
        const text = formatReadConfinementAudit(plan.audit);
        assert.match(text, /command: memoryMax=64M cpuQuota=50 — on \(each launch runs in its own systemd user scope\)/);
        assert.match(text, /tmpSize: 1M \(1048576 bytes\) — on/);
        assert.doesNotMatch(formatReadConfinementAudit(planFor(withoutResources).audit), /resources:/);
        assert.notEqual(plan.hash, planFor(withoutResources).hash);
    });
    it("compiles the resources into the policy the launch builder reads", () => {
        const plan = planFor({ ...withoutResources, resources: { command: { tasksMax: 4 }, tmpSize: "1M" } });
        const compiled = compileWritePolicy({
            writableRoot: project, home, denyWrite: [], readConfinement: plan,
            permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
        });
        assert.deepEqual(compiled.readConfinement?.resources, { command: { tasksMax: 4 }, tmpSize: "1M" });
    });
});

const systemdUsable = (() => {
    if (!bwrapUsable) return false;
    const probe = spawnSync("systemd-run", ["--user", "--scope", "--quiet", "--collect", "-p", "TasksMax=50", "-p", "MemoryMax=64M", "-p", "CPUQuota=50%", "true"], { env: process.env });
    return probe.status === 0;
})();

describe("real systemd user scope", { skip: !systemdUsable && "bubblewrap or a systemd user manager with cpu, memory and pids is not available" }, () => {
    const real = (limits: CommandLimits, tmpSize?: string) =>
        planFor({ ...withoutResources, tools: { approved: ["sh", "sleep", "dd", "python3"], builtinDefaults: false }, resources: { command: limits, ...(tmpSize && { tmpSize }) } }, { commandScopeProbe: undefined as never, bwrapHelp: undefined as never });
    const run = (plan: ReturnType<typeof planFor>, script: string, timeoutMs = 20_000) => {
        const command = launch(plan, script, {}, { HOME: home });
        return spawnSync(command.file, command.fileArgs, { encoding: "utf8", env: { PATH: "/usr/bin:/bin", HOME: home }, timeout: timeoutMs });
    };
    it("ends a sleeping command at runtimeMaxSec, even one that ignores SIGTERM", () => {
        const plan = real({ runtimeMaxSec: 2 });
        const started = Date.now();
        const out = run(plan, "trap '' TERM; sleep 60");
        const seconds = (Date.now() - started) / 1000;
        assert.ok(out.status !== 0 && seconds < 15, `status ${out.status} after ${seconds}s ${out.stderr}`);
    });
    it("fails forks beyond tasksMax and kills a process over memoryMax, leaving the parent alive", () => {
        const forks = run(real({ tasksMax: 12 }), "n=0; while [ $n -lt 40 ]; do sleep 5 & n=$((n+1)); done 2>&1; kill $(jobs -p) 2>/dev/null; true");
        assert.match(forks.stdout + forks.stderr, /fork: .*(Resource temporarily unavailable|retry)|Cannot fork/i);
        const memory = run(real({ memoryMax: "48M", memorySwapMax: "0" }), "python3 -c 'x=bytearray(300*1024*1024); print(len(x))'; echo exit=$?");
        // The kernel kills the allocator; the manager may then stop the whole scope, so the shell may not report.
        assert.ok(memory.status !== 0 || /Killed|exit=137/.test(memory.stdout + memory.stderr), `${memory.status} ${memory.stdout}`);
        assert.doesNotMatch(memory.stdout, /314572800/);
    });
    it("bounds the private /tmp with ENOSPC", () => {
        const out = run(real({ tasksMax: 50 }, "1M"), "dd if=/dev/zero of=/tmp/fill bs=64k count=100 2>&1; echo done");
        assert.match(out.stdout, /No space left on device/);
    });
    it("works when the launch is spawned with a minimal environment", () => {
        const out = run(real({ tasksMax: 50 }), "echo ok");
        assert.equal(out.stdout.trim(), "ok", out.stderr);
    });
    it("runs each launch in its own scope named after its process, and the scope is gone when the launch ends", async () => {
        const plan = real({ tasksMax: 50, memoryMax: "64M" });
        const command = launch(plan, "sleep 3", {}, { HOME: home });
        const child = spawn(command.file, command.fileArgs, { detached: true, stdio: "ignore", env: { PATH: "/usr/bin:/bin", HOME: home } });
        const pid = child.pid!;
        const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
        const scopes = () => spawnSync("systemctl", ["--user", "list-units", "--type=scope", "--all", "--no-legend", `run-p${pid}-*`], { encoding: "utf8" }).stdout.trim();
        let seen = "";
        for (let i = 0; i < 30 && !seen; i++) { seen = scopes(); if (!seen) await new Promise((r) => setTimeout(r, 100)); }
        assert.match(seen, new RegExp(`run-p${pid}-`), "the launch process itself moved into the scope: its pid is unchanged, so signals sent to it behave as before");
        await exited;
        let left = "x";
        for (let i = 0; i < 50 && left; i++) { left = scopes(); if (left) await new Promise((r) => setTimeout(r, 100)); }
        assert.equal(left, "", "no scope remains, not even a failed one (--collect)");
    });
});
