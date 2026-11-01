/**
 * Shared helpers for the resource-limit tests (command limits and private /tmp size: the read-confinement
 * policy's optional `resources.command` and `resources.tmpSize`).
 *
 * Everything launches through the package's own controller, frozen plan and argument builder
 * (`buildSandboxCommand` / the foreground shell operations); nothing hand-writes bubblewrap or systemd-run
 * arguments. Expected results derive from kernel, cgroup v2 and systemd semantics, never from product output.
 * Real-systemd cases use SMALL capped values, bounded loops, and always clean up their scopes.
 * Fixtures live under a non-scratch base (override: PI_SANDBOX_TEST_NON_TEMP_BASE).
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { buildSandboxCommand } from "../../shared-sandbox-core.ts";
import type { ForegroundSandboxController } from "../../state.ts";
import { PYTHON, controllerFor, rawPolicy, type Fixture } from "./hardening-support.ts";

export { PYTHON, baseSkip, base, confinedExec, controllerFor, lastJson, makeFixture, rawPolicy, q, type Fixture, type RawPolicy } from "./hardening-support.ts";

export type CommandLimits = { memoryMax?: string; memorySwapMax?: string; tasksMax?: number; cpuQuota?: number; runtimeMaxSec?: number };
export type Resources = { command?: CommandLimits; tmpSize?: string };

/** A policy that adds `resources` to the minimal read-confinement policy of the hardening tests. */
export const resourcePolicy = (fx: Fixture, resources?: Resources) => rawPolicy(fx, undefined, resources ? { resources } : {});

export const controllerWith = (fx: Fixture, resources?: Resources, overrides: Parameters<typeof controllerFor>[2] = {}): ForegroundSandboxController =>
    controllerFor(fx, resourcePolicy(fx, resources), overrides);

// ---- is real systemd available? ----------------------------------------------------------
/**
 * Why real `systemd-run --user --scope` cases cannot run here, or false. The probe starts a scope with all five
 * properties and reads the cgroup files the kernel enforces them through, so a missing user manager and a missing
 * delegated controller (cpu, memory, pids) are both detected by what they do.
 * These skips are deliberately NOT turned into failures by PI_SANDBOX_REQUIRE_BACKEND: that variable names sandbox
 * backends (docs/development-and-release.md, "Sandbox confinement lanes"), and a systemd user manager is not one.
 */
export function systemdSkip(): string | false {
    if (process.platform !== "linux") return "Linux systemd only";
    const probe = spawnSync("systemd-run", ["--user", "--scope", "--quiet", "-p", "MemoryMax=64M", "-p", "MemorySwapMax=0", "-p", "TasksMax=32",
        "-p", "CPUQuota=150%", "-p", "RuntimeMaxSec=30", "--", "/bin/sh", "-c",
        'd=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); cat "$d/memory.max" "$d/memory.swap.max" "$d/pids.max" "$d/cpu.max"'],
        { encoding: "utf8", timeout: 20_000 });
    if (probe.error) return `systemd-run unavailable: ${probe.error.message}`;
    if (probe.status !== 0) return `no reachable systemd user manager: ${(probe.stderr || "").trim().split("\n")[0]}`;
    const lines = probe.stdout.trim().split("\n");
    const expected = ["67108864", "0", "32", "150000 100000"];
    if (lines.join("|") !== expected.join("|")) return `user manager lacks the cpu, memory and pids controllers or does not apply scope properties (got ${JSON.stringify(lines)})`;
    const show = spawnSync("systemctl", ["--user", "show", "--property=Version"], { encoding: "utf8", timeout: 10_000 });
    if (show.status !== 0) return "systemctl --user show is unavailable";
    return false;
}

// ---- launching -----------------------------------------------------------------------------
export type Built = { file: string; fileArgs: string[] };

/** Build the confined command from the controller's frozen plan through the package's own argument builder. */
export function buildFor(controller: ForegroundSandboxController, fx: Fixture, execPath: string, execArgs: string[]): Built {
    const plan = controller.requireLaunchPlan();
    if (!plan.confined || !plan.policy.readConfinement) throw new Error("read confinement must be in force for these probes");
    return buildSandboxCommand({ profilePath: join(fx.profiles, "unused.sb"), execPath, execArgs, policy: plan.policy }, { env: process.env });
}

export type Run = { status: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string; elapsedMs: number; built: Built };

/** Build and run a confined command to completion. The environment is the test process's, as a real spawn site's is. */
export function runBuilt(controller: ForegroundSandboxController, fx: Fixture, execPath: string, execArgs: string[], timeoutMs = 90_000): Run {
    const built = buildFor(controller, fx, execPath, execArgs);
    const started = Date.now();
    const out = spawnSync(built.file, built.fileArgs, { encoding: "utf8", cwd: fx.project, timeout: timeoutMs, killSignal: "SIGKILL", env: { ...process.env, HOME: fx.home } });
    return { status: out.status, signal: out.signal, stdout: out.stdout ?? "", stderr: out.stderr ?? "", elapsedMs: Date.now() - started, built };
}

export const runPython = (controller: ForegroundSandboxController, fx: Fixture, script: string, args: string[] = [], timeoutMs?: number): Run =>
    runBuilt(controller, fx, PYTHON, ["-c", script, ...args], timeoutMs);

export function jsonLine<T = Record<string, unknown>>(run: Run): T {
    const line = run.stdout.trim().split("\n").reverse().find((entry) => entry.startsWith("{"));
    if (!line) throw new Error(`no JSON line (status ${run.status}, signal ${run.signal}): ${run.stdout}${run.stderr}`);
    return JSON.parse(line) as T;
}

// ---- in-sandbox probes -------------------------------------------------------------------------
/** Touch `argv[1]` MiB in 1 MiB steps. Prints ALLOC-DONE only when every step was granted. */
export const MEMORY_PROBE = String.raw`
import sys
chunks = []
for _ in range(int(sys.argv[1])):
    chunks.append(bytearray(b"\xff") * (1 << 20))
print("ALLOC-DONE", len(chunks), flush=True)
`;

/** Fork up to `argv[1]` sleeping children (bounded), then kill and reap them all. One JSON line. */
export const TASKS_PROBE = String.raw`
import os, sys, time, errno, json, signal
kids, err = [], None
for _ in range(int(sys.argv[1])):
    try:
        pid = os.fork()
    except OSError as e:
        err = errno.errorcode.get(e.errno, str(e.errno))
        break
    if pid == 0:
        time.sleep(10)
        os._exit(0)
    kids.append(pid)
for pid in kids:
    os.kill(pid, signal.SIGKILL)
for pid in kids:
    os.waitpid(pid, 0)
print(json.dumps({"forked": len(kids), "error": err}), flush=True)
`;

/** Write 64 KiB blocks into /tmp until the cap or `argv[1]` blocks; then 2 MiB into the project (a writable root). One JSON line. */
export const DISK_PROBE = String.raw`
import os, sys, errno, json
written, err = 0, None
fd = os.open("/tmp/fill", os.O_WRONLY | os.O_CREAT, 0o600)
try:
    for _ in range(int(sys.argv[1])):
        n = os.write(fd, b"x" * 65536)
        written += n
except OSError as e:
    err = errno.errorcode.get(e.errno, str(e.errno))
os.close(fd)
project_written, project_err = 0, None
try:
    pfd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT, 0o600)
    for _ in range(32):
        project_written += os.write(pfd, b"y" * 65536)
    os.close(pfd)
except OSError as e:
    project_err = errno.errorcode.get(e.errno, str(e.errno))
print(json.dumps({"written": written, "error": err, "projectWritten": project_written, "projectError": project_err}), flush=True)
`;

// ---- an unreachable user manager -------------------------------------------------------------------
/** Run `fn` with the user manager made unreachable for this process and everything it starts (restored afterwards). */
export async function withoutUserManager<T>(fx: Fixture, fn: () => Promise<T> | T): Promise<T> {
    const dir = join(fx.root, "no-user-manager");
    mkdirSync(dir, { recursive: true });
    const names = ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] as const;
    const saved = names.map((name) => [name, process.env[name]] as const);
    process.env.XDG_RUNTIME_DIR = dir;
    process.env.DBUS_SESSION_BUS_ADDRESS = `unix:path=${join(dir, "bus")}`;
    try {
        return await fn();
    } finally {
        for (const [name, value] of saved) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
    }
}

// ---- finding a launched command's scope ---------------------------------------------------------------
const cgroupOf = (pid: number): string | undefined => {
    try { return /^0::(.*)$/m.exec(readFileSync(`/proc/${pid}/cgroup`, "utf8"))?.[1]; } catch { return undefined; }
};
const parentOf = (pid: number): number | undefined => {
    try { const stat = readFileSync(`/proc/${pid}/stat`, "utf8"); return Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]); } catch { return undefined; }
};

/** The pid and all its descendants, from /proc. */
export function processTree(root: number): number[] {
    const parents = new Map<number, number>();
    for (const entry of readdirSync("/proc")) {
        if (!/^\d+$/.test(entry)) continue;
        const parent = parentOf(Number(entry));
        if (parent !== undefined) parents.set(Number(entry), parent);
    }
    const tree = new Set<number>([root]);
    for (let grew = true; grew;) {
        grew = false;
        for (const [pid, parent] of parents) if (tree.has(parent) && !tree.has(pid)) { tree.add(pid); grew = true; }
    }
    return [...tree];
}

export const ownCgroup = (): string => cgroupOf(process.pid) ?? "";

/** The `.scope` cgroup (other than the test's own) that some process of the launched tree is in, if any. */
export function scopeOfTree(root: number): string | undefined {
    const own = ownCgroup();
    for (const pid of processTree(root)) {
        const cgroup = cgroupOf(pid);
        if (cgroup && cgroup !== own && cgroup.endsWith(".scope")) return cgroup;
    }
    return undefined;
}

export const unitName = (cgroup: string): string => cgroup.slice(cgroup.lastIndexOf("/") + 1);

export function showUnit(unit: string, properties: string[]): Record<string, string> {
    const out = spawnSync("systemctl", ["--user", "show", unit, ...properties.flatMap((name) => ["-p", name])], { encoding: "utf8", timeout: 15_000 });
    return Object.fromEntries(out.stdout.trim().split("\n").filter(Boolean).map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
}

export const readCgroupFile = (cgroup: string, name: string): string | undefined => {
    const path = join("/sys/fs/cgroup", cgroup, name);
    try { return existsSync(path) ? readFileSync(path, "utf8").trim() : undefined; } catch { return undefined; }
};

export const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export async function waitFor<T>(what: () => T | undefined, timeoutMs: number, stepMs = 50): Promise<T | undefined> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const value = what();
        if (value !== undefined) return value;
        if (Date.now() > deadline) return undefined;
        await sleep(stepMs);
    }
}

export type Launched = { pid: number; exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>; stop: () => void };

/** Start a confined command without waiting for it. `stop` ends its whole tree (cleanup only). */
export function launchBuilt(controller: ForegroundSandboxController, fx: Fixture, execPath: string, execArgs: string[]): Launched {
    const built = buildFor(controller, fx, execPath, execArgs);
    const child = spawn(built.file, built.fileArgs, { cwd: fx.project, stdio: "ignore", env: { ...process.env, HOME: fx.home } });
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
    child.once("error", () => undefined);
    return {
        pid: child.pid!, exited,
        stop: () => { for (const pid of processTree(child.pid!).reverse()) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } } },
    };
}

/** Whether a transient unit is gone: not loaded, or inactive. */
export function unitGone(unit: string): boolean {
    const { LoadState, ActiveState } = showUnit(unit, ["LoadState", "ActiveState"]);
    return LoadState === "not-found" || ActiveState === "inactive" || ActiveState === "failed";
}

export function stopUnit(unit: string): void {
    spawnSync("systemctl", ["--user", "stop", unit], { encoding: "utf8", timeout: 15_000 });
}
