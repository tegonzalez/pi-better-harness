/**
 * Command limits: `resources.command` bounds every confined launch with its own transient
 * `systemd-run --user --scope` (memoryMax, memorySwapMax, tasksMax, cpuQuota, runtimeMaxSec); `resources.tmpSize`
 * sizes the private /tmp tmpfs. REAL `systemd-run --user` and real bubblewrap, launched through the package's own
 * controller, frozen plan and argument builder, with small capped values and bounded loops (never an unbounded
 * fork bomb). The foreground shell path is covered by one case.
 *
 * Fail closed: a configured limit with no reachable user manager is refused with a recorded reason (inactive audit
 * entry, shown by /sandbox workspace and /sandbox diagnostics confinement) and the command never runs; unset limits
 * change nothing (no systemd-run, the launch works with no user manager). The "missing controller" half of the
 * fail-closed clause has no portable seam and is not covered here.
 *
 * Skips cleanly, with a reason, without bubblewrap / a non-scratch fixture base (all cases), and without a
 * reachable systemd user manager that delegates the cpu, memory and pids controllers (real-scope cases).
 * With PI_SANDBOX_REQUIRE_BACKEND set, a missing or unusable bubblewrap fails instead of skipping; a missing
 * systemd user manager still skips, because that variable names sandbox backends and systemd is not one.
 * @level kernel
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test, { after, before } from "node:test";
import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

import { handleDiagnosticsCommand } from "../diagnostics-command.ts";
import { formatWorkspace } from "../workspace.ts";
import {
    DISK_PROBE, MEMORY_PROBE, PYTHON, TASKS_PROBE, baseSkip, buildFor, confinedExec, controllerWith, jsonLine, launchBuilt, lastJson, makeFixture,
    ownCgroup, q, readCgroupFile, runBuilt, runPython, scopeOfTree, showUnit, stopUnit, systemdSkip, unitGone, unitName, waitFor,
    withoutUserManager, type Fixture, type Resources,
} from "./support/limits-support.ts";

const kernelSkip = baseSkip();
const scopeSkip = kernelSkip || systemdSkip();
const tk = (name: string, body: () => void | Promise<void>) => test(name, { skip: kernelSkip }, body);
const ts = (name: string, body: () => void | Promise<void>) => test(name, { skip: scopeSkip }, body);

let fx: Fixture;
const listScopes = (): Set<string> => new Set(spawnSync("systemctl", ["--user", "list-units", "--type=scope", "--all", "--plain", "--no-legend"], { encoding: "utf8" }).stdout
    .split("\n").map((line) => line.trim().split(/\s+/)[0] ?? "").filter((name) => name.endsWith(".scope")));
let scopesBefore = new Set<string>();

before(() => {
    if (kernelSkip) return;
    fx = makeFixture("pbs-resources-command-");
    if (!scopeSkip) scopesBefore = listScopes();
});
after(() => {
    if (!scopeSkip) {
        // Whatever the launches left behind: nothing may still be running, and failed scopes are cleared.
        const leftovers = [...listScopes()].filter((name) => !scopesBefore.has(name));
        for (const name of leftovers) { stopUnit(name); spawnSync("systemctl", ["--user", "reset-failed", name], { encoding: "utf8" }); }
    }
    if (fx) rmSync(fx.root, { recursive: true, force: true });
});

const run = (resources: Resources | undefined, script: string, args: string[] = [], timeoutMs?: number) => {
    const controller = controllerWith(fx, resources);
    try { return runPython(controller, fx, script, args, timeoutMs); } finally { controller.dispose(); }
};
const runSh = (resources: Resources | undefined, shellScript: string, timeoutMs?: number) => {
    const controller = controllerWith(fx, resources);
    try { return runBuilt(controller, fx, "/bin/sh", ["-c", shellScript], timeoutMs); } finally { controller.dispose(); }
};
const argvOf = (resources: Resources | undefined): string[] => {
    const controller = controllerWith(fx, resources);
    try { const built = buildFor(controller, fx, "/bin/sh", ["-c", "true"]); return [built.file, ...built.fileArgs]; } finally { controller.dispose(); }
};

// ---- private /tmp size (needs no systemd) --------------------------------------------------------------
const MiB = 1 << 20;
const disk = (resources: Resources | undefined) => {
    const result = run(resources, DISK_PROBE, ["64", join(fx.project, "bulk.bin")]);
    assert.equal(result.status, 0, result.stderr);
    return jsonLine<{ written: number; error: string | null; projectWritten: number; projectError: string | null }>(result);
};

tk("tmpSize: writes beyond the cap fail with ENOSPC, at most the cap lands, and a writable root is not limited", () => {
    const out = disk({ tmpSize: "1M" });
    assert.equal(out.error, "ENOSPC");
    assert.ok(out.written <= MiB, `at most 1 MiB fits: ${out.written}`);
    assert.ok(out.written >= MiB / 2, `the cap is the size, not a smaller number: ${out.written}`);
    assert.equal(out.projectError, null, "disk quotas on writable roots are out of scope: the project takes 2 MiB beyond the /tmp cap");
    assert.equal(out.projectWritten, 2 * MiB);
});

tk("tmpSize: the cap follows the configured size", () => {
    const out = disk({ tmpSize: "2M" });
    assert.equal(out.error, "ENOSPC");
    assert.ok(out.written > MiB && out.written <= 2 * MiB, `between 1 and 2 MiB: ${out.written}`);
});

tk("tmpSize: unset leaves the private /tmp at its kernel default (4 MiB fits)", () => {
    for (const resources of [undefined, {}, { command: undefined }] as (Resources | undefined)[]) {
        const out = disk(resources);
        assert.equal(out.error, null);
        assert.equal(out.written, 4 * MiB);
    }
});

tk("tmpSize: the argv sizes the private /tmp tmpfs in bytes: --size <bytes> directly before --tmpfs /tmp, units are powers of 1024", () => {
    const sized = (value: string): string[] => argvOf({ tmpSize: value });
    const bytes: Record<string, number> = { "1024": 1024, "1K": 1024, "1M": MiB, "64M": 64 * MiB, "2G": 2 * 1024 ** 3, "1T": 1024 ** 4 };
    for (const [value, expected] of Object.entries(bytes)) {
        const argv = sized(value);
        const at = argv.findIndex((arg, i) => arg === "--tmpfs" && argv[i + 1] === "/tmp");
        assert.ok(at >= 2, `${value}: a private /tmp tmpfs is mounted`);
        assert.equal(argv[at - 2], "--size", `${value}: --size directly precedes the /tmp tmpfs`);
        assert.equal(argv[at - 1], String(expected), `${value} is ${expected} bytes`);
        assert.equal(argv.filter((arg) => arg === "--size").length, 1, `${value}: only the private /tmp is sized`);
    }
    assert.equal(argvOf(undefined).includes("--size"), false, "unset: no --size");
});

tk("tmpSize alone needs no user manager and starts no scope", async () => {
    await withoutUserManager(fx, () => {
        const out = disk({ tmpSize: "1M" });
        assert.equal(out.error, "ENOSPC", "the cap still applies, and the launch is not refused");
    });
});

// ---- unset limits change nothing ---------------------------------------------------------------------
tk("unset limits: the command runs and inherits the launcher's resource limits even with no reachable user manager", async () => {
    await withoutUserManager(fx, () => {
        const result = runSh(undefined, "echo UNSET-RAN");
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /UNSET-RAN/);
    });
});

// ---- real scopes -------------------------------------------------------------------------------------------
ts("memoryMax: memory beyond the cap is killed inside the scope; the launching (test) process survives; memory below the cap works", () => {
    const control = run(undefined, MEMORY_PROBE, ["256"]);
    assert.match(control.stdout, /ALLOC-DONE 256/, `the probe itself must work without a limit: ${control.stderr}`);
    // memorySwapMax 0 so reclaim cannot satisfy the allocation from swap: the kernel must kill.
    const limited = run({ command: { memoryMax: "64M", memorySwapMax: "0" } }, MEMORY_PROBE, ["256"]);
    assert.doesNotMatch(limited.stdout, /ALLOC-DONE/, "the over-limit allocation did not complete");
    assert.notEqual(limited.status, 0, `killed, not successful (status ${limited.status}, signal ${limited.signal})`);
    assert.doesNotThrow(() => process.kill(process.pid, 0), "the parent survives");
    const small = run({ command: { memoryMax: "64M", memorySwapMax: "0" } }, MEMORY_PROBE, ["8"]);
    assert.match(small.stdout, /ALLOC-DONE 8/, `a launch under the cap works: ${small.stderr}`);
    assert.equal(small.status, 0);
});

ts("tasksMax: processes beyond the cap fail to fork (EAGAIN, bounded loop); without the limit the same loop forks them all", () => {
    const control = jsonLine<{ forked: number; error: string | null }>(run(undefined, TASKS_PROBE, ["48"]));
    assert.deepEqual(control, { forked: 48, error: null }, "the probe itself must work without a limit");
    const result = run({ command: { tasksMax: 24 } }, TASKS_PROBE, ["48"]);
    assert.equal(result.status, 0, result.stderr);
    const limited = jsonLine<{ forked: number; error: string | null }>(result);
    assert.equal(limited.error, "EAGAIN", "fork is refused by the pids controller");
    assert.ok(limited.forked < 24, `fewer children than the cap (the launcher and shell count too): ${limited.forked}`);
    assert.ok(limited.forked >= 1, "the cap is not so small that nothing runs");
});

ts("runtimeMaxSec: a sleeping command is ended after the limit, not after its own sleep", () => {
    const result = runSh({ command: { runtimeMaxSec: 3 } }, "/usr/bin/sleep 60; echo SLEPT", 55_000);
    assert.doesNotMatch(result.stdout, /SLEPT/, "the command did not run to completion");
    assert.notEqual(result.status, 0, `ended abnormally (status ${result.status}, signal ${result.signal})`);
    assert.notEqual(result.signal, "SIGKILL", "ended by the scope, not by the test's own timeout");
    assert.ok(result.elapsedMs < 40_000, `ended in ${result.elapsedMs} ms, far before the 60 s sleep`);
    assert.ok(result.elapsedMs >= 2_000, `not before the limit: ${result.elapsedMs} ms`);
    const quick = runSh({ command: { runtimeMaxSec: 30 } }, "echo QUICK");
    assert.equal(quick.status, 0, quick.stderr);
    assert.match(quick.stdout, /QUICK/, "a command that finishes within the limit is unaffected");
});

ts("scope properties: all five keys reach the scope (systemd properties and cgroup files); the command runs in its own scope, gone afterwards", async () => {
    const resources: Resources = { command: { memoryMax: "96M", memorySwapMax: "48M", tasksMax: 37, cpuQuota: 150, runtimeMaxSec: 45 } };
    const controller = controllerWith(fx, resources);
    const launched = launchBuilt(controller, fx, "/bin/sh", ["-c", "/usr/bin/sleep 8"]);
    let unit = "";
    try {
        const cgroup = await waitFor(() => scopeOfTree(launched.pid), 10_000);
        assert.ok(cgroup, "the launched command is in a scope cgroup of its own");
        assert.notEqual(cgroup, ownCgroup(), "not the test's own cgroup");
        unit = unitName(cgroup);
        const props = showUnit(unit, ["MemoryMax", "MemorySwapMax", "TasksMax", "CPUQuotaPerSecUSec", "RuntimeMaxUSec"]);
        assert.equal(props.MemoryMax, String(96 * MiB));
        assert.equal(props.MemorySwapMax, String(48 * MiB));
        assert.equal(props.TasksMax, "37");
        assert.equal(props.CPUQuotaPerSecUSec, "1.500000s", "150 percent of one CPU");
        assert.equal(props.RuntimeMaxUSec, "45s");
        assert.equal(readCgroupFile(cgroup, "memory.max"), String(96 * MiB));
        assert.equal(readCgroupFile(cgroup, "memory.swap.max"), String(48 * MiB));
        assert.equal(readCgroupFile(cgroup, "pids.max"), "37");
        assert.equal(readCgroupFile(cgroup, "cpu.max"), "150000 100000");
        const ended = await Promise.race([launched.exited, new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 25_000))]);
        assert.notEqual(ended, "timeout", "the command ended on its own");
        assert.deepEqual(ended, { code: 0, signal: null });
        const gone = await waitFor(() => unitGone(unit) ? true : undefined, 10_000);
        assert.equal(gone, true, `scope ${unit} is gone after the command ended`);
        assert.equal(readCgroupFile(cgroup, "pids.max"), undefined, "and so is its cgroup");
    } finally {
        launched.stop();
        if (unit) stopUnit(unit);
        controller.dispose();
    }
});

ts("each launch gets its own scope: two concurrent launches are in different scopes, neither is the test's cgroup", async () => {
    const controller = controllerWith(fx, { command: { tasksMax: 40 } });
    const first = launchBuilt(controller, fx, "/bin/sh", ["-c", "/usr/bin/sleep 6"]);
    const second = launchBuilt(controller, fx, "/bin/sh", ["-c", "/usr/bin/sleep 6"]);
    const units: string[] = [];
    try {
        const a = await waitFor(() => scopeOfTree(first.pid), 10_000);
        const b = await waitFor(() => scopeOfTree(second.pid), 10_000);
        assert.ok(a && b, "both commands are in a scope");
        units.push(unitName(a), unitName(b));
        assert.notEqual(a, b, "one scope per launch");
        assert.ok(a !== ownCgroup() && b !== ownCgroup());
        await Promise.all([first.exited, second.exited]);
        for (const unit of units) assert.equal(await waitFor(() => unitGone(unit) ? true : undefined, 10_000), true, `${unit} gone`);
    } finally {
        first.stop(); second.stop();
        for (const unit of units) stopUnit(unit);
        controller.dispose();
    }
});

ts("a limit only touches the launch it is configured for: a policy without limits starts no scope", async () => {
    const plain = controllerWith(fx, undefined);
    const launched = launchBuilt(plain, fx, "/bin/sh", ["-c", "/usr/bin/sleep 4"]);
    try {
        await new Promise((resolve) => setTimeout(resolve, 1500));
        assert.equal(scopeOfTree(launched.pid), undefined, "no transient scope without limits");
        await launched.exited;
    } finally { launched.stop(); plain.dispose(); }
});

ts("the foreground shell path runs inside the scope too: a bounded fork loop hits the cap", async () => {
    const controller = controllerWith(fx, { command: { tasksMax: 24 } });
    try {
        const script = join(fx.probeDir, "tasks-probe.py");
        writeFileSync(script, TASKS_PROBE);
        const out = await confinedExec(controller, fx, `${PYTHON} ${q(script)} 48`, { timeoutSeconds: 60 });
        assert.equal(out.exitCode, 0, out.output);
        const result = lastJson<{ forked: number; error: string | null }>(out.output);
        assert.equal(result.error, "EAGAIN");
        assert.ok(result.forked < 24, String(result.forked));
    } finally { controller.dispose(); }
});

// ---- fail closed ---------------------------------------------------------------------------------------
const LIMIT_VARIANTS: [string, Resources][] = [
    ["memoryMax", { command: { memoryMax: "64M" } }],
    ["memorySwapMax", { command: { memorySwapMax: "0" } }],
    ["tasksMax", { command: { tasksMax: 32 } }],
    ["cpuQuota", { command: { cpuQuota: 200 } }],
    ["runtimeMaxSec", { command: { runtimeMaxSec: 30 } }],
];

async function closedViews(resources: Resources) {
    const controller = controllerWith(fx, resources);
    const records: any[] = [];
    controller.onReadConfinementRecord((record) => records.push(record));
    controller.recordReadConfinement();
    let refusal = "";
    const ran = await confinedExec(controller, fx, "printf '%s-%s' CMD RAN", { timeoutSeconds: 30 })
        .then((out) => { refusal = out.output; return out.exitCode === 0 && out.output.includes("CMD-RAN"); }, (error) => { refusal = error instanceof Error ? error.message : String(error); return false; });
    controller.recordReadConfinement(); // a launch that failed closed may change the record
    const notes: string[] = [];
    const ctx = { ui: { notify: (m: string) => notes.push(m) } } as unknown as ExtensionCommandContext;
    await handleDiagnosticsCommand("confinement", ctx, () => controller.readConfinementReport());
    const views = { audit: JSON.stringify(records.at(-1)), "/sandbox workspace": formatWorkspace(controller.workspaceInfo()), "/sandbox diagnostics confinement": notes.join("\n") };
    return { controller, audit: records.at(-1), ran, refusal, views };
}

const REASON = /systemd|user manager|user scope|scope|resource limit|resources|memoryMax|memorySwapMax|tasksMax|cpuQuota|runtimeMaxSec/i;

tk("fail closed: each limit with no reachable user manager refuses the launch, with a reason that names the cause; nothing runs unscoped", async () => {
    for (const [key, resources] of LIMIT_VARIANTS) {
        await withoutUserManager(fx, async () => {
            const result = await closedViews(resources);
            try {
                assert.equal(result.ran, false, `${key}: the command must not run without the limit being applied`);
                assert.notEqual(result.refusal.trim(), "", `${key}: the refusal says why`);
                assert.match(result.refusal, REASON, `${key}: the refusal names the limits or the scope/user manager`);
            } finally { result.controller.dispose(); }
        });
    }
});

tk("fail closed: the reason is recorded: the audit entry is inactive with a reason, and /sandbox diagnostics confinement shows it", async () => {
    for (const [key, resources] of LIMIT_VARIANTS) {
        await withoutUserManager(fx, async () => {
            const result = await closedViews(resources);
            try {
                assert.equal(result.audit?.active, false, `${key}: the audit entry is inactive while the limit cannot be applied`);
                assert.match(String(result.audit?.reason), REASON, `${key}: the entry carries a reason`);
                assert.match(result.views["/sandbox diagnostics confinement"], REASON, `${key}: the diagnostics view shows the reason`);
            } finally { result.controller.dispose(); }
        });
    }
});

ts("fail closed: the same policy is accepted and runs once the user manager is reachable again (the refusal is about the manager, not the policy)", async () => {
    const result = await closedViews({ command: { tasksMax: 32 } });
    try {
        assert.equal(result.ran, true);
        assert.equal(result.audit?.active, true);
    } finally { result.controller.dispose(); }
});

tk("fail closed: a direct run through the argument builder cannot start the command unscoped without a user manager", async () => {
    await withoutUserManager(fx, () => {
        let outcome: { status: number | null; stdout: string } | "refused";
        try { const r = runSh({ command: { tasksMax: 32 } }, "printf '%s-%s' CMD RAN"); outcome = { status: r.status, stdout: r.stdout }; } catch { outcome = "refused"; }
        if (outcome !== "refused") {
            assert.doesNotMatch(outcome.stdout, /CMD-RAN/, "the command must not have run");
            assert.notEqual(outcome.status, 0, "the launch itself failed");
        }
    });
});
