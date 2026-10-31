/**
 * Controller wiring for the Linux read-confinement mode: policy-gated, cached,
 * audited, fail-closed, and applied only to Linux + Outside project = Off.
 * @level unit
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";
import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

import { handleDiagnosticsCommand } from "../diagnostics-command.ts";
import { defaultSandboxPermissions } from "../permissions.ts";
import { configuredReadConfinementPolicyFile, loadConfiguredReadConfinementPolicy } from "../read-confinement-settings.ts";
import { compileWritePolicy, evaluateReadAccess, processReadConfinement, READ_CONFINEMENT_POLICY_ENV } from "../shared-sandbox-core.ts";
import { hashPolicy, parseReadConfinementPolicy } from "../shared-read-confinement.ts";
import { ForegroundSandboxController, type ForegroundSandboxSeams } from "../state.ts";

const fixtures = realpathSync(mkdtempSync(join(tmpdir(), "pi-better-sandbox-confinement-")));
after(() => rmSync(fixtures, { recursive: true, force: true }));
const home = join(fixtures, "home");
const project = join(fixtures, "project");
const target = join(fixtures, "target");
const profiles = join(fixtures, "profiles");
for (const dir of [home, project, target, profiles]) mkdirSync(dir, { recursive: true });
writeFileSync(join(target, "f"), "x");
symlinkSync(target, join(project, "link"));

function seams(over: Partial<ForegroundSandboxSeams> = {}): ForegroundSandboxSeams {
    const raw = { version: 1 as const };
    return {
        platform: () => "linux",
        lookupExecutable: () => "/usr/bin/bwrap",
        home: () => home,
        createProfileDir: () => profiles,
        readConfinement: {
            loadPolicy: () => ({ policy: parseReadConfinementPolicy(raw), source: "fixture-policy", sha256: hashPolicy(raw) }),
            plan: { passwdHomes: () => [], env: { PATH: "/usr/bin" } },
        },
        ...over,
    };
}

function enabled(outsideProject: "off" | "read", over: Partial<ForegroundSandboxSeams> = {}) {
    const controller = new ForegroundSandboxController(seams(over));
    controller.beginSession(project);
    const settings = defaultSandboxPermissions();
    settings.main = { ...settings.main, enabled: true, outsideProject, storedCredentials: "off" };
    controller.setPermissionSettings(settings);
    return controller;
}

test("Outside project = Off with a policy attaches the computed mount plan and in-process allow set", () => {
    const controller = enabled("off");
    const plans: string[] = [];
    controller.onReadConfinementPlan((plan) => plans.push(plan.hash));
    const launch = controller.requireLaunchPlan();
    assert.ok(launch.confined && launch.policy.readConfinement);
    assert.ok(launch.policy.readConfinement.readRoots.includes(target));
    const compiled = compileWritePolicy(launch.policy, seams());
    assert.equal(evaluateReadAccess(join(project, "link", "f"), compiled).allowed, true);
    assert.equal(evaluateReadAccess(join(fixtures, "other"), compiled).allowed, false);
    controller.requireLaunchPlan();
    assert.equal(plans.length, 0, "the plan was computed at session start, before the listener");
    assert.match(controller.readConfinementReport(), /policy fixture-policy/);
    controller.dispose();
});

test("other modes, other platforms and an unconfigured policy keep the original behavior", () => {
    const read = enabled("read").requireLaunchPlan();
    assert.ok(read.confined && !read.policy.readConfinement);
    const none = enabled("off", { readConfinement: { loadPolicy: () => undefined } }).requireLaunchPlan();
    assert.ok(none.confined && !none.policy.readConfinement);
    const controller = new ForegroundSandboxController(seams({ platform: () => "darwin", getconf: () => "/private/var/folders/zz/x/T" }));
    controller.beginSession(project);
    assert.equal(controller.status().backend === "linux-bubblewrap", false);
});

test("an invalid or capped policy fails closed with a clear error", () => {
    const bad = enabled("off", { readConfinement: { loadPolicy: () => { throw new Error("Invalid read-confinement policy at $.x: nope"); } } });
    assert.throws(() => bad.requireLaunchPlan(), /Read confinement failed closed: Invalid read-confinement policy/);
    const raw = { version: 1 as const, limits: { maxSymlinks: 1 }, walkSkipDirNames: [] };
    mkdirSync(join(project, "d2"), { recursive: true });
    symlinkSync(target, join(project, "link2"));
    const capped = enabled("off", { readConfinement: {
        loadPolicy: () => ({ policy: parseReadConfinementPolicy(raw), source: "p", sha256: hashPolicy(raw) }),
        plan: { passwdHomes: () => [] },
    } });
    assert.throws(() => capped.requireLaunchPlan(), /failed closed.*maxSymlinks/);
});

test("the policy location is configuration: env wins, then the harness setting, and it must be absolute", () => {
    assert.equal(configuredReadConfinementPolicyFile({ env: { PI_SANDBOX_READ_CONFINEMENT_POLICY: "/etc/x.json" } }), "/etc/x.json");
    assert.throws(() => configuredReadConfinementPolicyFile({ env: { PI_SANDBOX_READ_CONFINEMENT_POLICY: "rel.json" } }), /absolute/);
    const agentDir = join(fixtures, "agent");
    mkdirSync(agentDir);
    assert.equal(configuredReadConfinementPolicyFile({ env: {}, agentDir: () => agentDir }), undefined);
    const file = join(fixtures, "policy.json");
    writeFileSync(file, JSON.stringify({ version: 1 }));
    assert.equal(loadConfiguredReadConfinementPolicy({ env: { PI_SANDBOX_READ_CONFINEMENT_POLICY: file } })?.source, file);
});

test("/sandbox diagnostics confinement shows the audited plan", async () => {
    const controller = enabled("off");
    controller.requireLaunchPlan();
    const out: string[] = [];
    const ctx = { ui: { notify: (m: string) => out.push(m) } } as unknown as ExtensionCommandContext;
    await handleDiagnosticsCommand("confinement", ctx, () => controller.readConfinementReport());
    assert.match(out[0]!, /Read confinement: project .*\n\s+policy fixture-policy sha256:/);
    controller.dispose();
});

test("the plan is computed once at session start and frozen: later symlinks have no effect, a new session sees them", () => {
    const late = join(fixtures, "late-target");
    mkdirSync(late, { recursive: true });
    const proj = join(fixtures, "frozen-project");
    mkdirSync(proj, { recursive: true });
    const controller = new ForegroundSandboxController(seams());
    controller.beginSession(proj);
    const settings = defaultSandboxPermissions();
    settings.main = { ...settings.main, enabled: true, outsideProject: "off", storedCredentials: "off" };
    controller.setPermissionSettings(settings);
    symlinkSync(late, join(proj, "late-link"));
    controller.beginSession(proj); // e.g. a session-tree restore: same frozen plan
    controller.setPermissionSettings(settings);
    const first = controller.requireLaunchPlan();
    assert.ok(first.confined && first.policy.readConfinement && !first.policy.readConfinement.readRoots.includes(late));
    for (let i = 0; i < 3; i++) controller.requireLaunchPlan();
    assert.equal(processReadConfinement()?.state, "active");
    controller.dispose();
    assert.equal(processReadConfinement(), undefined, "dispose clears the published plan");
    const next = new ForegroundSandboxController(seams());
    next.beginSession(proj);
    next.setPermissionSettings(settings);
    const second = next.requireLaunchPlan();
    assert.ok(second.confined && second.policy.readConfinement?.readRoots.includes(late));
    next.dispose();
});

test("a failed plan is published process-wide so other actors fail closed, and the status record says so", () => {
    const controller = new ForegroundSandboxController(seams({ readConfinement: { loadPolicy: () => { throw new Error("nope"); } } }));
    controller.beginSession(project);
    const settings = defaultSandboxPermissions();
    settings.main = { ...settings.main, enabled: true, outsideProject: "off", storedCredentials: "off" };
    controller.setPermissionSettings(settings);
    assert.equal(processReadConfinement()?.state, "failed");
    assert.throws(() => compileWritePolicy({ writableRoot: project, home, permissions: { ...settings.main, commands: true, network: false } }, { platform: () => "linux" }), /failed closed: .*nope/);
    const record = controller.readConfinementRecord();
    assert.ok(record && record.active === false && /nope/.test(record.reason));
    controller.dispose();
    assert.equal(process.env[READ_CONFINEMENT_POLICY_ENV], undefined);
});

test("the status record carries {active, profile, policyHash, planHash} only while the plan is in force", () => {
    const controller = enabled("off");
    const record = controller.readConfinementRecord();
    assert.ok(record?.active);
    assert.equal(record.profile, "main");
    assert.match(record.policyHash, /^[0-9a-f]{64}$/);
    assert.match(record.planHash, /^[0-9a-f]{64}$/);
    const seen: unknown[] = [];
    controller.onReadConfinementRecord((r) => seen.push(r));
    controller.recordReadConfinement();
    controller.recordReadConfinement();
    assert.equal(seen.length, 1, "emitted once per change");
    const settings = defaultSandboxPermissions();
    settings.main = { ...settings.main, enabled: true, outsideProject: "read", storedCredentials: "off" };
    controller.setPermissionSettings(settings);
    const inactive = controller.readConfinementRecord();
    assert.equal(inactive?.active, false);
    controller.recordReadConfinement();
    assert.equal(seen.length, 2);
    controller.dispose();
});
