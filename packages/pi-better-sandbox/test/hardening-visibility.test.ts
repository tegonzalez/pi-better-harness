/**
 * Row `visibility`: the audit entry `pi-better-sandbox-read-confinement`, `/sandbox workspace` and
 * `/sandbox diagnostics confinement` show the state of each hardening measure (ipc, uts, userns, keyring, fds) as
 * on, off by policy, or unavailable. A measure that is on but cannot be applied (here: a bubblewrap without
 * `--disable-userns`, or without seccomp program support) yields an INACTIVE audit entry with a reason, the views
 * say so, and nothing launches without it (fail closed).
 *
 * Available and switched-off states: the real extension, driven the way test/workspace.test.ts drives it (a
 * TUI-like session, policy location from the agent dir's settings). Unavailable states: the extension has no seam
 * for the bubblewrap lookup (it only trusts /usr/bin and /bin), so these use the controller with the
 * `lookupExecutable` seam, wired as the extension wires it (record listener, `formatWorkspace(workspaceInfo())`
 * for `/sandbox workspace`, `handleDiagnosticsCommand("confinement", ...)` over `readConfinementReport()` for
 * `/sandbox diagnostics confinement`), as in read-confinement.test.ts. A bubblewrap lacking a capability is a
 * wrapper that passes everything to the real bubblewrap except the capability's flags (hidden from `--help` too).
 * The format is the product's; the tests read a state as the first state word (on / off / unavailable, or a
 * boolean) after the measure's name.
 * @level integration
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test, { after } from "node:test";
import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext, RegisteredCommand, ToolDefinition } from "@earendil-works/pi-coding-agent";

import piBetterSandbox from "../index.ts";
import { defaultSandboxPermissions } from "../permissions.ts";
import { READ_CONFINEMENT_ENTRY } from "../read-confinement-settings.ts";
import { SESSION_PERMISSION_ENTRY } from "../session-permissions.ts";
import { handleDiagnosticsCommand } from "../diagnostics-command.ts";
import { formatWorkspace } from "../workspace.ts";
import {
    base, baseSkip, confinedExec, controllerFor, lookupWith, makeFixture, rawPolicy, writeFakeBwrap, type Fixture,
} from "./support/hardening-support.ts";

const skip = baseSkip();
const MEASURES = ["ipc", "uts", "userns", "keyring", "fds"] as const;
type Measure = (typeof MEASURES)[number];
type State = "on" | "off" | "unavailable";

const fixtures = skip ? "" : realpathSync(mkdtempSync(join(base!, "pbs-hardening-visibility-")));
const agentDir = join(fixtures, "agent");
const policyFile = join(fixtures, "policies", "policy.json");
const projectRoot = join(fixtures, "work", "project");
const fakeDir = join(fixtures, "fake");
const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
const originalPolicyEnv = process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY;
const originalCwd = process.cwd();

if (!skip) {
    for (const dir of [agentDir, join(fixtures, "policies"), projectRoot, fakeDir]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(projectRoot, "file.txt"), "project\n");
    // A checkout, as a real working folder is (see workspace.test.ts).
    mkdirSync(join(projectRoot, ".git", "hooks"), { recursive: true });
    mkdirSync(join(projectRoot, ".git", "info"), { recursive: true });
    mkdirSync(join(projectRoot, ".git", "objects", "info"), { recursive: true });
    for (const name of ["config", "config.worktree", "info/attributes", "objects/info/alternates", "objects/info/http-alternates", "gitdir"]) writeFileSync(join(projectRoot, ".git", name), "");
    writeFileSync(join(projectRoot, ".git", "commondir"), ".\n");
    for (const name of [".env", ".env.local", ".pi"]) writeFileSync(join(projectRoot, name), "");
    writeFileSync(join(agentDir, "settings.json"), JSON.stringify({ piBetterHarness: { sandboxReadConfinement: { policyFile } } }));
    delete process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY;
    process.env.PI_CODING_AGENT_DIR = agentDir;
}

after(() => {
    process.chdir(originalCwd);
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
    if (originalPolicyEnv === undefined) delete process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY; else process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY = originalPolicyEnv;
    if (fixtures) rmSync(fixtures, { recursive: true, force: true });
});

function confinedSettings() {
    const settings = defaultSandboxPermissions();
    settings.main = { ...settings.main, enabled: true, projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false };
    return settings;
}

type Session = {
    audit: any; entries: { customType: string; data: any }[]; slash: (args: string) => Promise<string>; shutdown: () => void;
};

/** One real extension session on the fixture workspace with `hardening` in the policy. */
async function startSession(hardening: Record<string, unknown> | undefined): Promise<Session> {
    writeFileSync(policyFile, JSON.stringify({ version: 1, tools: { approved: ["sh", "cat"] }, ...(hardening ? { hardening } : {}) }));
    const commands = new Map<string, Omit<RegisteredCommand, "name" | "sourceInfo">>();
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => unknown>();
    const entries: { customType: string; data: any }[] = [];
    const notes: string[] = [];
    const ctx = {
        cwd: projectRoot, hasUI: true, mode: "tui", model: { provider: "test-provider", id: "test-model" }, thinkingLevel: "off",
        sessionManager: {
            getBranch: () => [{ type: "custom", customType: SESSION_PERMISSION_ENTRY, data: { version: 1, permissions: confinedSettings() } }],
            getSessionId: () => "visibility-session", getSessionFile: () => join(fixtures, "visibility-session.jsonl"),
        },
        ui: { theme: { fg: (_c: string, t: string) => t }, notify: (m: string) => notes.push(m), setStatus: () => undefined, confirm: async () => true },
    } as unknown as ExtensionCommandContext;
    process.chdir(projectRoot);
    const pi = {
        appendEntry: (customType: string, data: unknown) => entries.push({ customType, data }),
        events: { emit: () => undefined, on: () => () => undefined },
        registerTool: (_tool: ToolDefinition) => undefined,
        registerCommand: (name: string, command: Omit<RegisteredCommand, "name" | "sourceInfo">) => commands.set(name, command),
        on: (event: string, handler: (event: unknown, context: ExtensionContext) => unknown) => handlers.set(event, handler),
    } as unknown as ExtensionAPI;
    piBetterSandbox(pi);
    await handlers.get("session_start")?.({ type: "session_start", reason: "startup" }, ctx);
    const audits = entries.filter((e) => e.customType === READ_CONFINEMENT_ENTRY);
    return {
        audit: audits.at(-1)?.data, entries,
        slash: async (args) => { notes.length = 0; await commands.get("sandbox")?.handler(args, ctx); return notes.join("\n"); },
        shutdown: () => { handlers.get("session_shutdown")?.({ type: "session_shutdown" }, ctx); },
    };
}

const TOKEN = /\b(on|off|unavailable|inactive|active|true|false)\b/i;
/** The first state word after the measure's name; true/active count as on, false/inactive as off. */
function stateOf(text: string, measure: Measure): State | undefined {
    const at = text.search(new RegExp(`\\b${measure}\\b`, "i"));
    if (at < 0) return undefined;
    const word = TOKEN.exec(text.slice(at + measure.length))?.[1]?.toLowerCase();
    if (!word) return undefined;
    return word === "on" || word === "true" || word === "active" ? "on" : word === "unavailable" ? "unavailable" : "off";
}

async function views(session: Session): Promise<Record<string, string>> {
    return { audit: JSON.stringify(session.audit), "/sandbox workspace": await session.slash("workspace"), "/sandbox diagnostics confinement": await session.slash("diagnostics confinement") };
}

function expectStates(texts: Record<string, string>, expected: Record<Measure, State>): void {
    for (const [where, text] of Object.entries(texts)) {
        for (const measure of MEASURES) assert.equal(stateOf(text, measure), expected[measure], `${where}: state of ${measure}\n${text}`);
    }
}

const allOn: Record<Measure, State> = { ipc: "on", uts: "on", userns: "on", keyring: "on", fds: "on" };

test("[visibility] a default session: the audit entry is active and the audit and both views list every measure as on", { skip }, async () => {
    const session = await startSession(undefined);
    try {
        assert.equal(session.audit?.active, true, "the launch audit entry is active");
        expectStates(await views(session), allOn);
    } finally { session.shutdown(); }
});

test("[visibility] a measure switched off by policy is shown as off; the others stay on; the entry stays active", { skip }, async () => {
    for (const measure of MEASURES) {
        const session = await startSession({ [measure]: false });
        try {
            assert.equal(session.audit?.active, true, `${measure}=false: still active`);
            expectStates(await views(session), { ...allOn, [measure]: "off" });
        } finally { session.shutdown(); }
    }
});

test("[visibility] a configured hostname does not hide the uts state", { skip }, async () => {
    const session = await startSession({ hostname: "pbs-test-host" });
    try {
        assert.equal(session.audit?.active, true);
        expectStates(await views(session), allOn);
    } finally { session.shutdown(); }
});

// ---- unavailable: controller level, fake bubblewrap through the lookup seam --------------
let unavailableFixture: Fixture | undefined;
after(() => { if (unavailableFixture) rmSync(unavailableFixture.root, { recursive: true, force: true }); });

async function controllerViews(hardening: Record<string, unknown> | undefined, fake: string) {
    unavailableFixture ??= makeFixture("pbs-hardening-visibility-ctl-");
    const fx = unavailableFixture;
    const seams = lookupWith(fake);
    const controller = controllerFor(fx, rawPolicy(fx, hardening), seams);
    const entries: any[] = [];
    controller.onReadConfinementRecord((record) => entries.push(record));
    controller.recordReadConfinement();
    const ran = await confinedExec(controller, fx, "echo CMD-RAN-MARK", { seams, timeoutSeconds: 30 })
        .then((out) => out.exitCode === 0 && out.output.includes("CMD-RAN-MARK"), () => false);
    controller.recordReadConfinement(); // a launch that failed closed may change the record
    const out: string[] = [];
    const ctx = { ui: { notify: (m: string) => out.push(m) } } as unknown as ExtensionCommandContext;
    await handleDiagnosticsCommand("confinement", ctx, () => controller.readConfinementReport());
    const audit = entries.at(-1);
    const texts = { audit: JSON.stringify(audit), "/sandbox workspace": formatWorkspace(controller.workspaceInfo()), "/sandbox diagnostics confinement": out.join("\n") };
    return { controller, audit, texts, ran };
}

async function unavailable(missing: string[], measure: Measure, reason: RegExp, version?: string): Promise<void> {
    unavailableFixture ??= makeFixture("pbs-hardening-visibility-ctl-");
    const dir = join(unavailableFixture.root, `bwrap-without-${measure}`);
    mkdirSync(dir, { recursive: true });
    const fake = writeFakeBwrap(dir, "bwrap", missing, version);
    const lacking = await controllerViews(undefined, fake);
    try {
        assert.equal(lacking.ran, false, `${measure} on but not applicable: the command must not run`);
        assert.equal(lacking.audit?.active, false, `${measure} on but not applicable: the audit entry is inactive`);
        assert.match(String(lacking.audit?.reason), reason, "the entry carries a reason that names the measure");
        for (const [where, text] of Object.entries(lacking.texts)) {
            assert.equal(stateOf(text, measure), "unavailable", `${where}: ${measure} is unavailable\n${text}`);
            for (const other of ["ipc", "uts", "fds"] as const) assert.notEqual(stateOf(text, other), "unavailable", `${where}: ${other} is not blamed\n${text}`);
        }
        assert.match(lacking.texts["/sandbox diagnostics confinement"], reason, "the diagnostics view shows the reason");
    } finally { lacking.controller.dispose(); }
    // The same bubblewrap is fine once the measure is switched off by policy: it is off, not unavailable.
    const off = await controllerViews({ [measure]: false }, fake);
    try {
        assert.equal(off.ran, true, `${measure}=false needs no capability: the command runs`);
        assert.equal(off.audit?.active, true, `${measure}=false: active`);
        for (const [where, text] of Object.entries(off.texts)) assert.equal(stateOf(text, measure), "off", `${where}\n${text}`);
    } finally { off.controller.dispose(); }
}

test("[visibility] userns on with a bubblewrap lacking --disable-userns: inactive entry with a reason; views show it unavailable", { skip }, async () => {
    await unavailable(["--disable-userns", "--assert-userns-disabled"], "userns", /userns|user namespace|disable-userns/i, "0.4.1");
});

test("[visibility] keyring on with a bubblewrap lacking seccomp program support: inactive entry with a reason; views show it unavailable", { skip }, async () => {
    await unavailable(["--seccomp", "--add-seccomp-fd"], "keyring", /keyring|seccomp|keyctl/i);
});
