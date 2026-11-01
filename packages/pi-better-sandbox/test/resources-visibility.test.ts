/**
 * D5 visibility: the configured `resources.command` limits and `resources.tmpSize` are recorded in the audit entry
 * `pi-better-sandbox-read-confinement`, shown by `/sandbox workspace` and `/sandbox diagnostics confinement`, and
 * covered by `policyHash` (the hash the real policy loader computes for the policy file).
 *
 * The real extension, driven the way test/hardening-visibility.test.ts and test/workspace.test.ts drive it (a
 * TUI-like session, policy location from the agent dir's settings). The format is the product's: the tests look for
 * each configured value in the text of each view, in its raw spelling or as the byte count a size converts to, and
 * for an integer as a whole number. Values are chosen so they cannot occur by accident.
 *
 * The command-limit session needs a reachable systemd user manager with the cpu, memory and pids controllers
 * (otherwise the limits cannot be applied and the entry is correctly inactive: that is covered in
 * resources-command.test.ts); the tmpSize-only session needs none.
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
import { base, baseSkip } from "./support/hardening-support.ts";
import { systemdSkip, type Resources } from "./support/limits-support.ts";

const kernelSkip = baseSkip();
const scopeSkip = kernelSkip || systemdSkip();

const fixtures = kernelSkip ? "" : realpathSync(mkdtempSync(join(base!, "pbs-resources-visibility-")));
const agentDir = join(fixtures, "agent");
const policyFile = join(fixtures, "policies", "policy.json");
const projectRoot = join(fixtures, "work", "project");
const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
const originalPolicyEnv = process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY;
const originalCwd = process.cwd();

if (!kernelSkip) {
    for (const dir of [agentDir, join(fixtures, "policies"), projectRoot]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(projectRoot, "file.txt"), "project\n");
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

type Session = { audit: any; slash: (args: string) => Promise<string>; shutdown: () => void };

async function startSession(resources: Resources | undefined): Promise<Session> {
    writeFileSync(policyFile, JSON.stringify({ version: 1, tools: { approved: ["sh", "cat"] }, ...(resources ? { resources } : {}) }));
    const commands = new Map<string, Omit<RegisteredCommand, "name" | "sourceInfo">>();
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => unknown>();
    const entries: { customType: string; data: any }[] = [];
    const notes: string[] = [];
    const ctx = {
        cwd: projectRoot, hasUI: true, mode: "tui", model: { provider: "test-provider", id: "test-model" }, thinkingLevel: "off",
        sessionManager: {
            getBranch: () => [{ type: "custom", customType: SESSION_PERMISSION_ENTRY, data: { version: 1, permissions: confinedSettings() } }],
            getSessionId: () => "resources-session", getSessionFile: () => join(fixtures, "resources-session.jsonl"),
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
        audit: audits.at(-1)?.data,
        slash: async (args) => { notes.length = 0; await commands.get("sandbox")?.handler(args, ctx); return notes.join("\n"); },
        shutdown: () => { handlers.get("session_shutdown")?.({ type: "session_shutdown" }, ctx); },
    };
}

const MiB = 1 << 20;
const views = async (session: Session): Promise<Record<string, string>> => ({
    audit: JSON.stringify(session.audit),
    "/sandbox workspace": await session.slash("workspace"),
    "/sandbox diagnostics confinement": await session.slash("diagnostics confinement"),
});

/** A size appears raw ("96M"), as a unit-spaced form ("96 MiB"), or as its byte count. */
const sizeMention = (mebibytes: number): RegExp => new RegExp(`\\b${mebibytes}\\s?(M|MiB|MB|Mi)\\b|\\b${mebibytes * MiB}\\b`);
const intMention = (value: number): RegExp => new RegExp(`(?<![\\w.])${value}(?![\\w.])`);

// Distinctive values: none of them is a default or a round number a view might print for another reason.
const COMMAND: Resources["command"] = { memoryMax: "96M", memorySwapMax: "48M", tasksMax: 1237, cpuQuota: 175, runtimeMaxSec: 1893 };
const TMP = "3M";

function expectCommandShown(texts: Record<string, string>): void {
    for (const [where, text] of Object.entries(texts)) {
        assert.match(text, sizeMention(96), `${where}: memoryMax\n${text}`);
        assert.match(text, sizeMention(48), `${where}: memorySwapMax\n${text}`);
        assert.match(text, intMention(1237), `${where}: tasksMax\n${text}`);
        assert.match(text, intMention(175), `${where}: cpuQuota\n${text}`);
        assert.match(text, intMention(1893), `${where}: runtimeMaxSec\n${text}`);
    }
}
function expectCommandAbsent(texts: Record<string, string>): void {
    for (const [where, text] of Object.entries(texts)) {
        assert.doesNotMatch(text, sizeMention(96), where);
        assert.doesNotMatch(text, intMention(1237), where);
        assert.doesNotMatch(text, intMention(1893), where);
    }
}

test("[visibility] command limits: the audit entry and both views show every configured value", { skip: scopeSkip }, async () => {
    const session = await startSession({ command: COMMAND });
    try {
        assert.equal(session.audit?.active, true, "the launch audit entry is active (the limits can be applied here)");
        expectCommandShown(await views(session));
    } finally { session.shutdown(); }
});

test("[visibility] tmpSize: the audit entry and both views show the configured size", { skip: kernelSkip }, async () => {
    const session = await startSession({ tmpSize: TMP });
    try {
        assert.equal(session.audit?.active, true);
        for (const [where, text] of Object.entries(await views(session))) assert.match(text, sizeMention(3), `${where}: tmpSize\n${text}`);
    } finally { session.shutdown(); }
});

test("[visibility] unset limits show nothing of the kind, and the entry stays active", { skip: kernelSkip }, async () => {
    const session = await startSession(undefined);
    try {
        assert.equal(session.audit?.active, true);
        const texts = await views(session);
        expectCommandAbsent(texts);
        for (const [where, text] of Object.entries(texts)) assert.doesNotMatch(text, sizeMention(3), where);
    } finally { session.shutdown(); }
});

test("[visibility] policyHash in the audit entry changes with each limit and with tmpSize", { skip: scopeSkip }, async () => {
    const variants: [string, Resources | undefined][] = [
        ["none", undefined],
        ["memoryMax", { command: { memoryMax: "96M" } }], ["memoryMax-2", { command: { memoryMax: "112M" } }],
        ["memorySwapMax", { command: { memorySwapMax: "48M" } }],
        ["tasksMax", { command: { tasksMax: 1237 } }], ["tasksMax-2", { command: { tasksMax: 1238 } }],
        ["cpuQuota", { command: { cpuQuota: 175 } }],
        ["runtimeMaxSec", { command: { runtimeMaxSec: 1893 } }],
        ["tmpSize", { tmpSize: TMP }], ["tmpSize-2", { tmpSize: "5M" }],
        ["all", { command: COMMAND, tmpSize: TMP }],
    ];
    const hashes = new Map<string, string>();
    for (const [name, resources] of variants) {
        const session = await startSession(resources);
        try {
            assert.equal(session.audit?.active, true, `${name}: active`);
            assert.match(String(session.audit?.policyHash), /^[0-9a-f]{64}$/, `${name}: the entry records a policy hash`);
            hashes.set(name, session.audit.policyHash);
        } finally { session.shutdown(); }
    }
    assert.equal(new Set(hashes.values()).size, hashes.size, `every variant has its own policyHash: ${JSON.stringify([...hashes])}`);
});

test("[visibility] changing a limit changes what the views show (no stale value)", { skip: scopeSkip }, async () => {
    const first = await startSession({ command: COMMAND });
    first.shutdown();
    const second = await startSession({ command: { ...COMMAND, tasksMax: 1555 } });
    try {
        for (const [where, text] of Object.entries(await views(second))) {
            assert.match(text, intMention(1555), `${where}: the new value`);
            assert.doesNotMatch(text, intMention(1237), `${where}: not the old one`);
        }
    } finally { second.shutdown(); }
});
