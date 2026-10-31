/**
 * Workspace binding: the agent dir carries the policy location, `/sandbox` shows the active
 * workspace, `/sandbox check` decides with the tools' own evaluator, and a TUI-like session
 * (the owner's separate pi in the working folder) runs `!` commands under the identical
 * confined plan, with the same hashes as a second session on the same workspace.
 * Fixtures live under an explicit non-temp base (the sandbox's /tmp is writable by design and
 * a policy file may not live in scratch); override with PI_SANDBOX_TEST_NON_TEMP_BASE.
 * @level unit
 * @level integration
 */
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import test, { after, before } from "node:test";
import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext, RegisteredCommand, ToolDefinition, UserBashEventResult } from "@earendil-works/pi-coding-agent";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

import piBetterSandbox from "../index.ts";
import { READ_CONFINEMENT_ENTRY, configuredReadConfinementPolicyFile } from "../read-confinement-settings.ts";
import { defaultSandboxPermissions } from "../permissions.ts";
import { SESSION_PERMISSION_ENTRY } from "../session-permissions.ts";
import { hashPolicy, parseReadConfinementPolicy } from "../shared-read-confinement.ts";
import { ForegroundSandboxController } from "../state.ts";
import { formatPathCheck, formatWorkspace } from "../workspace.ts";
import { nonTempBase } from "./support/fixture-base.ts";
import { realBackendSkip } from "./support/resolvable-backend.ts";

const base = nonTempBase();
const baseSkip = base === undefined ? "no writable non-temp fixture base (set PI_SANDBOX_TEST_NON_TEMP_BASE)" : false;
const backendSkip = baseSkip || realBackendSkip();
const linuxOnly = process.platform === "linux" ? false : "Linux bubblewrap only";
const skip = backendSkip || linuxOnly;

const fixtures = base ? realpathSync(mkdtempSync(join(base, "pi-better-sandbox-workspace-"))) : "";
const agentDir = join(fixtures, "agent");
const policyDir = join(fixtures, "policies");
const policyFile = join(policyDir, "policy.json");
const projectRoot = join(fixtures, "work", "project");
const otherProject = join(fixtures, "work", "other-project");
const shared = join(fixtures, "shared-folder");
const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
const originalPolicyEnv = process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY;
const originalCwd = process.cwd();

const policy = { version: 1 as const, readOnly: [shared], tools: { approved: ["sh", "cat", "ls"] } };

if (base) {
    for (const dir of [agentDir, policyDir, projectRoot, otherProject, shared]) mkdirSync(dir, { recursive: true });
    writeFileSync(policyFile, JSON.stringify(policy));
    writeFileSync(join(projectRoot, "file.txt"), "project\n");
    // A checkout, as a real working folder is: the sandbox leaves placeholders for protected entries
    // (.env, .git/hooks, ...) on first launch, which would otherwise change the plan between sessions.
    mkdirSync(join(projectRoot, ".git", "hooks"), { recursive: true });
    mkdirSync(join(projectRoot, ".git", "info"), { recursive: true });
    mkdirSync(join(projectRoot, ".git", "objects", "info"), { recursive: true });
    for (const name of ["config", "config.worktree", "info/attributes", "objects/info/alternates", "objects/info/http-alternates", "gitdir"]) writeFileSync(join(projectRoot, ".git", name), "");
    writeFileSync(join(projectRoot, ".git", "commondir"), ".\n");
    for (const name of [".env", ".env.local", ".pi"]) writeFileSync(join(projectRoot, name), "");
    writeFileSync(join(otherProject, "secret.txt"), "other project\n");
    writeFileSync(join(shared, "doc.txt"), "shared doc\n");
    // The workspace's agent dir carries the policy location: no PI_SANDBOX_READ_CONFINEMENT_POLICY needed.
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

test("a plain PI_CODING_AGENT_DIR applies the policy named in the agent dir's settings", { skip: baseSkip }, () => {
    assert.equal(getAgentDir(), agentDir);
    assert.equal(configuredReadConfinementPolicyFile(), policyFile, "no env var and no seams: the agent dir settings decide");
    const expected = hashPolicy(parseReadConfinementPolicy(policy));
    const controller = new ForegroundSandboxController();
    controller.beginSession(projectRoot);
    const info = controller.workspaceInfo();
    assert.equal(info.policyPath, policyFile);
    assert.equal(info.policyHash, expected);
    assert.equal(info.agentDir, agentDir);
    assert.equal(info.cwd, projectRoot);
    controller.dispose();
});

test("an env-var policy location still wins over the agent dir setting", { skip: baseSkip }, () => {
    assert.equal(configuredReadConfinementPolicyFile({ env: { PI_SANDBOX_READ_CONFINEMENT_POLICY: "/absolute/other.json" } }), "/absolute/other.json");
});

test("a policy file inside the working folder (writable) is refused for the workspace", { skip: baseSkip }, () => {
    const inside = join(projectRoot, "policy.json");
    writeFileSync(inside, JSON.stringify(policy));
    const controller = new ForegroundSandboxController({ readConfinement: { loadPolicy: () => ({ policy: parseReadConfinementPolicy(policy), source: inside, sha256: hashPolicy(policy) }) } });
    controller.beginSession(projectRoot);
    assert.equal(controller.workspaceInfo().confinement, "failed");
    assert.match(controller.workspaceInfo().note ?? "", /policy file .* is inside/);
    controller.dispose();
    rmSync(inside);
});

test("the workspace and path check format is stable and carries the hashes", () => {
    const info = { cwd: "/w", agentDir: "/a", confinement: "active" as const, policyPath: "/p.json", policyHash: "h1", planHash: "h2" };
    assert.match(formatWorkspace(info), /cwd:\s+\/w[\s\S]*agent dir:\s+\/a[\s\S]*policy:\s+\/p\.json[\s\S]*policyHash: h1[\s\S]*planHash:\s+h2/);
    const verdict = { allowed: false, reason: "r" };
    assert.match(formatPathCheck({ input: "x", path: "/x", read: verdict, write: verdict, exec: verdict }), /read:\s+DENIED\s+r/);
});

// ---- a TUI-like owner session in the working folder --------------------------------------

const tools = new Map<string, ToolDefinition>();
const commands = new Map<string, Omit<RegisteredCommand, "name" | "sourceInfo">>();
const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => unknown>();
const entries: { customType: string; data: any }[] = [];
const notes: string[] = [];
let ctx: ExtensionCommandContext;

before(async () => {
    if (skip) return;
    ctx = {
        cwd: projectRoot, hasUI: true, mode: "tui",
        model: { provider: "test-provider", id: "test-model" }, thinkingLevel: "off",
        sessionManager: {
            getBranch: () => [{ type: "custom", customType: SESSION_PERMISSION_ENTRY, data: { version: 1, permissions: confinedSettings() } }],
            getSessionId: () => "owner-session", getSessionFile: () => join(fixtures, "owner-session.jsonl"),
        },
        ui: { theme: { fg: (_c: string, t: string) => t }, notify: (m: string) => notes.push(m), setStatus: () => undefined, confirm: async () => true },
    } as unknown as ExtensionCommandContext;
    process.chdir(projectRoot);
    const pi = {
        appendEntry: (customType: string, data: unknown) => entries.push({ customType, data }),
        events: { emit: () => undefined, on: () => () => undefined },
        registerTool: (tool: ToolDefinition) => tools.set(tool.name, tool),
        registerCommand: (name: string, command: Omit<RegisteredCommand, "name" | "sourceInfo">) => commands.set(name, command),
        on: (event: string, handler: (event: unknown, context: ExtensionContext) => unknown) => handlers.set(event, handler),
    } as unknown as ExtensionAPI;
    piBetterSandbox(pi);
    await handlers.get("session_start")?.({ type: "session_start", reason: "startup" }, ctx);
});

async function bang(command: string): Promise<{ exitCode: number | null; output: string }> {
    const result = handlers.get("user_bash")?.({ type: "user_bash", command, excludeFromContext: false, cwd: projectRoot }, ctx) as UserBashEventResult;
    assert.ok(result?.operations, "user_bash routes through the sandboxed operations");
    let output = "";
    const { exitCode } = await result.operations.exec(command, projectRoot, { onData: (chunk) => { output += chunk.toString(); } });
    return { exitCode, output };
}

async function slash(args: string): Promise<string> {
    notes.length = 0;
    await commands.get("sandbox")?.handler(args, ctx);
    return notes.join("\n");
}

test("/sandbox workspace and diagnostics show cwd, agent dir, policy and both hashes", { skip }, async () => {
    const audit = entries.find((e) => e.customType === READ_CONFINEMENT_ENTRY)?.data;
    assert.equal(audit?.active, true, "the launch audit entry is active");
    for (const text of [await slash("workspace"), await slash("diagnostics confinement")]) {
        assert.ok(text.includes(`cwd:        ${projectRoot}`), text);
        assert.ok(text.includes(`agent dir:  ${agentDir}`));
        assert.ok(text.includes(`policy:     ${policyFile}`));
        assert.ok(text.includes(`policyHash: ${audit.policyHash}`));
        assert.ok(text.includes(`planHash:   ${audit.planHash}`));
        assert.ok(text.includes("confinement: active"));
    }
});

test("/sandbox check reports read, write and exec with a reason, from the tools' own evaluator", { skip }, async () => {
    const inProject = await slash(`check ${join(projectRoot, "file.txt")}`);
    assert.match(inProject, /read:\s+ALLOWED/);
    assert.match(inProject, /write:\s+ALLOWED/);
    const relative = await slash("check file.txt");
    assert.match(relative, /read:\s+ALLOWED/);
    const other = await slash(`check ${join(otherProject, "secret.txt")}`);
    assert.match(other, /read:\s+DENIED\s+not mounted/);
    assert.match(other, /write:\s+DENIED/);
    assert.match(other, /exec:\s+DENIED/);
    const ro = await slash(`check ${join(shared, "doc.txt")}`);
    assert.match(ro, /read:\s+ALLOWED\s+read-only mount: read-only path from policy readOnly/);
    assert.match(ro, /write:\s+DENIED/);
    const missing = await slash("check");
    assert.match(missing, /needs a path/);
    // A symlink inside the project to the other project is decided on its realpath.
    symlinkSync(otherProject, join(projectRoot, "to-other"));
    assert.match(await slash("check to-other/secret.txt"), /read:\s+DENIED/);
    rmSync(join(projectRoot, "to-other"));
});

test("the check agrees with what `!` commands experience (read, write, network)", { skip }, async () => {
    // Read another project: not found.
    const read = await bang(`cat ${JSON.stringify(join(otherProject, "secret.txt"))}`);
    assert.notEqual(read.exitCode, 0);
    assert.match(read.output, /No such file or directory/);
    // The read-only shared folder reads but does not write.
    assert.equal((await bang(`cat ${JSON.stringify(join(shared, "doc.txt"))}`)).output, "shared doc\n");
    assert.notEqual((await bang(`echo x > ${JSON.stringify(join(shared, "new.txt"))}`)).exitCode, 0);
    assert.equal(existsSync(join(shared, "new.txt")), false);
    // Write outside the project: fails, no artifact.
    assert.notEqual((await bang(`echo x > ${JSON.stringify(join(otherProject, "w.txt"))}`)).exitCode, 0);
    assert.equal(existsSync(join(otherProject, "w.txt")), false);
    // Write inside: works.
    assert.equal((await bang(`echo ok > ${JSON.stringify(join(projectRoot, "bang.txt"))}`)).exitCode, 0);
    assert.equal(readFileSync(join(projectRoot, "bang.txt"), "utf8"), "ok\n");
    // The unapproved host tools are absent from PATH.
    assert.notEqual((await bang("curl --version")).exitCode, 0);
    // Network: a listener on the host loopback is unreachable (namespace unshared).
    let connections = 0;
    const server = createServer((socket) => { connections++; socket.end(); });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    try {
        const net = await bang(`exec 3<>/dev/tcp/127.0.0.1/${port}`);
        assert.notEqual(net.exitCode, 0);
        assert.equal(connections, 0);
    } finally { await new Promise<void>((resolve) => server.close(() => resolve())); }
});

test("a second session on the same workspace (agent dir, cwd, policy) reports identical hashes", { skip }, () => {
    const first = entries.find((e) => e.customType === READ_CONFINEMENT_ENTRY)!.data;
    const worker = new ForegroundSandboxController();
    worker.beginSession(projectRoot);
    const settings = confinedSettings();
    worker.setPermissionSettings(settings);
    const info = worker.workspaceInfo();
    assert.equal(info.policyHash, first.policyHash);
    assert.deepEqual(JSON.parse(JSON.stringify(worker.readConfinementRecord()?.active ? (worker.readConfinementRecord() as any).audit : null)), first.audit);
    assert.equal(info.planHash, first.planHash);
    worker.dispose();
});
