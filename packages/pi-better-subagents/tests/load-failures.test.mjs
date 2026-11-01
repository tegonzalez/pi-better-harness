/**
 * Fail-fast load: a config or catalog file that fails to load or parse is
 * surfaced at load and refuses the launch instead of silently running with
 * the shipped defaults or a lower-priority definition.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "load-failures-"));
const runtimeTmp = join(root, "tmp");
mkdirSync(runtimeTmp, { recursive: true });
process.env.TMPDIR = runtimeTmp;
process.env.PI_CODING_AGENT_DIR = join(root, "agent");
mkdirSync(process.env.PI_CODING_AGENT_DIR, { recursive: true });

const { configLoadError, loadConfig, loadLaunchConfig, setConfigForTests, setConfigPathForTests } = await import("../config.ts");
const { loadLaunchSnapshot, prepareCatalogJob } = await import("../catalog-runtime.ts");
const { baseDir } = await import("../registry.ts");
const { default: extension } = await import("../index.ts");

after(() => {
    setConfigPathForTests(undefined);
    rmSync(root, { recursive: true, force: true });
});

function model(provider, id) {
    return { provider, id, reasoning: true };
}

function configFixture(t) {
    const dir = mkdtempSync(join(root, "config-"));
    const path = join(dir, "settings.json");
    const bundled = join(dir, "bundled.json");
    writeFileSync(bundled, JSON.stringify({ maxConcurrent: 4, defaultTools: "read" }));
    setConfigPathForTests(path, bundled);
    t.after(() => setConfigPathForTests(undefined));
    return { path, bundled };
}

describe("config load failures", { concurrency: false }, () => {
    it("records an invalid saved section, keeps readers on the fallback, and refuses launch config until repaired", (t) => {
        const { path } = configFixture(t);
        writeFileSync(path, JSON.stringify({ piBetterHarness: { subagents: { defaultModel: "local/x" } } }));
        assert.equal(loadLaunchConfig().defaultModel, "local/x");
        assert.equal(configLoadError(), undefined);

        writeFileSync(path, "{broken");
        assert.deepEqual(loadConfig(), { maxConcurrent: 4, defaultTools: "read" });
        assert.ok(configLoadError(), "the load failure is recorded, not swallowed");
        assert.match(configLoadError().message, new RegExp(path.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")));
        assert.throws(() => loadLaunchConfig(), (error) => {
            assert.match(error.message, /Subagent config failed to load/);
            assert.match(error.message, /settings\.json/);
            assert.match(error.message, /no child was started/i);
            return true;
        });

        writeFileSync(path, JSON.stringify({ piBetterHarness: { subagents: { maxConcurrent: 2 } } }));
        assert.equal(loadLaunchConfig().maxConcurrent, 2);
        assert.equal(configLoadError(), undefined);
    });

    it("records an unparseable shipped config.json instead of silently dropping its defaults", (t) => {
        const { bundled } = configFixture(t);
        writeFileSync(bundled, "{ not json");
        loadConfig();
        assert.ok(configLoadError());
        assert.match(configLoadError().message, /bundled\.json/);
        assert.throws(() => loadLaunchConfig(), /Subagent config failed to load/);
    });

    it("subagent_spawn and subagent_spawn_batch refuse to launch and session_start reports the error", async (t) => {
        const { path } = configFixture(t);
        writeFileSync(path, '{"piBetterHarness":{"subagents":[]}}');
        const tools = {};
        const events = {};
        extension({
            registerTool(tool) { tools[tool.name] = tool; },
            registerCommand() {},
            on(name, handler) { events[name] = handler; },
            sendMessage() {},
            appendEntry() {},
        });
        const notices = [];
        const ctx = {
            cwd: root,
            hasUI: true,
            mode: "rpc",
            model: model("local", "fg"),
            modelRegistry: { getAvailable: () => [model("local", "fg")] },
            isProjectTrusted: () => true,
            isIdle: () => true,
            sessionManager: { getSessionId: () => "s1", getBranch: () => [], getEntries: () => [] },
            ui: { notify(message, level) { notices.push({ message, level }); }, select: async () => undefined, setWidget() {}, setStatus() {} },
        };
        await events.session_start?.({}, ctx);
        assert.ok(notices.some((item) => /Subagent config failed to load/.test(item.message) && item.level === "error"),
            `session_start must report the load error; got ${JSON.stringify(notices)}`);

        const runsDir = join(baseDir(), "runs");
        const before = new Set(existsSync(runsDir) ? readdirSync(runsDir) : []);
        await assert.rejects(tools.subagent_spawn.execute("tc", { prompt: "hi", tools: "read", sandbox: false }, null, null, ctx),
            /Subagent config failed to load/);
        await assert.rejects(tools.subagent_spawn_batch.execute("tc", { jobs: [{ prompt: "a" }, { prompt: "b" }] }, null, null, ctx),
            /Subagent config failed to load/);
        await assert.rejects(tools.subagent_spawn.execute("tc", { prompt: "hi", role: "developer", tools: "read", sandbox: false }, null, null, ctx),
            /Subagent config failed to load/);
        const created = (existsSync(runsDir) ? readdirSync(runsDir) : []).filter((id) => !before.has(id));
        assert.deepEqual(created, []);
        setConfigForTests(undefined);
    });
});

describe("catalog load failures", { concurrency: false }, () => {
    it("blocks a catalog launch when a catalog file could not be read, naming the file", { skip: process.getuid?.() === 0 ? "root reads mode 000 files" : false }, async (t) => {
        setConfigForTests({ defaultModel: null, tierPolicy: null, maxConcurrent: 4 });
        t.after(() => setConfigForTests(undefined));
        const userRoot = mkdtempSync(join(root, "user-"));
        const cwd = mkdtempSync(join(root, "proj-"));
        const roles = join(userRoot, "agents", "roles");
        mkdirSync(roles, { recursive: true });
        // Meant to override the bundled reviewer; unreadable, so its id is unknown.
        const broken = join(roles, "my-reviewer.md");
        writeFileSync(broken, "---\nschema: pi-agent/v1\nkind: role\nid: role.reviewer\nname: My Reviewer\n---\nx\n");
        chmodSync(broken, 0o000);
        t.after(() => chmodSync(broken, 0o644));
        const host = {
            cwd,
            projectTrusted: true,
            userRoot,
            projectConfigDirName: ".pi",
            hasUI: false,
            foregroundModel: "openai/gpt-6-luna",
            configuredDefaultModel: null,
            registry: { getAvailable: () => [model("openai", "gpt-6.1-sol"), model("openai", "gpt-6-luna"), model("openai", "gpt-6-astra")], find: () => undefined },
        };
        const snapshot = loadLaunchSnapshot(host);
        const prepared = await prepareCatalogJob(snapshot, { prompt: "Review.", role: "role.reviewer" }, host);
        assert.equal(prepared.status, "blocked");
        assert.match(prepared.message, /my-reviewer\.md/);
        assert.match(prepared.message, /failed to load/);
        assert.match(prepared.message, /Repair or remove/);
        assert.match(prepared.message, /No child was started/);

        // A catalog-free launch does not depend on the catalog.
        const legacy = await prepareCatalogJob(snapshot, { prompt: "Plain." }, host);
        assert.equal(legacy.status, "legacy");

        chmodSync(broken, 0o644);
        const repaired = await prepareCatalogJob(loadLaunchSnapshot(host), { prompt: "Review.", role: "role.reviewer" }, host);
        assert.equal(repaired.status, "ready", repaired.message);
    });

    it("blocks a catalog launch when a catalog file has no readable id", async (t) => {
        setConfigForTests({ defaultModel: null, tierPolicy: null, maxConcurrent: 4 });
        t.after(() => setConfigForTests(undefined));
        const userRoot = mkdtempSync(join(root, "user-"));
        const cwd = mkdtempSync(join(root, "proj-"));
        const agents = join(userRoot, "agents", "agents");
        mkdirSync(agents, { recursive: true });
        writeFileSync(join(agents, "payments.md"), "---\nschema: [unclosed\n---\nbody\n");
        const host = {
            cwd,
            projectTrusted: true,
            userRoot,
            hasUI: false,
            foregroundModel: "openai/gpt-6-luna",
            configuredDefaultModel: null,
            registry: { getAvailable: () => [model("openai", "gpt-6.1-sol"), model("openai", "gpt-6-luna")], find: () => undefined },
        };
        const prepared = await prepareCatalogJob(loadLaunchSnapshot(host), { prompt: "Build.", role: "role.developer" }, host);
        assert.equal(prepared.status, "blocked");
        assert.match(prepared.message, /payments\.md/);
    });

    function roleInheritanceFixture(t, { projectRole = false } = {}) {
        setConfigForTests({ defaultModel: null, tierPolicy: null, maxConcurrent: 4 });
        t.after(() => setConfigForTests(undefined));
        const userRoot = mkdtempSync(join(root, "user-"));
        const cwd = mkdtempSync(join(root, "proj-"));
        const userRoles = join(userRoot, "agents", "roles");
        mkdirSync(userRoles, { recursive: true });
        // Meant to override the shipped developer role; its id cannot be read.
        writeFileSync(join(userRoles, "my-developer.md"), "---\nschema: [unclosed\n---\nbody\n");
        const projectAgents = join(cwd, ".pi", "agents", "agents");
        mkdirSync(projectAgents, { recursive: true });
        writeFileSync(join(projectAgents, "payments.md"),
            "---\nschema: pi-agent/v1\nkind: agent\nid: agent.payments\nname: Payments\nroleId: role.developer\ninstructions:\n  mode: add\n---\nPayments work.\n");
        if (projectRole) {
            const projectRoles = join(cwd, ".pi", "agents", "roles");
            mkdirSync(projectRoles, { recursive: true });
            writeFileSync(join(projectRoles, "developer.md"),
                "---\nschema: pi-agent/v1\nkind: role\nid: role.developer\nname: Project Developer\ndefaults:\n  model: openai/gpt-6.1-sol\n---\nProject developer.\n");
        }
        return {
            cwd,
            projectTrusted: true,
            userRoot,
            projectConfigDirName: ".pi",
            hasUI: false,
            foregroundModel: "openai/gpt-6-luna",
            configuredDefaultModel: null,
            registry: { getAvailable: () => [model("openai", "gpt-6.1-sol"), model("openai", "gpt-6-luna")], find: () => undefined },
        };
    }

    it("blocks a project agent whose inherited role resolves below a broken personal file", async (t) => {
        const host = roleInheritanceFixture(t);
        const snapshot = loadLaunchSnapshot(host);
        const prepared = await prepareCatalogJob(snapshot, { prompt: "Build.", agent: "agent.payments" }, host);
        assert.equal(prepared.status, "blocked", "the shipped role must not launch while a personal role file is broken");
        assert.match(prepared.message, /my-developer\.md/);
        assert.match(prepared.message, /No child was started/);
    });

    it("does not block a project agent and project role on a lower-ranked broken personal file", async (t) => {
        const host = roleInheritanceFixture(t, { projectRole: true });
        const prepared = await prepareCatalogJob(loadLaunchSnapshot(host), { prompt: "Build.", agent: "agent.payments" }, host);
        assert.equal(prepared.status, "ready", prepared.message);
    });
});
