import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { register } from "node:module";
import { getSharedCapacityGate, _resetSharedCapacityGateForTests } from "../capacity.mjs";

register(new URL("./pi_host_stub_hooks.mjs", import.meta.url));

const { default: extension, subagentsArgumentCompletions } = await import("../index.ts");
const { setConfigForTests, setConfigPathForTests, loadConfig, writeSubagentSettings, normalizeConcurrencyCap } = await import("../config.ts");
const { normalizeDelegationMode, delegationPrompt, DELEGATION_MODE_REQUEST } = await import("../delegation.ts");

const SETTINGS = "pi-better-subagents-settings";

// A session model that follows pi's persistence rules for the hooks this extension uses:
// pi.sendMessage without triggerTurn appends a custom_message entry while idle, and a
// before_agent_start `message` is stored after the run's prompt. Model requests are built
// from the compaction-aware context entries and then passed through any `context` handler.
function harness() {
    const handlers = new Map();
    const commands = new Map();
    const tools = new Map();
    const notifications = [];
    const entries = [];
    const sent = [];
    const events = new EventEmitter();
    extension({
        events,
        appendEntry(customType, data) { entries.push({ type: "custom", customType, data }); },
        sendMessage(message, options) {
            sent.push({ message, options });
            entries.push({ type: "custom_message", customType: message.customType, content: message.content,
                display: message.display, details: message.details });
        },
        registerTool(tool) { tools.set(tool.name, tool); },
        registerCommand(name, command) { commands.set(name, command); },
        on(name, handler) { handlers.set(name, handler); },
    });
    const view = { contextEntries: () => entries };
    const ctx = { ui: { notify(message, level) { notifications.push({ message, level }); } },
        sessionManager: { getBranch: () => entries, buildContextEntries: () => view.contextEntries() } };
    const mode = () => { const request = {}; events.emit(DELEGATION_MODE_REQUEST, request); return request.mode; };
    const toMessage = (entry) => entry.type === "message" ? structuredClone(entry.message)
        : entry.type === "custom_message" ? { role: "custom", customType: entry.customType, content: entry.content,
            display: entry.display, details: structuredClone(entry.details) } : undefined;
    /** One model request: context entries as messages, through the context hook if one is registered. */
    const request = () => {
        const messages = view.contextEntries().map(toMessage).filter(Boolean);
        const hook = handlers.get("context");
        return hook ? hook({ type: "context", messages: structuredClone(messages) }, ctx)?.messages ?? messages : messages;
    };
    /** Start a run like pi: before_agent_start, then persist the prompt and any returned message. */
    const run = (prompt = "Next prompt") => {
        const result = handlers.get("before_agent_start")({ type: "before_agent_start", prompt, systemPrompt: "Base prompt." }, ctx) ?? {};
        entries.push({ type: "message", message: { role: "user", content: prompt } });
        if (result.message) entries.push({ type: "custom_message", ...structuredClone(result.message) });
        return result.systemPrompt;
    };
    const settingsMessages = (messages = request()) =>
        messages.filter((message) => message.role === "custom" && message.customType === SETTINGS);
    const latestSettings = () => { run(); return settingsMessages().at(-1); };
    return { handlers, commands, tools, notifications, entries, sent, ctx, view, mode, request, run, settingsMessages, latestSettings };
}

const stable = ({ revision, delegationMode, maxConcurrent, sources }) => ({ revision, delegationMode, maxConcurrent, sources });

test("effective settings replace stale context and share live reservations with spawn admission", async () => {
    setConfigForTests({ delegationMode: "adaptive", maxConcurrent: 4 });
    _resetSharedCapacityGateForTests();
    try {
        const h = harness();
        const inspect = () => h.tools.get("subagent_settings").execute();
        const original = (await inspect()).structuredContent;
        assert.equal(original.maxConcurrent, 4);
        assert.equal(original.sources.maxConcurrent, "config");
        const gate = getSharedCapacityGate(() => 0);
        assert.equal(gate.tryReserve(2, 4), true);
        const reserved = (await inspect()).structuredContent;
        assert.equal(reserved.pendingCount, 2);
        assert.equal(reserved.occupiedSlots, 2);
        assert.equal(reserved.availableSlots, 2);
        assert.equal(reserved.revision, original.revision, "occupancy changes do not change the settings revision");
        h.run("Keep my prompt");
        const customEntries = () => h.entries.filter((entry) => entry.type === "custom").length;
        const historySize = customEntries();
        await h.commands.get("subagents").handler("cap 1", h.ctx);
        const current = (await inspect()).structuredContent;
        assert.equal(current.maxConcurrent, 1);
        assert.equal(current.sources.maxConcurrent, "session");
        assert.equal(current.pendingCount, 2, "lowering the cap keeps existing reservations");
        assert.equal(current.availableSlots, 0);
        assert.notEqual(current.revision, original.revision);
        for (const name of ["subagent_spawn", "subagent_spawn_batch"]) {
            await assert.rejects(h.tools.get(name).execute("over-cap", name.endsWith("batch")
                ? { jobs: [{ prompt: "Must not launch" }] } : { prompt: "Must not launch" }, undefined, undefined, h.ctx),
            name.endsWith("batch") ? /0\/1 subagent slots free/ : /Max concurrent subagents \(1\)/);
        }
        await h.commands.get("subagents").handler("mode coordinator", h.ctx);
        const messages = h.request();
        assert.equal(messages[0].content, "Keep my prompt", "unrelated context is preserved");
        const block = messages.at(-1);
        assert.equal(block.customType, SETTINGS);
        assert.match(block.content, /concurrency limit 1 \(session\)/);
        assert.match(block.content, /delegation mode coordinator \(session\)/);
        assert.doesNotMatch(block.content, /adaptive/);
        assert.deepEqual(block.details, stable((await inspect()).structuredContent));
        assert.equal(customEntries(), historySize + 2, "only the two settings changes are persisted as setting entries");
        assert.equal(h.settingsMessages(messages).length, 3, "the first run and each change add one settings message");
        await h.commands.get("subagents").handler("cap 6", h.ctx);
        const increased = (await inspect()).structuredContent;
        assert.equal(increased.availableSlots, 4, "raising the limit makes capacity available immediately");
        gate.release(2);
        assert.equal((await inspect()).structuredContent.availableSlots, 6);
    } finally {
        setConfigForTests(undefined);
        _resetSharedCapacityGateForTests();
    }
});

test("settings context keeps earlier requests as a byte-stable prefix and adds one message per settings change", async () => {
    setConfigForTests({ delegationMode: "adaptive", maxConcurrent: 4 });
    _resetSharedCapacityGateForTests();
    try {
        const h = harness();
        const systemPrompt = h.run("First prompt");
        const first = h.request();
        assert.equal(h.settingsMessages(first).length, 1, "the first run adds one settings message");
        const [settings] = h.settingsMessages(first);
        assert.equal(settings.display, false);
        assert.match(settings.content, /delegation mode adaptive \(config\); concurrency limit 4 \(config\)/);
        assert.doesNotMatch(settings.content, /running|reserved|occupied|available/i, "injected context carries no live counts");
        assert.deepEqual(Object.keys(settings.details).sort(), ["delegationMode", "maxConcurrent", "revision", "sources"]);

        // Same settings, growing history, and changed occupancy: request 1 stays an exact prefix.
        const gate = getSharedCapacityGate(() => 0);
        assert.equal(gate.tryReserve(2, 4), true);
        h.entries.push({ type: "message", message: { role: "assistant", content: [{ type: "toolCall", id: "t1", name: "read", arguments: {} }] } });
        h.entries.push({ type: "message", message: { role: "toolResult", toolCallId: "t1", content: [{ type: "text", text: "ok" }] } });
        const second = h.request();
        assert.ok(second.length > first.length);
        assert.deepEqual(second.slice(0, first.length), first, "call 1 is an unchanged prefix of call 2");
        assert.equal(h.settingsMessages(second).length, 1);
        assert.equal(h.run("Second prompt"), systemPrompt, "the system prompt does not change with history or occupancy");
        const third = h.request();
        assert.deepEqual(third.slice(0, second.length), second, "an unchanged revision adds no settings message on the next run");
        assert.equal(h.settingsMessages(third).length, 1);
        assert.equal(h.sent.length, 0, "nothing is sent while settings are unchanged");

        // A settings change adds exactly one message at the point of change, without starting a turn.
        await h.commands.get("subagents").handler("cap 2", h.ctx);
        const changed = h.request();
        assert.equal(changed.length, third.length + 1);
        assert.deepEqual(changed.slice(0, third.length), third, "a settings change does not alter earlier messages");
        assert.equal(changed.at(-1).customType, SETTINGS);
        assert.match(changed.at(-1).content, /concurrency limit 2 \(session\)/);
        assert.deepEqual(h.sent.map(({ options }) => options), [{ triggerTurn: false }]);
        assert.equal(h.run("After change"), systemPrompt, "mode and limit changes leave the system prompt unchanged");
        assert.equal(h.settingsMessages().length, 2, "the next run does not repeat a revision the context already holds");
        await h.commands.get("subagents").handler("mode coordinator", h.ctx);
        assert.equal(h.run("After mode"), systemPrompt);
        assert.equal(h.settingsMessages().length, 3);

        // Compaction that summarizes the settings message away gets one fresh copy on the next run.
        const compactedAt = h.entries.length;
        h.view.contextEntries = () => [{ type: "message", message: { role: "user", content: "Summary" } }, ...h.entries.slice(compactedAt)];
        h.run("After compaction");
        const compacted = h.settingsMessages();
        assert.equal(compacted.length, 1);
        assert.match(compacted[0].content, /delegation mode coordinator \(session\); concurrency limit 2 \(session\)/);
        h.run("Later");
        assert.equal(h.settingsMessages().length, 1);
        gate.release(2);
    } finally {
        setConfigForTests(undefined);
        _resetSharedCapacityGateForTests();
    }
});

test("the delegation system prompt is deterministic, covers every mode, and points to live capacity", () => {
    const h = harness();
    const prompt = h.run();
    assert.equal(prompt, harness().run(), "independent instances produce the same prompt");
    for (const mode of ["manual", "adaptive", "coordinator"]) assert.ok(prompt.includes(delegationPrompt(mode)));
    assert.match(prompt, /ceiling, not a target/);
    assert.match(prompt, /call subagent_settings for current running, reserved, and available slots/);
    assert.doesNotMatch(prompt, /\b\d+\b/, "no counts, limits, or timestamps");
    assert.match(h.tools.get("subagent_settings").description, /Call it for live capacity/);
});

test("same-value session overrides revise provenance and saving restores the configured revision", async () => {
    const dir = mkdtempSync(join(tmpdir(), "delegation-source-revision-"));
    const path = join(dir, "settings.json");
    const defaults = { piBetterHarness: { subagents: { delegationMode: "adaptive", maxConcurrent: 3 } } };
    writeFileSync(path, JSON.stringify(defaults));
    setConfigPathForTests(path);
    try {
        const h = harness();
        const command = h.commands.get("subagents");
        const inspect = async () => {
            const entries = structuredClone(h.entries);
            const result = await h.tools.get("subagent_settings").execute();
            assert.notEqual(result.isError, true);
            assert.deepEqual(h.entries, entries, "inspection does not persist a settings snapshot");
            assert.deepEqual(h.latestSettings().details, stable(result.structuredContent),
                "the next request context and inspection agree on values, sources, and revision");
            return result.structuredContent;
        };
        const configured = await inspect();
        assert.equal(configured.maxConcurrent, 3);
        assert.equal(configured.delegationMode, "adaptive");
        assert.deepEqual(configured.sources, { delegationMode: "config", maxConcurrent: "config" });
        const { revision: configuredRevision, ...configuredValues } = configured;
        for (const [args, key] of [["cap 3", "maxConcurrent"], ["mode adaptive", "delegationMode"]]) {
            await command.handler(args, h.ctx);
            const overridden = await inspect();
            const { revision, ...values } = overridden;
            assert.deepEqual(values, { ...configuredValues, sources: { ...configured.sources, [key]: "session" } });
            assert.notEqual(revision, configuredRevision, "a source-only override changes the settings revision");
            await command.handler("save", h.ctx);
            assert.deepEqual(await inspect(), configured, "saving unchanged values restores config sources and revision");
            assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), defaults, "saved mode and numeric cap stay unchanged");
            const fresh = harness();
            assert.deepEqual((await fresh.tools.get("subagent_settings").execute()).structuredContent, configured,
                "a new extension sees the same saved defaults and revision");
        }
    } finally {
        setConfigPathForTests(undefined);
        rmSync(dir, { recursive: true, force: true });
    }
});

test("session cap validates input and follows reload, branch navigation, and reset", async () => {
    setConfigForTests({ delegationMode: "manual", maxConcurrent: 3 });
    try {
        const h = harness();
        const command = h.commands.get("subagents");
        await command.handler("cap 6", h.ctx);
        for (const value of ["0", "-1", "1.5", "abc", "9007199254740992"]) {
            const before = h.entries.length;
            await command.handler(`cap ${value}`, h.ctx);
            assert.equal(h.entries.length, before, "invalid caps do not alter session history");
            assert.equal(h.notifications.at(-1).level, "warning");
        }
        await command.handler("settings", h.ctx);
        assert.match(h.notifications.at(-1).message, /Concurrent subagents: 6\./);
        await h.handlers.get("session_start")({}, { ...h.ctx, mode: "print", hasUI: false, cwd: process.cwd(), isIdle: () => true });
        await command.handler("settings", h.ctx);
        assert.match(h.notifications.at(-1).message, /Concurrent subagents: 6\./);
        h.entries.length = 0;
        await h.handlers.get("session_tree")({}, h.ctx);
        await command.handler("settings", h.ctx);
        assert.match(h.notifications.at(-1).message, /Concurrent subagents: 3\./);
        await command.handler("cap 9", h.ctx);
        await command.handler("mode coordinator", h.ctx);
        await command.handler("reset", h.ctx);
        await command.handler("settings", h.ctx);
        assert.match(h.notifications.at(-1).message, /Delegation mode: manual\. Concurrent subagents: 3\./);
    } finally {
        setConfigForTests(undefined);
    }
});

test("settings save refuses corrupt config without discarding session choices", async () => {
    const dir = mkdtempSync(join(tmpdir(), "subagent-settings-"));
    const path = join(dir, "settings.json");
    setConfigPathForTests(path);
    try {
        const h = harness();
        await h.commands.get("subagents").handler("cap 8", h.ctx);
        writeFileSync(path, "{broken");
        await h.commands.get("subagents").handler("save", h.ctx);
        assert.equal(readFileSync(path, "utf8"), "{broken");
        assert.equal(h.notifications.at(-1).level, "warning");
        await h.commands.get("subagents").handler("settings", h.ctx);
        assert.match(h.notifications.at(-1).message, /Concurrent subagents: 8\./);
        writeFileSync(path, "{}");
        writeSubagentSettings({ delegationMode: "manual", maxConcurrent: 5 });
        assert.equal(loadConfig().maxConcurrent, 5);
        assert.equal(normalizeConcurrencyCap(5), 5);
        for (const value of [undefined, null, 0, -1, 1.5, "8", NaN, Infinity]) {
            assert.equal(normalizeConcurrencyCap(value), 4);
        }
    } finally {
        setConfigPathForTests(undefined);
        rmSync(dir, { recursive: true, force: true });
    }
});

test("normalization falls back to adaptive and each prompt expresses its boundary", () => {
    for (const value of [undefined, null, "invalid", "MANUAL", 1]) assert.equal(normalizeDelegationMode(value), "adaptive");
    assert.equal(normalizeDelegationMode("manual"), "manual");
    assert.equal(normalizeDelegationMode("coordinator"), "coordinator");
    assert.match(delegationPrompt("manual"), /plan mode does not override/);
    assert.match(delegationPrompt("manual"), /explicitly asks/);
    assert.doesNotMatch(delegationPrompt("manual"), /Delegate every nontrivial/);
    assert.match(delegationPrompt("adaptive"), /substantial independent work/);
    assert.match(delegationPrompt("coordinator"), /agents_catalog/);
    assert.match(delegationPrompt("coordinator"), /every nontrivial task covered by an available role/);
    assert.match(delegationPrompt("coordinator"), /unowned or ambiguous work/);
});

test("/subagents action completions expose complete mode selections with context", () => {
    assert.deepEqual(subagentsArgumentCompletions(""), [
        { value: "settings", label: "settings", description: "Open delegation mode and concurrency settings" },
        { value: "cap", label: "cap <number>", description: "Set a positive concurrent subagent limit for this session" },
        { value: "reset", label: "reset", description: "Reset session mode and cap to saved defaults" },
        { value: "mode manual", label: "mode manual", description: "Delegate only when explicitly requested" },
        { value: "mode adaptive", label: "mode adaptive", description: "Delegate substantial independent work" },
        { value: "mode coordinator", label: "mode coordinator", description: "Delegate role-owned work by default" },
        { value: "save", label: "save", description: "Save the current mode and cap as defaults" },
    ]);
    assert.deepEqual(subagentsArgumentCompletions(" mode a")?.map((entry) => entry.value), ["mode adaptive"]);
    assert.equal(subagentsArgumentCompletions("mode invalid"), null);
    const command = harness().commands.get("subagents");
    assert.deepEqual(command.getArgumentCompletions("mode c").map((entry) => entry.value), ["mode coordinator"]);
    assert.match(command.description, /settings.*cap <number>.*save.*reset/);
});

test("/subagents save confirms, preserves other config, and clears the session override", async () => {
    const dir = mkdtempSync(join(tmpdir(), "delegation-save-"));
    const path = join(dir, "settings.json");
    writeFileSync(path, JSON.stringify({ piBetterHarness: { subagents: { defaultTools: "read", delegationMode: "adaptive" } } }));
    setConfigPathForTests(path);
    try {
        const h = harness();
        const command = h.commands.get("subagents");
        await command.handler("mode coordinator", h.ctx);
        await command.handler("cap 7", h.ctx);
        h.ctx.hasUI = true;
        h.ctx.ui.confirm = async () => false;
        await command.handler("save", h.ctx);
        assert.equal(JSON.parse(readFileSync(path, "utf8")).piBetterHarness.subagents.delegationMode, "adaptive");
        assert.match(h.notifications.at(-1).message, /unchanged/);
        h.ctx.ui.confirm = async () => true;
        await command.handler("save", h.ctx);
        const saved = JSON.parse(readFileSync(path, "utf8")).piBetterHarness.subagents;
        assert.equal(saved.delegationMode, "coordinator");
        assert.equal(saved.maxConcurrent, 7);
        assert.equal(saved.defaultTools, "read");
        assert.equal(h.entries.findLast((entry) => entry.customType === "pi-better-subagents-delegation").data.mode, null);
        assert.equal(h.mode(), "coordinator");
        await h.handlers.get("session_start")({ reason: "reload" }, { ...h.ctx, mode: "print", hasUI: false, cwd: process.cwd(), sessionManager: h.ctx.sessionManager, isIdle: () => true });
        assert.equal(h.mode(), "coordinator", "a saved default survives reload after the session override is cleared");
        await command.handler("settings", h.ctx);
        assert.match(h.notifications.at(-1).message, /Concurrent subagents: 7\./);
    } finally {
        setConfigPathForTests(undefined);
        setConfigForTests(undefined);
        rmSync(dir, { recursive: true, force: true });
    }
});

test("/subagents reports config, changes only this session, rejects invalid args and injects current mode", async () => {
    setConfigForTests({ delegationMode: "manual" });
    try {
        const h = harness();
        const command = h.commands.get("subagents");
        assert.ok(command);
        await command.handler("", h.ctx);
        assert.match(h.notifications.at(-1).message, /^Delegation mode: manual\. Concurrent subagents: 4\./);
        assert.match(h.latestSettings().content, /delegation mode manual/);
        await command.handler("mode coordinator", h.ctx);
        assert.equal(h.mode(), "coordinator");
        assert.match(h.latestSettings().content, /delegation mode coordinator/);
        await command.handler("mode adaptive extra", h.ctx);
        assert.match(h.notifications.at(-1).message, /Usage: \/subagents/);
        assert.equal(h.notifications.at(-1).level, "warning");
        assert.equal(h.mode(), "coordinator");
        await command.handler("mode adaptive", h.ctx);
        assert.match(h.latestSettings().content, /delegation mode adaptive/);
        await h.handlers.get("session_start")({ reason: "reload" }, { ...h.ctx, mode: "print", hasUI: false, cwd: process.cwd(), sessionManager: { ...h.ctx.sessionManager, getSessionId: () => "test" }, isIdle: () => true });
        assert.equal(h.mode(), "adaptive");
        await command.handler("mode coordinator", h.ctx);
        await h.handlers.get("session_start")({ reason: "reload" }, { ...h.ctx, mode: "print", hasUI: false, cwd: process.cwd(), sessionManager: { ...h.ctx.sessionManager, getSessionId: () => "test" }, isIdle: () => true });
        assert.equal(h.mode(), "coordinator", "the session entry restores an override after reload");
        h.entries.length = 0;
        await h.handlers.get("session_tree")({ reason: "branch-change" }, h.ctx);
        assert.equal(h.mode(), "manual", "a branch without an override returns to the configured mode");
        const another = harness();
        assert.equal(another.mode(), "manual", "an override must not change config or another extension instance");
    } finally {
        setConfigForTests(undefined);
    }
});
