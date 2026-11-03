/**
 * A launch belongs to the session lifetime that asked for it.
 *
 * Policy under test: after a session ends (shutdown, reload, /new, /resume, fork)
 * nothing that belongs to that lifetime may start work, arm supervision or start a
 * model turn. Only `session_start` reopens an instance; a spawn never does.
 *
 *  - a spawn in a torn-down instance is refused before anything exists, and the
 *    health ticker stays off;
 *  - a LOCAL spawn whose catalog preparation is in flight across the shutdown is
 *    refused, leaves no run and no reserved slot, and arms nothing;
 *  - a REMOTE spawn whose launch (the ssh mux) is in flight across the shutdown
 *    resolves late, past the shutdown sweep: the child it started is stopped, the
 *    stop is recorded as a shutdown stop, the tool call fails with a refusal, no
 *    ticker is armed and no turn is started. This holds across a later
 *    `session_start` too (the launch belongs to the lifetime that ended);
 *  - the bridge of that late launch may exit, and be finalized, BEFORE the stop records
 *    `killed`: the run is already marked as belonging to the ended lifetime, so even with
 *    the teardown latch cleared and the same session id nothing it says starts a turn
 *    (at most one non-triggering notice), and the stop never overwrites the status the
 *    exit recorded.
 *
 * The remote launch is gated by a wrapper around the fake ssh transport
 * (tests/fixtures/remote/bin/ssh): it holds the ControlMaster establishment, the
 * only await between the remote-launch call and the recorded run, while
 * `$FAKE_SSH_DIR/mux-hold` exists. The "remote" pi is the fixture fake pi running
 * locally under a private HOME; no network and no real host.
 *
 * // @level integration
 */
import assert from "node:assert/strict";
import { after, beforeEach, describe, test } from "node:test";
import { EventEmitter } from "node:events";
import { register } from "node:module";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures", "remote");
const root = mkdtempSync(join(tmpdir(), "session-end-launch-"));
const original = {
    PATH: process.env.PATH, TMPDIR: process.env.TMPDIR, PI_CODING_AGENT_DIR: process.env.PI_CODING_AGENT_DIR,
    FAKE_SSH_DIR: process.env.FAKE_SSH_DIR, FAKE_REMOTE_HOME: process.env.FAKE_REMOTE_HOME, FAKE_PI_LOG: process.env.FAKE_PI_LOG,
};
process.env.TMPDIR = root;
process.env.PI_CODING_AGENT_DIR = join(root, "agent");
mkdirSync(process.env.PI_CODING_AGENT_DIR);

// Local child: an inert process that stays alive until stopped.
const bin = join(root, "bin");
mkdirSync(bin);
writeFileSync(join(bin, "pi"), `#!${process.execPath}\nsetInterval(() => {}, 1000);\n`, { mode: 0o755 });
// Remote transport: the fixture's fake ssh behind a gate on the ControlMaster establishment.
const sshDir = join(root, "ssh");
const remoteHome = join(root, "remote-home");
const sshBin = join(root, "ssh-bin");
mkdirSync(sshDir);
mkdirSync(join(remoteHome, "work"), { recursive: true });
mkdirSync(sshBin);
writeFileSync(join(sshBin, "ssh"), `#!/bin/sh
case "$*" in *ControlMaster=yes*) while [ -f "$FAKE_SSH_DIR/mux-hold" ]; do sleep 0.05; done;; esac
exec ${JSON.stringify(join(fixtures, "bin", "ssh"))} "$@"
`, { mode: 0o755 });
process.env.PATH = `${sshBin}:${bin}:${original.PATH}`;
process.env.FAKE_SSH_DIR = sshDir;
process.env.FAKE_REMOTE_HOME = remoteHome;
process.env.FAKE_PI_LOG = join(root, "pi.log");

// Keep the real catalog/model resolver; control only when its async result reaches
// execute (the in-flight window of a local launch). Host SDK packages are stubbed.
const catalogUrl = new URL("../catalog-runtime.ts", import.meta.url).href;
const wrapper = `export * from ${JSON.stringify(catalogUrl)};
import { prepareCatalogJob as prepare } from ${JSON.stringify(catalogUrl)};
export async function prepareCatalogJob(...args) {
    const result = await prepare(...args);
    await globalThis.__holdCatalogPreparation?.(args[1]);
    return result;
}`;
const stubs = new URL("./fixtures/earendil-stubs/", import.meta.url).href;
const loader = `export async function resolve(specifier, context, nextResolve) {
    if (specifier.startsWith("@earendil-works/")) {
        return { shortCircuit: true, url: ${JSON.stringify(stubs)} + specifier + "/index.js" };
    }
    if (specifier === "./catalog-runtime.ts" && context.parentURL?.endsWith("/index.ts")) {
        return { shortCircuit: true, url: ${JSON.stringify("data:text/javascript," + encodeURIComponent(wrapper))} };
    }
    return nextResolve(specifier, context);
}`;
register("data:text/javascript," + encodeURIComponent(loader));

const { default: extension, isHealthTickerActive, setShutdownStopForTests } = await import("../index.ts");
const { stopRemoteProcessAsync } = await import("../remote.ts");
const registry = await import("../registry.ts");
const capacity = await import("../capacity.mjs");
const config = await import("../config.ts");
const { killProcessTree } = await import("../spawn.ts");
const settingsPath = join(process.env.PI_CODING_AGENT_DIR, "settings.json");

const remoteTarget = {
    host: "example-alias",
    cwd: "~/work",
    pi: { command: process.execPath, args: [join(fixtures, "fake-pi.mjs")] },
    sandbox: { profile: "profile-a", env: { FAKE_SANDBOX_PROFILE: "{profile}" }, args: ["--sandbox-profile", "{profile}"], verifyTimeoutMs: 20_000 },
    termGraceSeconds: 2,
};

function save() {
    writeFileSync(settingsPath, JSON.stringify({ piBetterHarness: { subagents: {
        maxConcurrent: 6, defaultTools: "read", defaultModel: null, remoteTargets: { t: remoteTarget },
    } } }));
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(fn, { timeoutMs = 8000, intervalMs = 20 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const value = await fn();
        if (value) return value;
        if (Date.now() > deadline) return undefined;
        await pause(intervalMs);
    }
}
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

/** One extension instance with a host-like context. `start`/`shutdown` fire the real handlers. */
function harness(t, { sessionId = "launch-session" } = {}) {
    const tools = {};
    const handlers = {};
    const entries = [];
    const sent = [];
    const notes = [];
    extension({
        events: new EventEmitter(),
        registerTool(tool) { tools[tool.name] = tool; },
        registerCommand() {},
        appendEntry(customType, data) { entries.push({ type: "custom", customType, data }); },
        on(name, handler) { handlers[name] = handler; },
        sendMessage(message, options) { sent.push({ message, options }); },
    });
    const model = { provider: "local", id: "fixture", reasoning: true };
    const ctx = { cwd: root, model, hasUI: false, isIdle: () => true, isProjectTrusted: () => false,
        sessionManager: { getBranch: () => entries, getSessionId: () => sessionId }, modelRegistry: { getAvailable: () => [model] },
        ui: { setWidget() {}, notify: (msg, level) => notes.push({ msg, level }) } };
    const run = (tool, params) => tools[tool].execute("session-end", params, undefined, undefined, ctx);
    const start = () => handlers.session_start({ reason: "startup" }, ctx);
    const shutdown = (reason = "quit") => handlers.session_shutdown({ reason }, ctx);
    t.after(async () => {
        delete globalThis.__holdCatalogPreparation;
        rmSync(join(sshDir, "mux-hold"), { force: true });
        await start(); // reopen so the cleanup below can reach the stop path
        for (const meta of registry.listMetas().filter((m) => m.status === "running")) {
            try { await run("subagent_stop", { id: meta.id }); } catch { /* already gone */ }
        }
        await shutdown();
    });
    return { tools, ctx, run, sent, notes, start, shutdown, inspect: async () => (await run("subagent_settings", {})).structuredContent };
}

const triggering = (h) => h.sent.filter((entry) => entry.options?.triggerTurn === true);
const plain = (prompt) => ({ prompt, tools: "read", sandbox: false, callback: false });
const selected = (prompt) => ({ ...plain(prompt), role: "developer", model: "local/fixture", thinking: "low" });
const launchId = (result) => result.content[0].text.match(/id=(sa_[a-z0-9_]+)/)?.[1];
const runsOnDisk = () => { try { return readdirSync(join(registry.baseDir(), "runs")); } catch { return []; } };

function holdPreparation(prompt) {
    const entered = Promise.withResolvers();
    const resume = Promise.withResolvers();
    globalThis.__holdCatalogPreparation = async (job) => {
        if (job.prompt === prompt) {
            entered.resolve();
            await resume.promise;
        }
    };
    return { entered: entered.promise, release: () => resume.resolve() };
}

const remoteLeftovers = () => {
    const dir = join(remoteHome, ".pi-better-subagents", "runs");
    try {
        return readdirSync(dir).map((id) => {
            try { return Number(readFileSync(join(dir, id, "pid"), "utf8")); } catch { return undefined; }
        }).filter((pid) => Number.isInteger(pid));
    } catch { return []; }
};

beforeEach(() => {
    rmSync(registry.baseDir(), { recursive: true, force: true });
    rmSync(join(sshDir, "mux-hold"), { force: true });
    rmSync(join(sshDir, "master"), { force: true }); // an established master would skip the gated establishment
    capacity._resetSharedCapacityGateForTests();
    config.setConfigPathForTests(undefined);
    save();
});

after(() => {
    for (const pid of remoteLeftovers()) { try { killProcessTree(pid, "SIGKILL"); } catch { /* gone */ } }
    config.setConfigPathForTests(undefined);
    for (const [key, value] of Object.entries(original)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
    }
    rmSync(root, { recursive: true, force: true });
});

describe("a spawn in a torn-down instance", () => {
    test("is refused before anything exists, and the health ticker stays off until session_start", async (t) => {
        const h = harness(t);
        await h.start();
        const first = launchId(await h.run("subagent_spawn", plain("before shutdown")));
        assert.ok(first);
        assert.equal(isHealthTickerActive(), true, "supervision is armed while the session runs");
        await h.shutdown();
        assert.equal(isHealthTickerActive(), false);
        assert.equal(registry.readMeta(first).status, "killed", "shutdown stopped the session's run");
        const before = runsOnDisk();

        await assert.rejects(h.run("subagent_spawn", plain("after shutdown")), /launch refused: the session that asked for it has ended/);
        assert.equal(isHealthTickerActive(), false, "a refused spawn does not re-arm supervision");
        assert.deepEqual(runsOnDisk(), before, "nothing was created for the refused launch");
        assert.equal((await h.inspect()).pendingCount, 0, "its capacity reservation is released");
        assert.deepEqual(triggering(h), []);

        await h.start();
        const second = launchId(await h.run("subagent_spawn", plain("after session_start")));
        assert.ok(second, "only session_start reopens the instance");
        assert.equal(isHealthTickerActive(), true);
    });

    test("a batch launch is refused job by job and starts nothing", async (t) => {
        const h = harness(t);
        await h.start();
        await h.shutdown();
        const before = runsOnDisk();
        const outcome = await h.run("subagent_spawn_batch", { jobs: [plain("one"), plain("two")] }).catch((error) => error);
        const text = JSON.stringify(outcome?.structuredContent ?? outcome?.content ?? String(outcome?.message ?? outcome));
        assert.match(text, /launch refused: the session that asked for it has ended/);
        assert.deepEqual(runsOnDisk(), before);
        assert.equal(isHealthTickerActive(), false);
        assert.equal((await h.inspect()).pendingCount, 0);
    });
});

describe("a local spawn in flight across the shutdown", () => {
    test("is refused: no run, no reserved slot, no ticker, no turn", async (t) => {
        const h = harness(t);
        await h.start();
        assert.equal(isHealthTickerActive(), false, "nothing to supervise yet");
        const held = holdPreparation("in flight");
        const pending = h.run("subagent_spawn", selected("in flight"));
        const refused = assert.rejects(pending, /launch refused: the session that asked for it has ended/);
        await held.entered;
        assert.equal((await h.inspect()).pendingCount, 1, "the launch holds a slot while it is prepared");

        await h.shutdown();
        held.release();
        await refused;
        assert.deepEqual(runsOnDisk(), [], "no child record was created");
        assert.deepEqual(registry.listMetas(), []);
        assert.equal(isHealthTickerActive(), false, "the late launch did not arm supervision");
        assert.equal((await h.inspect()).pendingCount, 0, "the reservation was released");
        assert.deepEqual(h.sent, [], "nothing was told to the conversation, let alone a turn started");

        await h.start();
        assert.ok(launchId(await h.run("subagent_spawn", plain("next lifetime"))), "the next lifetime launches normally");
    });
});

describe("a local spawn in flight across the shutdown and a following session_start", () => {
    // The tool call began in the lifetime that ended; the new lifetime must not adopt it.
    test("single: is refused, with no run, no reserved slot, no ticker and no message", async (t) => {
        const h = harness(t);
        await h.start();
        const held = holdPreparation("began before shutdown");
        const pending = h.run("subagent_spawn", selected("began before shutdown"));
        const refused = assert.rejects(pending, /launch refused: the session that asked for it has ended/);
        await held.entered;
        assert.equal((await h.inspect()).pendingCount, 1);

        await h.shutdown();
        await h.start(); // the latch is cleared again: only the epoch says this call is stale
        assert.equal(isHealthTickerActive(), false);
        held.release();
        await refused;
        assert.deepEqual(runsOnDisk(), [], "no child record was created");
        assert.deepEqual(registry.listMetas(), []);
        assert.equal(isHealthTickerActive(), false, "the late launch did not arm supervision");
        assert.equal((await h.inspect()).pendingCount, 0, "the reservation was released");
        assert.deepEqual(h.sent, [], "nothing was told to the conversation");

        assert.ok(launchId(await h.run("subagent_spawn", plain("new lifetime"))), "the new lifetime still launches its own work");
    });

    test("batch: each job is refused and nothing starts", async (t) => {
        const h = harness(t);
        await h.start();
        const held = holdPreparation("batch began before shutdown");
        const pending = h.run("subagent_spawn_batch", { jobs: [selected("batch began before shutdown"), selected("second job")] })
            .catch((error) => error);
        await held.entered;

        await h.shutdown();
        await h.start();
        held.release();
        const outcome = await pending;
        const text = JSON.stringify(outcome?.structuredContent ?? outcome?.content ?? String(outcome?.message ?? outcome));
        assert.match(text, /launch refused: the session that asked for it has ended/);
        assert.deepEqual(runsOnDisk(), [], "no child record was created");
        assert.deepEqual(registry.listMetas(), []);
        assert.equal(isHealthTickerActive(), false);
        assert.equal((await h.inspect()).pendingCount, 0);
        assert.deepEqual(h.sent, []);
    });
});

describe("a remote spawn in flight across the shutdown", () => {
    const hold = () => writeFileSync(join(sshDir, "mux-hold"), "");
    const release = () => rmSync(join(sshDir, "mux-hold"), { force: true });
    const remoteSpawn = (h) => h.run("subagent_spawn", { prompt: "hang until aborted", remote: "t", callback: true });

    async function lateLaunchIsStopped(t, { sessionRestarts }) {
        const h = harness(t);
        await h.start();
        hold();
        const pending = remoteSpawn(h);
        const refused = assert.rejects(pending, /launch refused: the session ended while remote run (sa_\S+) was starting\. The run was stopped\./);
        // The launch is parked on the ssh mux: nothing is recorded yet, so the shutdown sweep cannot see it.
        assert.equal(await waitFor(() => runsOnDisk().length === 1), true, "the launch claimed its run directory");
        assert.deepEqual(registry.listMetas(), []);
        await h.shutdown("reload");
        if (sessionRestarts) await h.start();
        assert.equal(isHealthTickerActive(), false);

        release();
        await refused;
        const [meta] = registry.listMetas();
        assert.ok(meta, "the late launch's record exists so the stop is attributable");
        assert.equal(meta.status, "killed", "the run that started past the sweep was stopped");
        assert.equal(meta.stoppedReason, "shutdown", "and recorded as a shutdown stop");
        assert.equal(typeof meta.stoppedAt, "number");
        assert.equal(meta.supervisionInterruptedAt, undefined, "a confirmed stop leaves no interruption marker");
        // It owes nobody a completion: suppressed by the stop, or already told as a quiet notice
        // when the bridge's exit was finalized first (checked below; never a turn).
        assert.equal(typeof meta.completionCallbackSuppressedAt === "number" || typeof meta.completionCallbackSentAt === "number", true,
            "its completion is settled");
        if (meta.completionCallbackSuppressedAt !== undefined) assert.match(meta.completionCallbackSuppressedReason, /reload/);
        assert.equal(await waitFor(() => !alive(meta.pid)), true, "the local bridge is gone");
        assert.equal(await waitFor(() => remoteLeftovers().every((pid) => !alive(pid))), true, "and so is the remote process");
        assert.equal(isHealthTickerActive(), false, "the late launch did not arm supervision");
        await pause(200);
        assert.deepEqual(triggering(h), [], "no turn");
        // The exit of the bridge the stop just killed can race the stop's own record and tell the
        // conversation about the run; whatever it says is a non-triggering notice, never a turn.
        assert.ok(h.sent.filter((entry) => String(entry.message.content).includes(meta.id)).every((entry) => entry.options?.triggerTurn === false),
            "anything said about the run is non-triggering");
        if (registry.readMeta(meta.id).completionCallbackSentAt !== undefined) {
            assert.equal(h.sent.filter((entry) => String(entry.message.content).includes(meta.id)).length, 1, "told once, quietly");
        }
        return h;
    }

    test("the late launch is stopped, records the shutdown, arms nothing and starts no turn", async (t) => {
        await lateLaunchIsStopped(t, { sessionRestarts: false });
    });

    test("a session_start before the launch resolves does not adopt it: it belongs to the ended lifetime", async (t) => {
        const h = await lateLaunchIsStopped(t, { sessionRestarts: true });
        assert.ok(launchId(await h.run("subagent_spawn", plain("new lifetime local"))), "the new lifetime still launches its own work");
    });

    test("a bridge exit that finalizes the run before the stop records killed starts no turn, even with the latch cleared and the same session id", async (t) => {
        const h = harness(t);
        await h.start();
        hold();
        const outcome = remoteSpawn(h).then(() => undefined, (error) => error);
        assert.equal(await waitFor(() => runsOnDisk().length === 1), true, "the launch claimed its run directory");
        await h.shutdown("reload");
        await h.start(); // the latch is cleared again and the session id is the same
        assert.equal(isHealthTickerActive(), false);

        const seen = {};
        setShutdownStopForTests({
            remoteStopAsync: async (remote) => {
                const result = await stopRemoteProcessAsync(remote);
                const [meta] = registry.listMetas();
                seen.markerBeforeStop = registry.readMeta(meta.id).supervisionInterruptedAt;
                // Hold the stop's own bookkeeping until the bridge's exit has been finalized.
                seen.exitRecord = await waitFor(() => {
                    const current = registry.readMeta(meta.id);
                    return current.status !== "running" ? current : undefined;
                });
                return result;
            },
        }, 20_000);
        t.after(() => setShutdownStopForTests(undefined));
        release();
        const error = await outcome;
        assert.ok(error, "the launch is refused");
        assert.equal(typeof seen.markerBeforeStop, "number", "the run was marked as belonging to the ended lifetime before the stop");
        assert.ok(seen.exitRecord, "the bridge exit finalized the run before the stop bookkeeping");

        await pause(400); // longer than the batcher's flush window
        assert.deepEqual(triggering(h), [], "no turn");
        const [meta] = registry.listMetas();
        const about = h.sent.filter((entry) => String(entry.message.content).includes(meta.id));
        assert.ok(about.length <= 1, "at most one notice about the run");
        assert.ok(about.every((entry) => entry.options?.triggerTurn === false), "and it is non-triggering");
        assert.equal(meta.status, "killed", "the verified stop still ends the run it was stopping");
        assert.equal(meta.stoppedReason, "shutdown");
        assert.equal(meta.exitCode, seen.exitRecord.exitCode, "merged into the record the exit wrote, not written over it");
        assert.equal(meta.completionCallbackPendingAt, seen.exitRecord.completionCallbackPendingAt, "the exit's completion marker survived the stop");
        assert.equal(meta.supervisionInterruptedAt, undefined, "a confirmed outcome leaves no interruption marker");
        const owed = meta.completionCallbackSentAt !== undefined || meta.completionCallbackSuppressedAt !== undefined;
        assert.equal(owed, true, "its completion is settled (told quietly or suppressed), not left pending for a later turn");
    });
});
