/**
 * What a run may tell the conversation, by session lifetime (real extension, index.ts).
 *
 * Policy: nothing that belongs to an ended session lifetime may start a model turn;
 * a completion that arrives during the CURRENT lifetime still uses the triggering
 * batcher. Covered here:
 *
 *  - a completion arriving during the live session goes through the batcher as a
 *    triggering follow-up (never as a restart notice);
 *  - the deadline and stuck notices for a run that outlived its session (its record
 *    carries the shutdown interruption marker) are non-triggering, prefixed so the
 *    model is told not to continue, written as delivered only after the host
 *    accepted them, and never duplicated while a handoff is in flight; a refused
 *    handoff is retried by the next supervision tick. A run without the marker is
 *    the control: its notices still wake the parent;
 *  - a shutdown that cannot list this session's runs says so (a warning), since
 *    children may then still be running unstopped.
 *
 * Real children come from a PATH-injected fake `pi`; only setInterval is mocked so
 * the 15 s health tick is driven by hand. Host SDK packages are stubbed at the
 * module boundary.
 *
 * // @covers subagent.timing
 * // @covers subagent.completion-callback
 * // @level integration
 */
import { describe, it, after, mock } from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
import { mkdirSync, mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hostLikeSession } from "./host-session.mjs";

register(new URL("./pi_host_stub_hooks.mjs", import.meta.url));

const HERMETIC_TMPDIR = mkdtempSync(join(tmpdir(), "subagent-session-notices-"));
process.env.TMPDIR = HERMETIC_TMPDIR;

const { default: betterSubagents } = await import("../index.ts");
const { getCallbackBatcher } = await import("../shared-callback-batcher.ts");
const { readMeta, writeMeta, runDir } = await import("../registry.ts");
const { killProcessTree } = await import("../spawn.ts");

const HEALTH_TICK_MS = 15_000;
const QUIET = "(from a subagent run whose session has ended; this notice does not ask you to continue) ";

const binDir = mkdtempSync(join(tmpdir(), "fake-pi-notices-"));
const fakePiPath = join(binDir, "pi");
const IDLE_SCRIPT = "#!/bin/sh\necho \"{\\\"type\\\":\\\"fake_launch\\\"}\"\necho \"$@\"\nsleep 300\n";
// Finishes (a coherent agent_end, exit 0) once the test drops `done` next to its steer directory.
const WAIT_SCRIPT = "#!/bin/sh\nd=$(dirname \"$PI_SUBAGENT_STEER_DIR\")\necho launched --extension\nwhile [ ! -f \"$d/done\" ]; do sleep 0.05; done\necho '{\"type\":\"agent_end\"}'\nexit 0\n";
function writeFakePi(script) {
    writeFileSync(fakePiPath, script);
    chmodSync(fakePiPath, 0o755);
}
writeFakePi(IDLE_SCRIPT);
const originalPath = process.env.PATH ?? "";
process.env.PATH = `${binDir}:${originalPath}`;

const liveRuns = [];

function makeHarness(options = {}) {
    const tools = new Map();
    const handlers = new Map();
    const sent = [];
    const notes = [];
    const pi = {
        registerTool: (def) => tools.set(def.name, def),
        on: (event, fn) => handlers.set(event, fn),
        sendMessage: (message, sendOptions) => {
            sent.push({ message, options: sendOptions });
            return options.sendMessage?.(message, sendOptions, sent.length);
        },
    };
    const ctx = {
        cwd: tmpdir(),
        hasUI: false,
        isIdle: () => true,
        ui: { notify: (msg, level) => notes.push({ msg, level }), setWidget: () => {} },
        model: undefined,
        sessionManager: { getSessionId: () => options.sessionId ?? "notices-session" },
    };
    betterSubagents(hostLikeSession(pi, handlers));
    return {
        pi, tools, handlers, sent, notes, ctx,
        start: () => handlers.get("session_start")({ reason: "startup" }, ctx),
        shutdown: (reason = "quit") => handlers.get("session_shutdown")({ reason }, ctx),
    };
}

async function waitFor(fn, { timeoutMs = 5000, intervalMs = 20 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const value = await fn();
        if (value) return value;
        if (Date.now() > deadline) return undefined;
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const settle = () => new Promise((resolve) => setImmediate(resolve));
async function tick() {
    mock.timers.tick(HEALTH_TICK_MS);
    await settle();
}

async function spawnRun(h, overrides = {}) {
    const res = await h.tools.get("subagent_spawn").execute(
        "tc", { prompt: "notice test task", clean: true, sandbox: false, cwd: tmpdir(), ...overrides },
        undefined, undefined, h.ctx,
    );
    const out = res.content[0].text;
    const id = out.match(/id=(\S+)/)[1];
    const pid = Number(out.match(/\(pid (\d+)\)/)[1]);
    liveRuns.push({ id, pid });
    await waitFor(() => { try { return readMeta(id).status === "running"; } catch { return false; } });
    await sleep(100); // the fake child writes its launch lines before any test appends to the log
    return { id, pid };
}

async function reap({ id, pid }) {
    killProcessTree(pid, "SIGKILL");
    await waitFor(() => {
        const m = readMeta(id);
        return m && m.status !== "running" && m.status !== "orphaned" ? m : undefined;
    }, { timeoutMs: 2000 });
    rmSync(runDir(id), { recursive: true, force: true });
}

async function withFakeClock(fn) {
    mock.timers.enable({ apis: ["setInterval"] });
    try { await fn(); } finally { mock.timers.reset(); }
}

/** Mark a run as one that outlived its session: the record a shutdown leaves when it could not confirm the stop. */
function markOutlived(id) {
    writeMeta({ ...readMeta(id), supervisionInterruptedAt: Date.now() - 1_000, supervisionInterruptedReason: "reload" });
}

const about = (h, kind, id) => h.sent.filter((entry) => entry.message.customType === `subagent-${kind}` && String(entry.message.content).includes(id));

after(() => {
    process.env.PATH = originalPath;
    for (const { id, pid } of liveRuns) {
        killProcessTree(pid, "SIGKILL");
        rmSync(runDir(id), { recursive: true, force: true });
    }
    rmSync(binDir, { recursive: true, force: true });
    rmSync(HERMETIC_TMPDIR, { recursive: true, force: true });
});

describe("a completion arriving during the live session lifetime", () => {
    it("still uses the triggering batcher", async () => {
        await withFakeClock(async () => {
            writeFakePi(WAIT_SCRIPT);
            const h = makeHarness();
            let run;
            try {
                await h.start();
                run = await spawnRun(h);
                writeFileSync(join(runDir(run.id), "done"), "");
                assert.equal(await waitFor(() => readMeta(run.id)?.status === "completed"), true, "the run finishes inside the session");
                const batcher = getCallbackBatcher(h.pi);
                assert.equal(batcher.pendingCount(), 1, "its completion is queued on the batcher, not told quietly");
                assert.equal(await batcher.flush(), true);
                const batches = h.sent.filter((entry) => entry.message.customType === "background-completion-batch");
                assert.equal(batches.length, 1);
                assert.match(batches[0].message.content, new RegExp(run.id));
                assert.deepEqual(batches[0].options, { deliverAs: "followUp", triggerTurn: true }, "a completion of the live session may take a turn");
                assert.deepEqual(h.sent.filter((entry) => entry.message.customType === "subagent-restart-notice"), []);
                assert.ok(readMeta(run.id).completionCallbackSentAt > 0);
            } finally {
                if (run) await reap(run);
                await h.shutdown();
                writeFakePi(IDLE_SCRIPT);
            }
        });
    });
});

describe("notices for a run that outlived its session", () => {
    const stuckParams = { deadline_minutes: 0, max_minutes: 0, stuck_minutes: 0.002 };
    const deadlineParams = { deadline_minutes: 0.001, grace_minutes: 10, max_minutes: 0, stuck_minutes: 0 };
    /** Drive health ticks until the notice of `kind` for `id` has been handed to the host `count` times. */
    async function tickUntilNotice(h, kind, id, count = 1) {
        const deadline = Date.now() + 5000;
        while (about(h, kind, id).length < count && Date.now() < deadline) {
            await tick();
            await sleep(30);
        }
        return about(h, kind, id);
    }

    for (const [kind, params, text] of [["deadline", deadlineParams, /soft deadline/], ["stuck", stuckParams, /looks stuck: no progress/]]) {
        it(`the ${kind} notice is non-triggering, marked as not asking to continue, and delivered once`, async () => {
            await withFakeClock(async () => {
                const h = makeHarness();
                let quiet; let live;
                try {
                    await h.start();
                    quiet = await spawnRun(h, { name: `quiet-${kind}`, ...params });
                    live = await spawnRun(h, { name: `live-${kind}`, ...params });
                    markOutlived(quiet.id);

                    const notices = await tickUntilNotice(h, kind, quiet.id);
                    assert.equal(notices.length, 1);
                    assert.deepEqual(notices[0].options, { triggerTurn: false }, "it can only be appended to the conversation");
                    assert.ok(notices[0].message.content.startsWith(QUIET), "the model is told this does not ask it to continue");
                    assert.match(notices[0].message.content, text);
                    const handledAt = kind === "deadline" ? readMeta(quiet.id).timing.deadlineWakeSentAt : readMeta(quiet.id).timing.stuckWakeSentAt;
                    assert.ok(handledAt > 0, "the receipt is written once the host took it");

                    await tick();
                    await tick();
                    assert.equal(about(h, kind, quiet.id).length, 1, "one notice per run, not one per tick");

                    // Control: the same run in the live session still wakes the parent.
                    const control = await tickUntilNotice(h, kind, live.id);
                    assert.equal(control.length, 1);
                    assert.equal(control[0].options.triggerTurn, true, "a live run's notice keeps its wake");
                    assert.ok(!control[0].message.content.startsWith(QUIET));
                } finally {
                    if (quiet) await reap(quiet);
                    if (live) await reap(live);
                    await h.shutdown();
                }
            });
        });
    }

    it("never sends a second copy while the first handoff is in flight, then settles once it is accepted", async () => {
        await withFakeClock(async () => {
            let accept;
            const accepted = new Promise((resolve) => { accept = resolve; });
            const h = makeHarness({ sendMessage: (message) => message.customType === "subagent-deadline" ? accepted : undefined });
            let run;
            try {
                await h.start();
                run = await spawnRun(h, { name: "in-flight", ...deadlineParams });
                markOutlived(run.id);
                assert.equal((await tickUntilNotice(h, "deadline", run.id)).length, 1);
                for (let i = 0; i < 4; i++) { await tick(); await sleep(20); }
                assert.equal(about(h, "deadline", run.id).length, 1, "the in-flight handoff blocks a duplicate");
                assert.equal(readMeta(run.id).timing.deadlineWakeSentAt, undefined, "no receipt before the host accepts it");

                accept();
                assert.equal(await waitFor(() => readMeta(run.id).timing.deadlineWakeSentAt > 0), true, "accepted: receipted");
                for (let i = 0; i < 3; i++) { await tick(); await sleep(20); }
                assert.equal(about(h, "deadline", run.id).length, 1, "and never resent once receipted");
            } finally {
                accept?.();
                if (run) await reap(run);
                await h.shutdown();
            }
        });
    });

    it("retries a refused handoff on the next tick without ever starting a turn", async () => {
        await withFakeClock(async () => {
            const h = makeHarness({ sendMessage: (message, _options, count) => {
                if (message.customType === "subagent-deadline" && count === 1) return Promise.reject(new Error("host refused"));
                return undefined;
            } });
            let run;
            try {
                await h.start();
                run = await spawnRun(h, { name: "refused", ...deadlineParams });
                markOutlived(run.id);
                assert.equal((await tickUntilNotice(h, "deadline", run.id)).length, 1);
                await sleep(50);
                assert.equal(readMeta(run.id).timing.deadlineWakeSentAt, undefined, "a refused handoff is not receipted");
                assert.equal((await tickUntilNotice(h, "deadline", run.id, 2)).length, 2, "the next tick retries it");
                assert.equal(await waitFor(() => readMeta(run.id).timing.deadlineWakeSentAt > 0), true);
                assert.ok(about(h, "deadline", run.id).every((entry) => entry.options.triggerTurn === false));
            } finally {
                if (run) await reap(run);
                await h.shutdown();
            }
        });
    });
});

describe("a shutdown that cannot list this session's runs", () => {
    it("warns that runs may still be running instead of silently reporting nothing", async () => {
        const h = makeHarness({ sessionId: "unlistable" });
        const saved = process.env.TMPDIR;
        const broken = mkdtempSync(join(HERMETIC_TMPDIR, "unlistable-"));
        // The per-parent index cannot be created: its parent path is a regular file.
        mkdirSync(join(broken, "pi-better-subagents"));
        writeFileSync(join(broken, "pi-better-subagents", "by-parent"), "not a directory");
        try {
            await h.start();
            process.env.TMPDIR = broken;
            await h.shutdown("quit");
        } finally {
            process.env.TMPDIR = saved;
        }
        const warning = h.notes.find((note) => /Could not list this session's subagent runs/.test(note.msg));
        assert.ok(warning, "the human is told");
        assert.equal(warning.level, "warning");
        assert.match(warning.msg, /subagent_list/);
        assert.match(warning.msg, /subagent_stop/);
        assert.deepEqual(h.sent.filter((entry) => entry.options?.triggerTurn === true), []);
    });
});
