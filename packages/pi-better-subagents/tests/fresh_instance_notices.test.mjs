/**
 * Only the current lifetime of THIS extension instance may start a model turn.
 *
 * Pi loads extensions with `moduleCache: false`, so a reload, `/new`, `/resume` or
 * fork gives the replacing session a FRESH module instance whose in-memory state is
 * empty: it knows nothing about the runs the old instance launched, stopped or told
 * the conversation about. These tests load a second, cache-busted copy of index.ts
 * (`index.ts?instance=...`), the situation a real reload creates, and prove the
 * allowlist contract (`runsOfCurrentLifetime`):
 *
 *  - the record a late remote launch leaves when it is stopped as `lost` or `failed`
 *    (no interruption marker survives a confirmed outcome), an already-lost run whose
 *    notice was never sent, and a completion still pending from the old instance are
 *    each told to the new conversation exactly once and never start a turn
 *    (`triggerTurn: false`), however many session_starts, ticks and further fresh
 *    instances follow;
 *  - control: a run launched in the new lifetime still wakes the parent for its
 *    completion, for its lost notice and for its deadline notice.
 *
 * Real children come from a PATH-injected fake `pi`; only setInterval is mocked so the
 * 15 s health tick is driven by hand. Host SDK packages are stubbed at the module
 * boundary.
 *
 * // @covers subagent.completion-callback
 * // @covers subagent.health-callback
 * // @covers subagent.timing
 * // @level integration
 * // @fails-without-fix subagent.completion-callback
 */
import { describe, it, after, mock } from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

register(new URL("./pi_host_stub_hooks.mjs", import.meta.url));

const HERMETIC_TMPDIR = mkdtempSync(join(tmpdir(), "subagent-fresh-instance-"));
process.env.TMPDIR = HERMETIC_TMPDIR;

// Independent module instances of the extension, like successive reloads: they share only the disk.
const oldInstance = (await import("../index.ts")).default;
const newInstance = (await import("../index.ts?instance=reloaded")).default;
const thirdInstance = (await import("../index.ts?instance=third")).default;
const { getCallbackBatcher } = await import("../shared-callback-batcher.ts");
const { readMeta, writeMeta, nextRunId, runDir } = await import("../registry.ts");
const { killProcessTree } = await import("../spawn.ts");
const { observeFailures } = await import("../shared-failure-observations.ts");
const { failurePath } = await import("../failures.ts");

assert.notEqual(oldInstance, newInstance, "the cache-busted import is a distinct module instance");

const HEALTH_TICK_MS = 15_000;
const DEAD_PID = 4194304;
const SESSION = "fresh-instance-session";

const binDir = mkdtempSync(join(tmpdir(), "fake-pi-fresh-"));
const fakePiPath = join(binDir, "pi");
// Finishes (a coherent agent_end, exit 0) once the test drops `done` next to its steer directory.
const WAIT_SCRIPT = "#!/bin/sh\nd=$(dirname \"$PI_SUBAGENT_STEER_DIR\")\necho launched --extension\nwhile [ ! -f \"$d/done\" ]; do sleep 0.05; done\necho '{\"type\":\"agent_end\"}'\nexit 0\n";
writeFileSync(fakePiPath, WAIT_SCRIPT);
chmodSync(fakePiPath, 0o755);
const originalPath = process.env.PATH ?? "";
process.env.PATH = `${binDir}:${originalPath}`;

const liveRuns = [];
const dirOnly = [];

function makeHarness(extension, { idle = () => true } = {}) {
    const tools = new Map();
    const handlers = new Map();
    const sent = [];
    const notes = [];
    const pi = {
        registerTool: (def) => tools.set(def.name, def),
        on: (event, fn) => handlers.set(event, fn),
        sendMessage: (message, options) => { sent.push({ message, options }); },
    };
    const ctx = {
        cwd: tmpdir(),
        hasUI: false,
        isIdle: () => idle(),
        ui: { notify: (msg, level) => notes.push({ msg, level }), setWidget: () => {} },
        model: undefined,
        sessionManager: { getSessionId: () => SESSION },
    };
    extension(pi);
    return {
        pi, tools, handlers, sent, notes, ctx,
        start: () => handlers.get("session_start")({ reason: "startup" }, ctx),
        shutdown: (reason = "reload") => handlers.get("session_shutdown")({ reason }, ctx),
    };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const settle = () => new Promise((resolve) => setImmediate(resolve));
async function waitFor(fn, { timeoutMs = 5000, intervalMs = 20 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const value = await fn();
        if (value) return value;
        if (Date.now() > deadline) return undefined;
        await sleep(intervalMs);
    }
}
async function tick() {
    mock.timers.tick(HEALTH_TICK_MS);
    await settle();
}
async function withFakeClock(fn) {
    mock.timers.enable({ apis: ["setInterval"] });
    try { await fn(); } finally { mock.timers.reset(); }
}

async function spawnRun(h, overrides = {}) {
    const res = await h.tools.get("subagent_spawn").execute(
        "tc", { prompt: "fresh instance task", clean: true, sandbox: false, cwd: tmpdir(), ...overrides },
        undefined, undefined, h.ctx,
    );
    const out = res.content[0].text;
    const id = out.match(/id=(\S+)/)[1];
    const pid = Number(out.match(/\(pid (\d+)\)/)[1]);
    liveRuns.push({ id, pid });
    await waitFor(() => readMeta(id)?.status === "running");
    await sleep(100); // the fake child writes its launch line before a test touches the run
    return { id, pid };
}

const finish = (run) => writeFileSync(join(runDir(run.id), "done"), "");
const aboutRun = (h, id) => h.sent.filter((entry) => String(entry.message.content).includes(id));

/** A record the old instance left behind: owned by this process, no interruption marker, nothing told yet. */
function leftover(overrides) {
    const id = nextRunId();
    dirOnly.push(id);
    mkdirSync(runDir(id), { recursive: true });
    writeFileSync(join(runDir(id), "output.log"), "leftover\n");
    writeMeta({
        id, pid: DEAD_PID, pgid: DEAD_PID, pidStartTime: "gone-token", spawnPid: process.pid, cwd: tmpdir(), promptPreview: "late",
        startedAt: Date.now() - 120_000, endedAt: Date.now() - 60_000, logPath: join(runDir(id), "output.log"), sessionId: id,
        callbackOrigin: { cwd: tmpdir(), sessionId: SESSION }, callback: true, ...overrides,
    });
    return id;
}

const remoteBlock = {
    target: "t", host: "example-alias", remoteDir: "~/.pi-better-subagents/runs/x", sshArgv: ["ssh", "example-alias"], login: false,
    abortDonePath: join(tmpdir(), "no-abort-marker"), abortWaitMs: 0, termGraceSeconds: 1, stopScript: "true", cwd: "~/work",
};

after(() => {
    process.env.PATH = originalPath;
    for (const { id, pid } of liveRuns) {
        killProcessTree(pid, "SIGKILL");
        rmSync(runDir(id), { recursive: true, force: true });
    }
    for (const id of dirOnly) rmSync(runDir(id), { recursive: true, force: true });
    rmSync(binDir, { recursive: true, force: true });
    rmSync(HERMETIC_TMPDIR, { recursive: true, force: true });
});

describe("a fresh extension instance (a reload) with runs it did not launch", () => {
    it("tells a late remote launch stopped as lost or failed, an already-lost run and a pending completion once each, without a turn", async () => {
        await withFakeClock(async () => {
            // The old instance launches a run that finishes while the caller is busy (completion pending), then reloads.
            const previous = makeHarness(oldInstance, { idle: () => false });
            await previous.start();
            const pendingRun = await spawnRun(previous);
            finish(pendingRun);
            assert.equal(await waitFor(() => readMeta(pendingRun.id)?.status === "completed"), true);
            assert.equal(getCallbackBatcher(previous.pi).pendingCount(), 1, "the completion waits in the OLD instance's batch");
            await previous.shutdown("reload");
            assert.ok(readMeta(pendingRun.id).completionCallbackPendingAt > 0, "the obligation survives on disk");
            assert.equal(readMeta(pendingRun.id).completionCallbackSentAt, undefined);
            assert.deepEqual(previous.sent, [], "the old instance told nobody and woke nobody");

            // What a late remote launch leaves once its stop has been confirmed: no interruption marker
            // survives a confirmed outcome, so the record alone says nothing about which lifetime owns it.
            const lostLate = leftover({ status: "lost", lostAt: Date.now() - 60_000, stoppedReason: "shutdown", stoppedAt: Date.now() - 60_000, remote: remoteBlock });
            const failedLate = leftover({
                status: "failed", failureReason: "bridge exited", exitCode: 1, stoppedReason: "shutdown", stoppedAt: Date.now() - 60_000,
                completionCallbackPendingAt: Date.now() - 60_000, remote: remoteBlock,
            });
            observeFailures(failurePath(failedLate), [{ id: "late-failure", operation: "remote-launch", kind: "failure", summary: "the late launch failed" }], Date.now() - 90_000);
            // A run that was already lost before the reload, its health notice never sent.
            const alreadyLost = leftover({ status: "lost", lostAt: Date.now() - 60_000, orphanedAt: Date.now() - 90_000 });
            const everyone = [pendingRun.id, alreadyLost, lostLate, failedLate];
            for (const id of everyone) {
                assert.equal(readMeta(id).supervisionInterruptedAt, undefined, "no interruption marker: only the allowlist can quiet these");
            }

            // The new instance: a fresh module with empty in-memory state, same session id.
            const next = makeHarness(newInstance);
            await next.start();
            for (let i = 0; i < 4; i++) { await tick(); await sleep(20); }
            await getCallbackBatcher(next.pi).flush();
            await sleep(300); // longer than the batcher's flush window

            assert.deepEqual(next.sent.filter((entry) => entry.options?.triggerTurn !== false), [], "nothing from the old lifetime starts a turn");
            assert.deepEqual(next.sent.filter((entry) => entry.message.customType === "background-completion-batch"), []);
            const told = (id) => aboutRun(next, id);
            assert.equal(told(pendingRun.id).length, 1, "the completion pending from the old instance: once");
            assert.equal(told(pendingRun.id)[0].message.customType, "subagent-restart-notice");
            assert.equal(told(alreadyLost).length, 1, "the already-lost run: once");
            assert.equal(told(alreadyLost)[0].message.customType, "subagent-health");
            assert.equal(told(lostLate).length, 1, "the late launch stopped as lost: once");
            assert.equal(told(lostLate)[0].message.customType, "subagent-health");
            assert.equal(told(failedLate).length, 1, "the late launch stopped as failed: once");
            assert.equal(told(failedLate)[0].message.customType, "subagent-restart-notice");
            for (const id of everyone) assert.deepEqual(told(id)[0].options, { triggerTurn: false }, `${id} only informs`);
            assert.ok(readMeta(alreadyLost).lostCallbackSentAt > 0, "receipted once the host took it");
            assert.ok(readMeta(lostLate).lostCallbackSentAt > 0);
            assert.ok(readMeta(failedLate).completionCallbackSentAt > 0);
            assert.ok(readMeta(pendingRun.id).completionCallbackSentAt > 0);

            // Exactly once: another session_start, more ticks and a THIRD fresh instance add nothing.
            await next.start();
            for (let i = 0; i < 3; i++) { await tick(); await sleep(20); }
            await next.shutdown("reload");
            const third = makeHarness(thirdInstance);
            await third.start();
            for (let i = 0; i < 3; i++) { await tick(); await sleep(20); }
            await sleep(100);
            for (const id of everyone) {
                assert.equal(told(id).length, 1, `${id} is never told twice`);
                assert.deepEqual(aboutRun(third, id), [], `${id} is not re-delivered by a later instance`);
            }
            assert.deepEqual(third.sent.filter((entry) => entry.options?.triggerTurn !== false), []);
            await third.shutdown("quit");
        });
    });

    it("control: a run launched in the new lifetime still wakes the parent for its completion, its lost notice and its deadline", async () => {
        await withFakeClock(async () => {
            const h = makeHarness(newInstance);
            await h.start();
            const completing = await spawnRun(h);
            const losing = await spawnRun(h);
            const overdue = await spawnRun(h, { deadline_minutes: 0.001, grace_minutes: 10, max_minutes: 0, stuck_minutes: 0 });
            try {
                // Completion: through the triggering batcher.
                finish(completing);
                assert.equal(await waitFor(() => readMeta(completing.id)?.status === "completed"), true);
                assert.ok(getCallbackBatcher(h.pi).pendingCount() >= 1, "queued on the batcher, not told quietly");
                assert.equal(await getCallbackBatcher(h.pi).flush(), true);
                const batches = h.sent.filter((entry) => entry.message.customType === "background-completion-batch" && entry.message.content.includes(completing.id));
                assert.equal(batches.length, 1);
                assert.deepEqual(batches[0].options, { deliverAs: "followUp", triggerTurn: true }, "a run of the live lifetime may take a turn");
                assert.deepEqual(h.sent.filter((entry) => entry.message.customType === "subagent-restart-notice" && entry.message.content.includes(completing.id)), []);

                // Lost: its supervision disappears (recorded pid and process group gone).
                writeMeta({ ...readMeta(losing.id), pid: DEAD_PID, pgid: DEAD_PID, pidStartTime: "gone-token", callback: true });
                const wakes = () => ({
                    lost: h.sent.filter((e) => e.message.customType === "subagent-health" && e.message.content.includes(losing.id)),
                    deadline: h.sent.filter((e) => e.message.customType === "subagent-deadline" && e.message.content.includes(overdue.id)),
                });
                const limit = Date.now() + 5000;
                while ((wakes().lost.length < 1 || wakes().deadline.length < 1) && Date.now() < limit) { await tick(); await sleep(30); }
                const { lost, deadline } = wakes();
                assert.equal(lost.length, 1, "one lost notice");
                assert.equal(lost[0].options.triggerTurn, true, "a lost run of the live lifetime keeps its wake");
                assert.equal(lost[0].options.deliverAs, "followUp");
                assert.equal(deadline.length, 1, "one deadline notice");
                assert.equal(deadline[0].options.triggerTurn, true, "a deadline of the live lifetime keeps its wake");
            } finally {
                for (const run of [completing, losing, overdue]) killProcessTree(run.pid, "SIGKILL");
                await h.shutdown("quit");
            }
        });
    });
});
