/**
 * Parent → child steering: the per-run steer queue (steer-queue.ts), the child's
 * delivery extension (child-steer.ts), and the parent's subagent_steer tool and
 * steer surfaces on subagent_list / subagent_output / subagent_result (tools.ts).
 *
 * // @covers subagent.steer
 * // @level unit
 */
import { describe, it, after, mock } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
    STEER_DIR_ENV,
    PARENT_STEER_PREFIX,
    enqueueSteer,
    formatSteerLine,
    formatSteerShort,
    formatUndeliveredSteerNote,
    listSteerRequests,
    readSteerReceipt,
    receiptForId,
    steerQueueStatus,
    steerRevisionFacts,
    writeSteerReceipt,
} from "../steer-queue.ts";
import { completionCallbackFields } from "../callback-fields.ts";
import { emptyFailureState } from "../shared-failure-observations.ts";
import childSteer from "../child-steer.ts";
import { writeMeta, runDir, logPathFor, steerDirFor } from "../registry.ts";
import { subagentListTool, subagentOutputTool, subagentResultTool, subagentSteerTool } from "../tools.ts";

const TypeStub = { Object: (v) => v, String: (v) => v, Number: (v) => v, Boolean: (v) => v, Array: (v) => v, Optional: (v) => v };
const ORIGIN = { cwd: "/tmp", sessionId: "steer-session" };
const SESSION = { getActiveOrigin: () => ORIGIN };
const textOf = (result) => result.content.map((c) => c.text ?? "").join("\n");
const statusCursorOf = (body) => body.match(/\bstatusCursor=(\S+)/)?.[1];

const dirs = [];
function tempDir() {
    const dir = mkdtempSync(join(tmpdir(), "steer-queue-"));
    dirs.push(dir);
    return dir;
}
const runIds = [];
after(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    for (const id of runIds) rmSync(runDir(id), { recursive: true, force: true });
});

let runSeq = 0;
function writeRun({ status = "running", origin = ORIGIN, log = [] } = {}) {
    const id = `sa_steer${Date.now().toString(36)}_${(runSeq++).toString(36)}`;
    runIds.push(id);
    mkdirSync(runDir(id), { recursive: true });
    writeMeta({
        id, name: "worker", status, pid: status === "running" ? process.pid : 0, spawnPid: process.pid, cwd: "/tmp",
        promptPreview: "steer me", startedAt: Date.now() - 1000, ...(status === "running" ? {} : { endedAt: Date.now(), exitCode: 0 }),
        logPath: logPathFor(id), sessionId: id, callbackOrigin: origin,
    });
    writeFileSync(logPathFor(id), log.map((e) => JSON.stringify(e)).join("\n") + (log.length ? "\n" : ""));
    return id;
}

/** A fake child host: records sends, lets the test fire Pi events. */
function fakeChild(dir, { idle = () => false } = {}) {
    const handlers = new Map();
    const sent = [];
    const previous = process.env[STEER_DIR_ENV];
    process.env[STEER_DIR_ENV] = dir;
    try {
        childSteer({ on: (event, fn) => handlers.set(event, fn), sendUserMessage: (text, options) => sent.push({ text, options }) });
    } finally {
        if (previous === undefined) delete process.env[STEER_DIR_ENV];
        else process.env[STEER_DIR_ENV] = previous;
    }
    handlers.get("session_start")({}, { isIdle: idle });
    const enter = (text) => handlers.get("message_end")({ message: { role: "user", content: [{ type: "text", text }] } }, {});
    return { handlers, sent, enter, shutdown: () => handlers.get("session_shutdown")({}, {}) };
}

describe("steer queue files", () => {
    it("keeps requests in queue order, one file each, and never queues an id twice", () => {
        const dir = tempDir();
        enqueueSteer(dir, { id: "a", text: "first", at: 1000 });
        enqueueSteer(dir, { id: "b", text: "second", at: 1000 });
        enqueueSteer(dir, { id: "deadline:sa_x_1", text: "wrap up", kind: "deadline", at: 1000 });
        const again = enqueueSteer(dir, { id: "a", text: "first (retry)", at: 2000 });
        assert.equal(again.text, "first", "an id already queued returns the existing request");
        const requests = listSteerRequests(dir);
        assert.deepEqual(requests.map((r) => r.id), ["a", "b", "deadline:sa_x_1"]);
        assert.deepEqual(requests.map((r) => r.kind), ["parent", "parent", "deadline"]);
        assert.equal(readdirSync(dir).filter((n) => n.endsWith(".tmp")).length, 0, "no temp files left behind");
        assert.equal(readdirSync(dir).length, 3);
        assert.throws(() => enqueueSteer(dir, { id: "c", text: "   " }), /non-empty/);
    });

    it("accounts receipts per request: pending, delivered, last delivery", () => {
        const dir = tempDir();
        assert.deepEqual(steerQueueStatus(join(dir, "missing")).requests, [], "no queue directory is an empty queue");
        const a = enqueueSteer(dir, { id: "a", text: "one" });
        const b = enqueueSteer(dir, { id: "b", text: "two" });
        enqueueSteer(dir, { id: "c", text: "three" });
        writeSteerReceipt(dir, a, 5000);
        writeSteerReceipt(dir, b, 7000);
        const status = steerQueueStatus(dir);
        assert.equal(status.delivered, 2);
        assert.deepEqual(status.pending.map((r) => r.id), ["c"]);
        assert.equal(status.lastDeliveredAt, 7000);
        assert.equal(receiptForId(dir, "b").at, 7000);
        assert.equal(receiptForId(dir, "c"), undefined);
        // A receipt for a different id under the same file name is not a receipt for this request.
        writeFileSync(join(dir, `${listSteerRequests(dir)[2].base}.receipt.json`), JSON.stringify({ id: "zzz", at: 1 }));
        assert.equal(steerQueueStatus(dir).pending.length, 1);

        assert.equal(formatSteerShort(status, true), "steer: 2 delivered, 1 pending");
        assert.equal(formatSteerShort(status, false), "steer: 2 delivered, 1 UNDELIVERED");
        assert.match(formatSteerLine(status, true), /2 delivered \(last 1970-01-01T00:00:07\.000Z\), 1 pending \(c\) — delivered at the child's next turn boundary/);
        assert.match(formatSteerLine(status, false), /2 delivered \(last [^)]+\); 1 NOT delivered — no delivery receipt when the run ended \(c\)\./);
        assert.equal(formatSteerLine(steerQueueStatus(join(dir, "missing")), true), undefined, "never steered: no line");
    });
});

describe("child steer delivery", () => {
    it("delivers every pending request in order, once each, only while the agent is working", () => {
        const dir = tempDir();
        mock.timers.enable({ apis: ["setInterval"] });
        let idle = true;
        try {
            const child = fakeChild(dir, { idle: () => idle });
            mock.timers.tick(2_000);
            assert.equal(child.sent.length, 0, "no request yet");
            enqueueSteer(dir, { id: "r1", text: "first" });
            enqueueSteer(dir, { id: "r2", text: "second" });
            mock.timers.tick(2_000);
            assert.equal(child.sent.length, 0, "an idle child is not prompted");
            idle = false;
            mock.timers.tick(2_000);
            assert.deepEqual(child.sent, [
                { text: "first", options: { deliverAs: "steer" } },
                { text: "second", options: { deliverAs: "steer" } },
            ]);
            mock.timers.tick(2_000);
            mock.timers.tick(2_000);
            assert.equal(child.sent.length, 2, "each request is handed to Pi once");

            const [r1, r2] = listSteerRequests(dir);
            assert.equal(readSteerReceipt(dir, r1), undefined, "queued behind the current tool call is not delivered yet");
            child.handlers.get("message_end")({ message: { role: "assistant", content: [{ type: "text", text: "first" }] } }, {});
            child.enter("unrelated user text");
            assert.equal(readSteerReceipt(dir, r1), undefined);
            const before = Date.now();
            child.enter("first");
            assert.ok(readSteerReceipt(dir, r1).at >= before, "a receipt when the steer enters the conversation");
            assert.equal(readSteerReceipt(dir, r2), undefined, "the second request has its own receipt");
            child.enter("second");
            assert.equal(readSteerReceipt(dir, r2).id, "r2");

            // A later request is picked up at the next turn boundary, without waiting for the poll.
            enqueueSteer(dir, { id: "r3", text: "third" });
            child.handlers.get("turn_end")({}, {});
            assert.deepEqual(child.sent.map((s) => s.text), ["first", "second", "third"]);
            child.shutdown();
        } finally {
            mock.timers.reset();
        }
    });

    it("receipts identical texts in order and never resends a delivered request", () => {
        const dir = tempDir();
        mock.timers.enable({ apis: ["setInterval"] });
        try {
            enqueueSteer(dir, { id: "d1", text: "same" });
            enqueueSteer(dir, { id: "d2", text: "same" });
            const child = fakeChild(dir);
            mock.timers.tick(2_000);
            assert.equal(child.sent.length, 2);
            child.enter("same");
            const status = steerQueueStatus(dir);
            assert.deepEqual([...status.receipts.keys()], ["d1"], "the first identical text receipts the first request");
            assert.deepEqual(status.pending.map((r) => r.id), ["d2"]);
            child.enter("same");
            assert.equal(steerQueueStatus(dir).pending.length, 0);
            child.shutdown();

            // A fresh child process does not resend a request that already has a receipt.
            const next = fakeChild(dir);
            mock.timers.tick(2_000);
            assert.equal(next.sent.length, 0);
            next.shutdown();
        } finally {
            mock.timers.reset();
        }
    });

    it("retries a request Pi refused, keeping order", () => {
        const dir = tempDir();
        mock.timers.enable({ apis: ["setInterval"] });
        try {
            enqueueSteer(dir, { id: "x1", text: "one" });
            enqueueSteer(dir, { id: "x2", text: "two" });
            const handlers = new Map();
            const sent = [];
            let fail = true;
            process.env[STEER_DIR_ENV] = dir;
            try {
                childSteer({ on: (event, fn) => handlers.set(event, fn), sendUserMessage: (text) => { if (fail) throw new Error("busy"); sent.push(text); } });
            } finally {
                delete process.env[STEER_DIR_ENV];
            }
            handlers.get("session_start")({}, { isIdle: () => false });
            mock.timers.tick(2_000);
            assert.deepEqual(sent, []);
            fail = false;
            mock.timers.tick(2_000);
            assert.deepEqual(sent, ["one", "two"]);
            handlers.get("session_shutdown")({}, {});
        } finally {
            mock.timers.reset();
        }
    });
});

describe("subagent_steer tool", () => {
    const tool = subagentSteerTool(TypeStub, SESSION);

    it("queues a framed amendment for its own running child and returns at once with the steer id", async () => {
        const id = writeRun({ log: [{ type: "agent_start" }] });
        const result = await tool.execute("tc", { id, message: "Treat the format requirement as mandatory; drop candidates that fail it." });
        const body = textOf(result);
        assert.equal(result.details.state, "queued");
        assert.match(result.details.steerId, /^st_/);
        assert.match(body, new RegExp(`Queued steer ${result.details.steerId} for ${id}`));
        assert.match(body, /next turn boundary/);
        assert.doesNotMatch(body, /may not be delivered/);
        const [request] = listSteerRequests(steerDirFor(id));
        assert.equal(request.id, result.details.steerId);
        assert.equal(request.text, `${PARENT_STEER_PREFIX}\n\nTreat the format requirement as mandatory; drop candidates that fail it.`);
        assert.equal(request.kind, "parent");
    });

    it("refuses unknown, foreign-session, finished, and empty requests with a reason", async () => {
        await assert.rejects(tool.execute("tc", { id: "sa_nope_1", message: "x" }), /Unknown run id: sa_nope_1/);
        const foreign = writeRun({ origin: { cwd: "/tmp", sessionId: "someone-else" } });
        await assert.rejects(tool.execute("tc", { id: foreign, message: "x" }), /not a run of this session/);
        const done = writeRun({ status: "completed" });
        await assert.rejects(tool.execute("tc", { id: done, message: "x" }), /run is completed \(it has finished\)/);
        const running = writeRun();
        await assert.rejects(tool.execute("tc", { id: running, message: "   " }), /non-empty message/);
        for (const id of [foreign, done, running]) assert.equal(existsSync(steerDirFor(id)), false, `nothing queued for ${id}`);
    });

    it("warns that the steer may not be delivered when the child's agent loop has settled", async () => {
        const id = writeRun({ log: [{ type: "agent_start" }, { type: "agent_end" }, { type: "agent_settled", aborted: false }] });
        const result = await tool.execute("tc", { id, message: "also do Y" });
        assert.equal(result.details.mayNotDeliver, true);
        assert.match(textOf(result), /may not be delivered/);
        assert.equal(listSteerRequests(steerDirFor(id)).length, 1, "still queued, just not promised");
    });
});

describe("steer surfaces", () => {
    it("list, output, and running result show pending and delivered counts and the last delivery", async () => {
        const id = writeRun({ log: [{ type: "agent_start" }] });
        const dir = steerDirFor(id);
        const a = enqueueSteer(dir, { id: "st_a", text: "one" });
        enqueueSteer(dir, { id: "st_b", text: "two" });
        writeSteerReceipt(dir, a, Date.UTC(2026, 0, 2, 3, 4, 5));
        const list = textOf(await subagentListTool(TypeStub, SESSION).execute("tc", { max_bytes: 4096 }));
        assert.match(list, new RegExp(`${id}.*steer: 1 delivered, 1 pending`));
        const output = textOf(await subagentOutputTool(TypeStub, SESSION).execute("tc", { id, max_bytes: 4096 }));
        assert.match(output, /Steer: 1 delivered \(last 2026-01-02T03:04:05\.000Z\), 1 pending \(st_b\)/);
        const result = textOf(await subagentResultTool(TypeStub, SESSION).execute("tc", { id, max_bytes: 8192 }));
        assert.match(result, /still running/);
        assert.match(result, /Steer: 1 delivered .*1 pending \(st_b\)/);
    });

    it("a finished run's result says explicitly when a steer was never delivered", async () => {
        const id = writeRun({ status: "completed", log: [
            { type: "message_end", message: { role: "assistant", content: [{ type: "text", text: "done" }] } },
            { type: "agent_end" },
        ] });
        enqueueSteer(steerDirFor(id), { id: "st_late", text: "too late" });
        const result = textOf(await subagentResultTool(TypeStub, SESSION).execute("tc", { id, max_bytes: 8192 }));
        assert.match(result, /Steer: 0 delivered; 1 NOT delivered — no delivery receipt when the run ended \(st_late\)\./);
        assert.match(result, /st_late/);
        const list = textOf(await subagentListTool(TypeStub, SESSION).execute("tc", { max_bytes: 4096 }));
        assert.match(list, new RegExp(`${id}.*steer: 0 delivered, 1 UNDELIVERED`));
    });

    it("a never-steered run shows no steer line", async () => {
        const id = writeRun({ log: [{ type: "agent_start" }] });
        const output = textOf(await subagentOutputTool(TypeStub, SESSION).execute("tc", { id, max_bytes: 4096 }));
        assert.doesNotMatch(output, /Steer:/);
        assert.equal(readFileSync(logPathFor(id), "utf8").includes("agent_start"), true);
    });
});

describe("steer status cursors", () => {
    // A status cursor answers "unchanged" only when nothing the surface reports has changed;
    // a newly queued steer and a pending -> delivered transition are both changes.
    const surfaces = [
        ["subagent_list", (id, cursor) => subagentListTool(TypeStub, SESSION).execute("tc", { cursor, max_bytes: 4096 })],
        ["subagent_output", (id, cursor) => subagentOutputTool(TypeStub, SESSION).execute("tc", { id, cursor, max_bytes: 4096 })],
        ["subagent_result", (id, cursor) => subagentResultTool(TypeStub, SESSION).execute("tc", { id, cursor, max_bytes: 8192 })],
    ];
    for (const [name, call] of surfaces) {
        it(`${name}: queueing a steer and delivering it each change the status revision`, async () => {
            const id = writeRun({ log: [{ type: "agent_start" }] });
            const dir = steerDirFor(id);
            const first = textOf(await call(id));
            const cursor0 = statusCursorOf(first);
            assert.ok(cursor0, first);
            const same = textOf(await call(id, cursor0));
            assert.match(same, /unchanged/, "control: no change answers unchanged");

            const request = enqueueSteer(dir, { id: "st_new", text: "one" });
            const queued = textOf(await call(id, cursor0));
            assert.doesNotMatch(queued, /unchanged/, "a newly queued steer is a change");
            const cursor1 = statusCursorOf(queued);
            assert.ok(cursor1, queued);
            assert.notEqual(cursor1, cursor0);
            assert.match(textOf(await call(id, cursor1)), /unchanged/);

            writeSteerReceipt(dir, request, Date.now());
            const delivered = textOf(await call(id, cursor1));
            assert.doesNotMatch(delivered, /unchanged/, "pending -> delivered is a change");
            if (name === "subagent_list") assert.match(delivered, new RegExp(`${id}.*steer: 1 delivered`));
            else assert.match(delivered, /Steer: 1 delivered/);
        });
    }

    it("revision facts list each request with its receipt id and time, or null while pending", () => {
        const dir = tempDir();
        assert.deepEqual(steerRevisionFacts(join(dir, "missing")), []);
        const a = enqueueSteer(dir, { id: "a", text: "one" });
        enqueueSteer(dir, { id: "b", text: "two" });
        writeSteerReceipt(dir, a, 4000);
        assert.deepEqual(steerRevisionFacts(dir), [["a", "a", 4000], ["b", null, null]]);
    });
});

describe("completion callback", () => {
    const state = emptyFailureState();
    it("names steers without a delivery receipt at run end", () => {
        const id = writeRun({ status: "completed" });
        const dir = steerDirFor(id);
        const a = enqueueSteer(dir, { id: "st_ok", text: "one" });
        enqueueSteer(dir, { id: "st_late", text: "two" });
        writeSteerReceipt(dir, a, Date.now());
        assert.equal(formatUndeliveredSteerNote(steerQueueStatus(dir)), "1 steer NOT delivered (no delivery receipt): st_late.");
        const fields = completionCallbackFields({ id, status: "completed", startedAt: Date.now() - 1000, cwd: "/tmp" }, state);
        assert.match(fields.decision ?? "", /1 steer NOT delivered \(no delivery receipt\): st_late\./);
    });

    it("adds nothing when every steer was delivered or none was sent", () => {
        const id = writeRun({ status: "completed" });
        assert.equal(completionCallbackFields({ id, status: "completed", startedAt: Date.now() - 1000, cwd: "/tmp" }, state).decision, undefined);
        const dir = steerDirFor(id);
        writeSteerReceipt(dir, enqueueSteer(dir, { id: "st_ok", text: "one" }), Date.now());
        assert.equal(completionCallbackFields({ id, status: "completed", startedAt: Date.now() - 1000, cwd: "/tmp" }, state).decision, undefined);
    });
});
