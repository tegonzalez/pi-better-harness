/**
 * subagent_wait: a headless (`pi -p`) parent collects its children before its
 * one turn ends. See docs/usage.md "Nested agents: waiting in a headless session".
 *
 * Pins:
 * - blocks until every listed run is terminal and returns each run's answer;
 * - a run whose process exited but is not finalized yet is still waited for;
 * - returns early at timeout_minutes (default 30, cap 120, never unlimited), on
 *   abort, when the parent queues a steer/amendment for this process, and when a
 *   listed run raises an attention notice (which becomes part of the result);
 * - only runs returned with a final result are reported as collected (the
 *   index wiring suppresses their completion callback); unfinalized and
 *   running ones are not;
 * - urgent notices route to an active wait once (deduped), never to both;
 * - refuses outside one-shot (print/json) sessions;
 * - registration: inactive by default, granted to allow_nested children.
 *
 * // @covers subagent.wait
 * // @level unit
 */
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { logPathFor, readMeta, runDir, writeMeta } from "../registry.ts";
import { subagentWaitTool, waitTimeoutMs } from "../tools.ts";
import { claimUrgentNotice, registerWaiter, routeUrgentNotice } from "../wait-registry.ts";
import { STEER_DIR_ENV, enqueueSteer, newSteerId } from "../steer-queue.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const TypeStub = { Object: (v) => v, String: (v) => v, Number: (v) => v, Boolean: (v) => v, Array: (v) => v, Optional: (v) => v };

const ids = [];
const procs = [];
after(() => {
    for (const p of procs) { try { p.kill("SIGKILL"); } catch { /* gone */ } }
    for (const id of ids) { try { rmSync(runDir(id), { recursive: true, force: true }); } catch { /* best-effort */ } }
});

let n = 0;
function liveRun(name = "child") {
    const id = `sa_wait_${Date.now()}_${++n}`;
    ids.push(id);
    const proc = spawn("sleep", ["60"], { stdio: "ignore" });
    procs.push(proc);
    writeMeta({
        id, name, status: "running", pid: proc.pid, spawnPid: process.pid, cwd: "/tmp",
        promptPreview: `task ${id}`, startedAt: Date.now(), logPath: logPathFor(id), sessionId: id,
        completionCallbackPendingAt: undefined,
    });
    mkdirSync(runDir(id), { recursive: true });
    writeFileSync(logPathFor(id), "");
    return { id, proc };
}

function finish(run, text) {
    const events = [
        { type: "message_end", message: { role: "assistant", content: [{ type: "text", text }] } },
        { type: "agent_end", messages: [{ role: "assistant", content: [{ type: "text", text }] }] },
    ];
    writeFileSync(logPathFor(run.id), `${events.map((e) => JSON.stringify(e)).join("\n")}\n`);
    run.proc.kill("SIGKILL");
    const meta = readMeta(run.id);
    writeMeta({ ...meta, status: "completed", exitCode: 0, endedAt: Date.now() });
}

const textOf = (r) => r.content.map((c) => c.text ?? "").join("\n");
const headless = { mode: "json", hasUI: false, hasPendingMessages: () => false };

function tool(collected = [], extra = {}) {
    return subagentWaitTool(TypeStub, {}, { onCollected: (id) => collected.push(id), pollMs: 50, exitedGraceMs: 300, ...extra });
}

describe("subagent_wait", () => {
    it("blocks until every listed run finishes and returns each answer", async () => {
        const a = liveRun("a");
        const b = liveRun("b");
        const collected = [];
        setTimeout(() => finish(a, "answer from a"), 200);
        setTimeout(() => finish(b, "answer from b"), 500);
        const started = Date.now();
        const out = textOf(await tool(collected).execute("tc", { ids: [a.id, b.id] }, undefined, undefined, headless));
        assert.ok(Date.now() - started >= 450, "returned before the slower run finished");
        assert.match(out, /answer from a/);
        assert.match(out, /answer from b/);
        assert.deepEqual(collected.sort(), [a.id, b.id].sort());
    });

    it("waits past an exited-but-unfinalized run until it is finalized", async () => {
        const a = liveRun();
        setTimeout(() => a.proc.kill("SIGKILL"), 100); // process gone, meta still "running"
        setTimeout(() => finish(a, "finalized later"), 250); // within the grace period
        const out = textOf(await tool().execute("tc", { ids: [a.id] }, undefined, undefined, headless));
        assert.match(out, /finalized later/);
    });

    it("returns a run that vanished without finalization after the grace period, keeping its callback", async () => {
        const a = liveRun();
        a.proc.kill("SIGKILL");
        const collected = [];
        const started = Date.now();
        const out = textOf(await tool(collected).execute("tc", { ids: [a.id] }, undefined, undefined, headless));
        assert.ok(Date.now() - started >= 250, "returned before the grace period");
        assert.match(out, new RegExp(`${a.id}: process ended but not finalized yet`));
        assert.deepEqual(collected, []); // its completion is still announced when it is finalized
    });

    it("lists an orphaned run without collecting it", async () => {
        const a = liveRun();
        writeMeta({ ...readMeta(a.id), status: "orphaned", orphanedAt: Date.now() });
        const collected = [];
        const out = textOf(await tool(collected).execute("tc", { ids: [a.id] }, undefined, undefined, headless));
        assert.match(out, new RegExp(`${a.id}: orphaned`));
        assert.deepEqual(collected, []);
    });

    it("bounds every wait: default 30 minutes, capped at 120, 0 is not unlimited", () => {
        assert.equal(waitTimeoutMs({}), 30 * 60_000);
        assert.equal(waitTimeoutMs({ timeout_minutes: 500 }), 120 * 60_000);
        assert.equal(waitTimeoutMs({ timeout_minutes: 0 }), 0);
        assert.equal(waitTimeoutMs({ timeout_minutes: -3 }), 0);
    });

    it("returns when pi holds a pending user message (a delivered amendment)", async () => {
        const a = liveRun();
        let pending = false;
        setTimeout(() => { pending = true; }, 150);
        const ctx = { ...headless, hasPendingMessages: () => pending };
        const out = textOf(await tool().execute("tc", { ids: [a.id] }, undefined, undefined, ctx));
        assert.match(out, /amendment/i);
    });

    it("returns early with a listed run's attention notice, which it consumes", async () => {
        const a = liveRun();
        const b = liveRun();
        assert.equal(claimUrgentNotice(b.id, "nobody waits"), false); // no active wait: the batcher delivers it
        let claimed;
        setTimeout(() => { claimed = claimUrgentNotice(b.id, "NOTICE: b is blocked on a permission"); }, 150);
        const started = Date.now();
        const out = textOf(await tool([], { pollMs: 60_000 }).execute("tc", { ids: [a.id, b.id] }, undefined, undefined, headless));
        assert.ok(Date.now() - started < 5_000, "the notice did not wake the wait");
        assert.equal(claimed, true);
        assert.match(out, /NOTICE: b is blocked on a permission/);
        assert.match(out, new RegExp(`${a.id}[^\\n]*running`));
        assert.equal(claimUrgentNotice(a.id, "after the wait"), false);
    });

    it("returns at timeout_minutes with the unfinished runs listed as running", async () => {
        const a = liveRun();
        const b = liveRun();
        setTimeout(() => finish(a, "a done"), 100);
        const collected = [];
        const out = textOf(await tool(collected).execute("tc", { ids: [a.id, b.id], timeout_minutes: 0.01 }, undefined, undefined, headless));
        assert.match(out, /a done/);
        assert.match(out, new RegExp(`${b.id}[^\\n]*running`));
        assert.deepEqual(collected, [a.id]);
    });

    it("returns when the call is aborted", async () => {
        const a = liveRun();
        const ac = new AbortController();
        setTimeout(() => ac.abort(), 150);
        const started = Date.now();
        const out = textOf(await tool([], { pollMs: 60_000 }).execute("tc", { ids: [a.id] }, ac.signal, undefined, headless));
        assert.ok(Date.now() - started < 5_000, "abort did not wake the wait");
        assert.match(out, new RegExp(`${a.id}[^\\n]*running`));
    });

    it("returns when the parent queues an amendment for this process", async () => {
        const a = liveRun();
        const dir = mkdtempSync(join(tmpdir(), "steer-"));
        const previous = process.env[STEER_DIR_ENV];
        process.env[STEER_DIR_ENV] = dir;
        try {
            setTimeout(() => enqueueSteer(dir, { id: newSteerId(), text: "wrap up" }), 150);
            const out = textOf(await tool().execute("tc", { ids: [a.id] }, undefined, undefined, headless));
            assert.match(out, /amendment/i);
            assert.match(out, new RegExp(`${a.id}[^\\n]*running`));
        } finally {
            if (previous === undefined) delete process.env[STEER_DIR_ENV];
            else process.env[STEER_DIR_ENV] = previous;
        }
    });

    it("ignores an amendment that was already pending without a receipt when the wait began", async () => {
        const a = liveRun();
        const dir = mkdtempSync(join(tmpdir(), "steer-"));
        enqueueSteer(dir, { id: newSteerId(), text: "stale, never receipted" });
        const previous = process.env[STEER_DIR_ENV];
        process.env[STEER_DIR_ENV] = dir;
        try {
            const out = textOf(await tool().execute("tc", { ids: [a.id], timeout_minutes: 0.01 }, undefined, undefined, headless));
            assert.match(out, /timeout reached/);
        } finally {
            if (previous === undefined) delete process.env[STEER_DIR_ENV];
            else process.env[STEER_DIR_ENV] = previous;
        }
    });

    it("refuses outside a one-shot session", async () => {
        const a = liveRun();
        for (const mode of ["tui", "rpc"]) {
            await assert.rejects(() => tool().execute("tc", { ids: [a.id] }, undefined, undefined, { ...headless, mode }), /one-shot/);
        }
    });

    it("rejects an unknown run id", async () => {
        await assert.rejects(() => tool().execute("tc", { ids: ["sa_nope_1"] }, undefined, undefined, headless), /sa_nope_1/);
    });

    it("routes an urgent notice to an active wait once, else to the batcher", () => {
        const delivered = [];
        const acked = [];
        const event = (content, extra = {}) => ({ customType: "subagent-failure", id: "sa_route_1", status: "running", content,
            isDelivered: () => false, getSuppressionReason: () => undefined, onDelivered: (at) => acked.push(at), ...extra });
        const deliver = (e) => { delivered.push(e.content); return "batcher"; };
        const fmt = (e) => `TEXT ${e.content}`;
        // nobody waits: the batcher delivers
        assert.equal(routeUrgentNotice("sa_route_1", event("first"), fmt, deliver), "batcher");
        const w = registerWaiter(["sa_route_1"], () => {});
        const w2 = registerWaiter(["sa_route_1"], () => {});
        try {
            assert.equal(routeUrgentNotice("sa_route_1", event("second"), fmt, deliver), true);
            assert.deepEqual(w.notices, ["TEXT second"]);
            assert.deepEqual(w2.notices, ["TEXT second"]); // every wait on the run sees it
            // the same notice again (a later health tick) is acknowledged, not repeated
            assert.equal(routeUrgentNotice("sa_route_1", event("second"), fmt, deliver), true);
            assert.deepEqual(w.notices, ["TEXT second"]);
            assert.equal(acked.length, 2);
            // an already delivered or suppressed notice goes to the batcher's own handling
            assert.equal(routeUrgentNotice("sa_route_1", event("third", { isDelivered: () => true }), fmt, deliver), "batcher");
            // a failing acknowledgement never also delivers it
            assert.equal(routeUrgentNotice("sa_route_1", event("fourth", { onDelivered: () => { throw new Error("x"); } }), fmt, deliver), true);
            assert.deepEqual(delivered, ["first", "third"]);
        } finally {
            w.dispose();
            w2.dispose();
        }
    });

    it("source wiring: in SUBAGENT_TOOLS, registered, urgent notices routed (text check)", () => {
        const src = readFileSync(join(HERE, "..", "index.ts"), "utf-8");
        const list = src.slice(src.indexOf("const SUBAGENT_TOOLS = ["), src.indexOf("];", src.indexOf("const SUBAGENT_TOOLS = [")));
        assert.match(list, /"subagent_wait"/);
        assert.match(src, /registerTool\(subagentWaitTool\(/);
        assert.match(src, /onCollected: \(id\) => markCompletionCallbackSuppressed\(id,/);
        assert.equal((src.match(/void getCallbackBatcher\(pi\)\.deliverUrgent\(/g) ?? []).length, 0, "an urgent path bypasses routing");
        assert.equal((src.match(/void deliverUrgentFor\(pi, meta\.id, \{/g) ?? []).length, 3);
        const def = subagentWaitTool(TypeStub, {}, {});
        assert.equal(def.name, "subagent_wait");
        assert.equal(def.defaultActive, false);
    });
});
