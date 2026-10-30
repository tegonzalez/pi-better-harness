import { describe, it } from "node:test";
import assert from "node:assert/strict";
import repeatGuard, {
    callSignature,
    createRepeatGuard,
    errorSignature,
    normalizeErrorText,
    POLL_LIMIT,
    REPEAT_LIMIT,
    SIGNATURE_LIMIT,
    SIGNATURE_EXEMPT_TOOLS,
} from "../repeat-guard.ts";

function fakePi() {
    const handlers = {};
    return {
        handlers,
        on(name, fn) { (handlers[name] ??= []).push(fn); },
        emit(name, event, ctx) { return handlers[name]?.map((fn) => fn(event, ctx)).at(-1); },
    };
}

function fakeCtx() {
    const ctx = { notes: [], aborts: 0 };
    ctx.ui = { notify: (m) => ctx.notes.push(m) };
    ctx.abort = () => { ctx.aborts += 1; };
    return ctx;
}

const spawnArgs = { prompt: "x", agent: "", role: "developer" };
const text = (t) => [{ type: "text", text: t }];
const failed = (input, error = "agent is blank.") => ({ toolName: "subagent_spawn", input, isError: true, content: text(error) });
const ok = (toolName, input, result) => ({ toolName, input, isError: false, content: text(result) });
const pollArgs = {};
const pollResult = "Background activity: 0 running, 0 queued.";

/**
 * Pi's agent loop ends after a tool batch only when every result terminates
 * (pi-agent-core `shouldTerminateToolBatch`); this replays that rule over the
 * guard's tool_call decisions. Blocked calls never reach tool_result.
 * `parallel` mirrors executeToolCallsParallel: every tool_call runs before any result.
 */
function runBatch(pi, ctx, calls, { parallel = true } = {}) {
    const outcomes = [];
    const finish = (call, decision) => {
        if (decision?.block) return { call, blocked: decision, terminate: decision.terminate === true };
        const result = pi.emit("tool_result", { toolName: call.toolName, input: call.input, isError: call.isError, content: text(call.result) }, ctx);
        return { call, result, terminate: false };
    };
    if (parallel) {
        const decisions = calls.map((call) => pi.emit("tool_call", { toolName: call.toolName, input: call.input }, ctx));
        calls.forEach((call, i) => outcomes.push(finish(call, decisions[i])));
    } else {
        for (const call of calls) outcomes.push(finish(call, pi.emit("tool_call", { toolName: call.toolName, input: call.input }, ctx)));
    }
    pi.emit("turn_end", { toolResults: outcomes.map(() => ({})) }, ctx);
    return { outcomes, terminate: outcomes.length > 0 && outcomes.every((o) => o.terminate) };
}

describe("repeat guard", () => {
    it("signature ignores key order but not values", () => {
        assert.equal(callSignature("t", { a: 1, b: 2 }), callSignature("t", { b: 2, a: 1 }));
        assert.notEqual(callSignature("t", { a: 1 }), callSignature("t", { a: 2 }));
        assert.notEqual(callSignature("t", { a: 1 }), callSignature("u", { a: 1 }));
    });

    it("error signature normalizes quoted values, ids, paths and numbers but keeps the tool and the message", () => {
        assert.equal(
            errorSignature("subagent_spawn", 'Unknown agent "foo". 3 of 3 slots busy in /tmp/runs/7f3a9c2e1b (run 550e8400-e29b-41d4-a716-446655440000)'),
            errorSignature("subagent_spawn", "Unknown agent 'bar-baz'. 4 of 4 slots busy in ./other/dir (run 123e4567-e89b-12d3-a456-426614174000)"),
        );
        assert.notEqual(errorSignature("subagent_spawn", "agent is blank."), errorSignature("subagent_spawn", "role is blank."));
        assert.notEqual(errorSignature("a", "boom"), errorSignature("b", "boom"));
        assert.equal(normalizeErrorText("  run   7  in /x/y  "), "run <n> in <path>");
    });

    it("escalates on the 3rd identical failure and then blocks every call with terminate", () => {
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: false });
        assert.equal(REPEAT_LIMIT, 3);
        for (let i = 1; i <= 2; i++) {
            assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: spawnArgs }, ctx), undefined);
            assert.equal(pi.emit("tool_result", failed(spawnArgs), ctx), undefined);
        }
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: { ...spawnArgs } }, ctx), undefined);
        const third = pi.emit("tool_result", failed(spawnArgs), ctx);
        assert.equal(third.isError, true);
        assert.equal(third.content[0].text, "agent is blank.");
        const notice = third.content.at(-1).text;
        assert.match(notice, /REPEATED FAILURE: subagent_spawn failed 3 times.*identical arguments/s);
        assert.match(notice, /Exact error: "agent is blank\."/);
        assert.match(notice, /Stop now and ask the user: report the exact error, what you tried/);
        assert.equal(ctx.notes.length, 1);
        assert.match(ctx.notes[0], /subagent_spawn failed 3× with the same error/);
        const blocked = pi.emit("tool_call", { toolName: "subagent_spawn", input: { role: "developer", agent: "", prompt: "x" } }, ctx);
        assert.equal(blocked.block, true);
        assert.equal(blocked.terminate, true);
        assert.match(blocked.reason, /REPEATED FAILURE/);
        // Unlike the first version, a call with other arguments is blocked as well.
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: { prompt: "x", role: "developer" } }, ctx).terminate, true);
        // New user input clears the escalation.
        pi.emit("input", { text: "try again" });
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: spawnArgs }, ctx), undefined);
    });

    it("(a) varied arguments with the same error escalate at SIGNATURE_LIMIT (5)", () => {
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: false });
        assert.equal(SIGNATURE_LIMIT, 5);
        for (let i = 1; i <= 4; i++) {
            assert.equal(pi.emit("tool_result", failed({ prompt: `p${i}`, agent: `x${i}` }, `Unknown agent "x${i}" (run ${i})`), ctx), undefined);
        }
        const fifth = pi.emit("tool_result", failed({ prompt: "p5", agent: "x5", thinking: "high" }, 'Unknown agent "x5" (run 5)'), ctx);
        assert.ok(fifth, "fifth failure with the same normalized error escalates");
        assert.match(fifth.content.at(-1).text, /failed 5 times with the same error across 5 different argument variants/);
        assert.match(fifth.content.at(-1).text, /Exact error: "Unknown agent \\"x5\\" \(run 5\)"/);
        assert.equal(ctx.notes.length, 1);
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: { prompt: "d" } }, ctx).terminate, true);
    });

    it("different errors of one tool, or a success of that tool in between, do not escalate", () => {
        const g = createRepeatGuard(3);
        assert.equal(g.record("subagent_spawn", { a: 1 }, true, text("agent is blank.")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 2 }, true, text("role is blank.")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 3 }, true, text("prompt is required.")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 4 }, true, text("agent is blank.")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 5 }, false, text("launched")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 6 }, true, text("agent is blank.")), undefined);
        assert.equal(g.check("bash", {}), undefined);
        // Another tool's success does not clear subagent_spawn failures.
        assert.equal(g.record("bash", { command: "ls" }, false, text("ok")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 7 }, true, text("agent is blank.")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 8 }, true, text("agent is blank.")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 9 }, true, text("agent is blank.")), undefined);
        assert.equal(g.record("subagent_spawn", { a: 10 }, true, text("agent is blank."))?.kind, "failure");
    });

    it("exploration tools: varied no-match searches and missing files never escalate; identical calls still do", () => {
        const g = createRepeatGuard();
        for (let i = 0; i < 10; i++) {
            assert.equal(g.record("bash", { command: `rg term${i}` }, true, text("(no output)\n\nCommand exited with code 1")), undefined);
            assert.equal(g.record("read", { path: `src/f${i}.ts` }, true, text(`ENOENT: no such file or directory, access '/w/src/f${i}.ts'`)), undefined);
        }
        assert.ok(SIGNATURE_EXEMPT_TOOLS.has("bash"));
        assert.equal(g.record("bash", { command: "make" }, true, text("boom")), undefined);
        assert.equal(g.record("bash", { command: "make" }, true, text("boom")), undefined);
        assert.equal(g.record("bash", { command: "make" }, true, text("boom"))?.kind, "failure");
    });

    it("(b) after escalation a different tool later in the same batch is blocked and terminating", () => {
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: false });
        pi.emit("tool_result", failed(spawnArgs), ctx);
        pi.emit("tool_result", failed(spawnArgs), ctx);
        // Sequential batch: the escalating failure, then a poll and a read.
        const batch = runBatch(pi, ctx, [
            { toolName: "subagent_spawn", input: spawnArgs, isError: true, result: "agent is blank." },
            { toolName: "get_background_activity", input: pollArgs, isError: false, result: pollResult },
            { toolName: "read", input: { path: "a.ts" }, isError: false, result: "x" },
        ], { parallel: false });
        assert.match(batch.outcomes[0].result.content.at(-1).text, /REPEATED FAILURE/);
        for (const later of batch.outcomes.slice(1)) {
            assert.equal(later.blocked.block, true);
            assert.equal(later.blocked.terminate, true);
            assert.match(later.blocked.reason, /every further tool call \(any tool\) is blocked/i);
        }
        // The escalating result itself cannot terminate, so the model gets one turn to report…
        assert.equal(batch.terminate, false);
        assert.equal(ctx.aborts, 0);
        // …and any tool call in it ends the loop: every result of that batch terminates.
        const next = runBatch(pi, ctx, [
            { toolName: "get_background_activity", input: pollArgs },
            { toolName: "bash", input: { command: "echo hi" } },
        ]);
        assert.equal(next.terminate, true);
        assert.equal(ctx.aborts, 0);
    });

    it("aborts when blocking cannot end the loop", () => {
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: false });
        for (let i = 0; i < 3; i++) pi.emit("tool_result", failed(spawnArgs), ctx);
        pi.emit("turn_end", { toolResults: [{}] }, ctx); // escalation turn: model may still report
        assert.equal(ctx.aborts, 0);
        // A post-escalation batch with a result the guard never saw (unknown tool / invalid args).
        pi.emit("tool_call", { toolName: "subagent_spawn", input: spawnArgs }, ctx);
        pi.emit("turn_end", { toolResults: [{}, {}] }, ctx);
        assert.equal(ctx.aborts, 1);
        // A runtime that ignores terminate (or a queued follow-up) starts another turn.
        pi.emit("tool_call", { toolName: "bash", input: {} }, ctx);
        pi.emit("turn_end", { toolResults: [{}] }, ctx);
        assert.equal(ctx.aborts, 1);
        pi.emit("turn_start", {}, ctx);
        assert.equal(ctx.aborts, 2);
        // The loop ending clears the turn bookkeeping; new input clears the escalation.
        pi.emit("agent_end", {}, ctx);
        pi.emit("turn_start", {}, ctx);
        assert.equal(ctx.aborts, 2);
    });

    it("(c) identical successful results 5 times in a row escalate", () => {
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: false });
        assert.equal(POLL_LIMIT, 5);
        for (let i = 1; i < POLL_LIMIT; i++) {
            assert.equal(pi.emit("tool_result", ok("get_background_activity", { b: 1, a: 2 }, pollResult), ctx), undefined);
        }
        const fifth = pi.emit("tool_result", ok("get_background_activity", { a: 2, b: 1 }, pollResult), ctx);
        assert.equal(fifth.content[0].text, pollResult);
        assert.match(fifth.content.at(-1).text, /NO PROGRESS: get_background_activity returned the same result 5 times in a row/);
        assert.match(fifth.content.at(-1).text, /Stop now and ask the user: report what you were waiting for/);
        assert.equal(fifth.isError, undefined, "the poll result itself stays a success");
        assert.equal(ctx.notes.length, 1);
        assert.match(ctx.notes[0], /returned the same result 5× in a row/);
        assert.equal(pi.emit("tool_call", { toolName: "read", input: { path: "x" } }, ctx).terminate, true);
    });

    it("a changed result, or new progress elsewhere, restarts the poll streak", () => {
        const g = createRepeatGuard(3, 5);
        for (let i = 0; i < 4; i++) assert.equal(g.record("poll", {}, false, text("same")), undefined);
        assert.equal(g.record("poll", {}, false, text("changed")), undefined);
        for (let i = 0; i < 3; i++) assert.equal(g.record("poll", {}, false, text("changed")), undefined);
        assert.equal(g.record("edit", { path: "a" }, false, text("edited")), undefined); // progress
        for (let i = 0; i < 4; i++) assert.equal(g.record("poll", {}, false, text("changed")), undefined);
        assert.equal(g.record("poll", {}, false, text("changed"))?.kind, "poll");
        // Two alternating no-progress polls still escalate.
        const h = createRepeatGuard(3, 5);
        let hit;
        for (let i = 0; i < 10 && !hit; i++) hit = h.record(i % 2 ? "b" : "a", {}, false, text("same"));
        assert.equal(hit?.kind, "poll");
    });

    it("(d) user input resets failures, polls and the escalation", () => {
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: false });
        pi.emit("tool_result", failed({ a: 1 }), ctx);
        pi.emit("tool_result", failed({ a: 2 }), ctx);
        for (let i = 0; i < 4; i++) pi.emit("tool_result", ok("poll", {}, "same"), ctx);
        pi.emit("input", { text: "keep going", source: "interactive" });
        // Counts restarted: neither the 3rd failure nor the 5th poll escalates.
        assert.equal(pi.emit("tool_result", failed({ a: 3 }), ctx), undefined);
        assert.equal(pi.emit("tool_result", ok("poll", {}, "same"), ctx), undefined);
        for (let a = 4; a <= 6; a++) pi.emit("tool_result", failed({ a }), ctx);
        assert.ok(pi.emit("tool_result", failed({ a: 7 }), ctx));
        assert.equal(pi.emit("tool_call", { toolName: "poll", input: {} }, ctx).block, true);
        pi.emit("input", { text: "the agent name is developer" });
        assert.equal(pi.emit("tool_call", { toolName: "poll", input: {} }, ctx), undefined);
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: { a: 5 } }, ctx), undefined);
    });

    it("(e) incident replay: varied failing spawns paired with an identical poll end the turn", () => {
        // Session 01a18443: every assistant message paired a rejected subagent_spawn
        // (arguments varied; 173 variants in 1493 failures) with a successful
        // get_background_activity poll returning the same text (830 polls).
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: false });
        const spawnError = (n) => `Cannot launch subagent: role "${["developer", "dev", "role.developer"][n % 3]}" requires agent; got "" at /tmp/pi-runs/run-${1000 + n}`;
        let turns = 0;
        let ended = false;
        for (let n = 0; n < 50 && !ended; n++) {
            pi.emit("turn_start", {}, ctx);
            turns += 1;
            const batch = runBatch(pi, ctx, [
                { toolName: "subagent_spawn", input: { prompt: `task ${n}`, role: ["developer", "dev", "role.developer"][n % 3], agent: "" }, isError: true, result: spawnError(n) },
                { toolName: "get_background_activity", input: pollArgs, isError: false, result: pollResult },
            ]);
            ended = batch.terminate;
        }
        assert.equal(ended, true, "the agent loop stops");
        // Turns 1–4 fail; turn 5 escalates (model still gets one reply); turn 6 is fully blocked.
        assert.equal(turns, 6);
        assert.equal(ctx.notes.length, 1);
        assert.match(ctx.notes[0], /subagent_spawn failed 5× with the same error/);
        assert.equal(ctx.aborts, 0, "terminate alone ended the loop");
    });

    it("child escalation names the parent agent", () => {
        const pi = fakePi();
        const ctx = fakeCtx();
        repeatGuard(pi, { child: true });
        let last;
        for (let i = 0; i < SIGNATURE_LIMIT; i++) last = pi.emit("tool_result", failed({ prompt: `v${i}` }), ctx);
        assert.match(last.content.at(-1).text, /return to the parent agent/);
        assert.match(last.content.at(-1).text, /blocked until the parent agent replies/);
        assert.equal(ctx.notes.length, 0, "children do not notify the UI");
        assert.equal(pi.emit("tool_call", { toolName: "bash", input: {} }, ctx).terminate, true);
    });

    it("a success of the same call resets its failure count", () => {
        const g = createRepeatGuard(3);
        g.record("bash", { command: "x" }, true);
        g.record("bash", { command: "x" }, true);
        g.record("bash", { command: "x" }, false);
        assert.equal(g.record("bash", { command: "x" }, true), undefined);
        assert.equal(g.check("bash", { command: "x" }), undefined);
    });

    it("ignores nested tool calls made by other tools", () => {
        const pi = fakePi();
        repeatGuard(pi, { child: false });
        for (let i = 0; i < 5; i++) assert.equal(pi.emit("tool_result", { ...failed(spawnArgs), parentToolCallId: "p" }), undefined);
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: spawnArgs }), undefined);
    });
});
