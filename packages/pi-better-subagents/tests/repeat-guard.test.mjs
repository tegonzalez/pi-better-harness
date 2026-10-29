import { describe, it } from "node:test";
import assert from "node:assert/strict";
import repeatGuard, { callSignature, createRepeatGuard, REPEAT_LIMIT } from "../repeat-guard.ts";

function fakePi() {
    const handlers = {};
    return {
        handlers,
        on(name, fn) { (handlers[name] ??= []).push(fn); },
        emit(name, event, ctx) { return handlers[name]?.map((fn) => fn(event, ctx)).at(-1); },
    };
}

const spawnArgs = { prompt: "x", agent: "", role: "developer" };
const failed = (input) => ({ toolName: "subagent_spawn", input, isError: true, content: [{ type: "text", text: "agent is blank." }] });

describe("repeat guard", () => {
    it("signature ignores key order but not values", () => {
        assert.equal(callSignature("t", { a: 1, b: 2 }), callSignature("t", { b: 2, a: 1 }));
        assert.notEqual(callSignature("t", { a: 1 }), callSignature("t", { a: 2 }));
        assert.notEqual(callSignature("t", { a: 1 }), callSignature("u", { a: 1 }));
    });

    it("escalates on the 3rd identical failure and blocks the next identical call with terminate", () => {
        const pi = fakePi();
        const notes = [];
        const ctx = { ui: { notify: (m) => notes.push(m) } };
        repeatGuard(pi, { child: false });
        assert.equal(REPEAT_LIMIT, 3);
        for (let i = 1; i <= 2; i++) {
            assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: spawnArgs }), undefined);
            assert.equal(pi.emit("tool_result", failed(spawnArgs), ctx), undefined);
        }
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: { ...spawnArgs } }), undefined);
        const third = pi.emit("tool_result", failed(spawnArgs), ctx);
        assert.equal(third.isError, true);
        assert.match(third.content.at(-1).text, /REPEATED FAILURE: subagent_spawn failed 3 times.*ask the user/s);
        assert.equal(third.content[0].text, "agent is blank.");
        assert.equal(notes.length, 1);
        const blocked = pi.emit("tool_call", { toolName: "subagent_spawn", input: { role: "developer", agent: "", prompt: "x" } });
        assert.equal(blocked.block, true);
        assert.equal(blocked.terminate, true);
        // A different call is not blocked.
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: { prompt: "x", role: "developer" } }), undefined);
        // New user input clears the escalation.
        pi.emit("input", { text: "try again" });
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: spawnArgs }), undefined);
    });

    it("child escalation names the parent agent", () => {
        const pi = fakePi();
        repeatGuard(pi, { child: true });
        let last;
        for (let i = 0; i < 3; i++) last = pi.emit("tool_result", failed(spawnArgs), undefined);
        assert.match(last.content.at(-1).text, /return to the parent agent/);
        assert.equal(pi.emit("tool_call", { toolName: "subagent_spawn", input: spawnArgs }).terminate, true);
    });

    it("a success resets the count; non-consecutive failures still count only identical calls", () => {
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
