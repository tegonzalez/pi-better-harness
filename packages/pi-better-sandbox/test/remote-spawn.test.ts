/**
 * A remote spawn is network use: refused while the parent's Network access is Off.
 * @level unit
 */
import assert from "node:assert/strict";
import test from "node:test";

import { REMOTE_SPAWN_REFUSAL, spawnUsesRemote } from "../remote-spawn.ts";

const map = (value: Record<string, string> | undefined | "unreadable") => () => value;

test("explicit remote, resume and remoteAgents-mapped agents count as remote; plain local spawns do not", () => {
    const none = map(undefined);
    assert.equal(spawnUsesRemote("subagent_spawn", { prompt: "x" }, none), false);
    assert.equal(spawnUsesRemote("subagent_spawn", { prompt: "x", agent: "agent.local" }, map({ "agent.far": "box" })), false);
    assert.equal(spawnUsesRemote("subagent_spawn", { remote: "box" }, none), true);
    assert.equal(spawnUsesRemote("subagent_spawn", { resume: "run-1" }, none), true);
    assert.equal(spawnUsesRemote("subagent_spawn", { agent: "agent.far" }, map({ "agent.far": "box" })), true);
    assert.equal(spawnUsesRemote("bash", { remote: "box" }, none), false, "only the spawn tools are covered here");
});

test("batch jobs inherit the shared agent/remote and any remote job makes the call remote", () => {
    const far = map({ "agent.far": "box" });
    assert.equal(spawnUsesRemote("subagent_spawn_batch", { jobs: [{ prompt: "a" }, { prompt: "b" }] }, far), false);
    assert.equal(spawnUsesRemote("subagent_spawn_batch", { jobs: [{ prompt: "a" }, { prompt: "b", remote: "box" }] }, far), true);
    assert.equal(spawnUsesRemote("subagent_spawn_batch", { remote: "box", jobs: [{ prompt: "a" }] }, far), true);
    assert.equal(spawnUsesRemote("subagent_spawn_batch", { agent: "agent.far", jobs: [{ prompt: "a" }] }, far), true);
    assert.equal(spawnUsesRemote("subagent_spawn_batch", { agent: "agent.far", jobs: [{ prompt: "a", agent: "agent.near" }] }, far), false);
    assert.equal(spawnUsesRemote("subagent_spawn_batch", { jobs: [{ prompt: "a", resume: "run-1" }] }, far), true);
});

test("unreadable settings fail closed for a named agent only", () => {
    assert.equal(spawnUsesRemote("subagent_spawn", { agent: "agent.x" }, map("unreadable")), true);
    assert.equal(spawnUsesRemote("subagent_spawn", { prompt: "x" }, map("unreadable")), false);
    assert.match(REMOTE_SPAWN_REFUSAL, /Network access is Off/);
});
