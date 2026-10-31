/**
 * A remote spawn is network use: refused while the parent's Network access is Off.
 * @level unit
 */
import assert from "node:assert/strict";
import test from "node:test";

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { readRemoteAgents, REMOTE_SPAWN_REFUSAL, spawnUsesRemote } from "../remote-spawn.ts";

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

test("the guard resolves remoteAgents like the spawn path: bundled config.json, saved settings, legacy file; no migration", () => {
    const dir = mkdtempSync(join(tmpdir(), "remote-agents-"));
    try {
        const seams = (agentDir: string, bundled: string[]) => ({ agentDir: () => agentDir, bundledPaths: bundled });
        const bundled = join(dir, "bundled.json");
        writeFileSync(bundled, JSON.stringify({ remoteAgents: { "agent.far": "box" }, maxConcurrent: 2 }));
        const empty = join(dir, "a1");
        mkdirSync(empty);
        assert.deepEqual(readRemoteAgents(seams(empty, [bundled])), { "agent.far": "box" }, "bundled config.json");
        assert.equal(spawnUsesRemote("subagent_spawn", { agent: "agent.far" }, () => readRemoteAgents(seams(empty, [bundled]))), true);
        assert.equal(readRemoteAgents(seams(empty, [join(dir, "missing.json")])), undefined);

        const legacyDir = join(dir, "a2");
        mkdirSync(join(legacyDir, "extensions"), { recursive: true });
        writeFileSync(join(legacyDir, "extensions", "pi-better-subagents-config.json"), JSON.stringify({ remoteAgents: { "agent.old": "box" } }));
        assert.deepEqual(readRemoteAgents(seams(legacyDir, [])), { "agent.old": "box" }, "un-migrated legacy file");
        assert.equal(readRemoteAgents(seams(legacyDir, [])) !== "unreadable", true);
        assert.equal(JSON.stringify(readRemoteAgents(seams(legacyDir, []))), JSON.stringify({ "agent.old": "box" }));
        assert.throws(() => readFileSyncOrThrow(join(legacyDir, "settings.json")), "reading must not migrate into settings.json");

        const saved = join(dir, "a3");
        mkdirSync(saved);
        writeFileSync(join(saved, "settings.json"), JSON.stringify({ piBetterHarness: { subagents: { remoteAgents: { "agent.new": "box2" } } } }));
        assert.deepEqual(readRemoteAgents(seams(saved, [bundled])), { "agent.new": "box2" }, "saved settings override the bundled defaults");

        const broken = join(dir, "a4");
        mkdirSync(broken);
        writeFileSync(join(broken, "settings.json"), "{ not json");
        assert.equal(readRemoteAgents(seams(broken, [bundled])), "unreadable", "unreadable saved settings fail closed");
    } finally { rmSync(dir, { recursive: true, force: true }); }
});

function readFileSyncOrThrow(path: string): string {
    return readFileSync(path, "utf8");
}
