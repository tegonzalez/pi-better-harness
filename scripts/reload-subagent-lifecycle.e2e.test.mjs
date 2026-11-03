/**
 * A real `/reload` stops the session's in-flight subagent children and never
 * starts a turn because of it.
 *
 * Detached children would otherwise outlive their session and keep spending
 * with nobody left to supervise, bound or stop them. A real Pi AgentSession
 * loads the subagents extension from its package entry file, the way `pi -e`
 * does, and `session.reload()` is the same call Pi's `/reload` command makes:
 * session_shutdown, a fresh extension load (jiti with no module cache, so no
 * in-memory state survives), then session_start. The journeys prove:
 * 1. a child alive at the reload is stopped (process gone), its record says
 *    `killed` with `stoppedReason: "shutdown"`, no completion is delivered and
 *    the model is never asked anything because of it;
 * 2. a run whose exit observer is gone (its record says supervision was
 *    interrupted, e.g. a stop that could not be confirmed) is finalized from
 *    the child's own coherent log by the reloaded session instead of being
 *    reported `lost`.
 *
 * `pi` on PATH is a fake child that streams the same NDJSON events a real
 * `pi -p --mode json` child writes and waits for a release marker, so no model
 * request or installed Pi CLI is involved. The offline provider answers
 * callback-triggered turns.
 *
 * // @covers subagent.run-finalization
 * // @covers subagent.completion-callback
 * // @level integration
 */
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test, { after } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
// Stay outside the preload's exit-swept directory so failed cleanup can retain fixtures.
const fixtureRoot = process.env.PI_SCRIPTS_TEST_MACHINE_TMPDIR ?? realpathSync(tmpdir());
const fixtures = realpathSync(mkdtempSync(join(fixtureRoot, "pi-reload-subagent-")));
const dir = (name) => { const path = join(fixtures, name); mkdirSync(path, { recursive: true }); return path; };
const tmp = dir("tmp");
const agentDir = dir("agent");
const fakeBin = dir("fake-bin");
const release = join(fixtures, "child-release");

// Everything the extensions persist lives under TMPDIR; set it before any product
// module computes a registry path.
process.env.TMPDIR = tmp;
process.env.TMP = tmp;
process.env.TEMP = tmp;
process.env.PI_CODING_AGENT_DIR = agentDir;

// Fake `pi` child: one assistant message, wait for the release marker, then a
// coherent terminal event (agent_end) and exit 0.
const FAKE_CHILD = [
  "#!/bin/sh",
  "printf '%s\\n' '{\"type\":\"message_end\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"reload-survives answer\"}]}}'",
  `while [ ! -f '${release}' ]; do sleep 0.05; done`,
  "printf '%s\\n' '{\"type\":\"agent_end\",\"messages\":[{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"reload-survives answer\"}]}]}'",
  "exit 0",
  "",
].join("\n");
writeFileSync(join(fakeBin, "pi"), FAKE_CHILD);
chmodSync(join(fakeBin, "pi"), 0o755);

const originalPath = process.env.PATH ?? "";
after(() => {
  process.env.PATH = originalPath;
  rmSync(fixtures, { recursive: true, force: true });
});

const { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager } =
  await import("@earendil-works/pi-coding-agent");
const { createAssistantMessageEventStream, InMemoryCredentialStore } = await import("@earendil-works/pi-ai");
// The test's own view of the persisted state: separate module instances from the
// ones the session loads, sharing only the disk.
const registry = await import("../packages/pi-better-subagents/registry.ts");

const EXTENSIONS = [join(repoRoot, "packages/pi-better-subagents/index.ts")];
const delay = (ms) => new Promise((done) => setTimeout(done, ms));

async function waitFor(what, fn, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await delay(50);
  }
}

function childAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === "EPERM"; }
}

/** A real Pi session over the subagents extension; `reload()` is what `/reload` runs. */
async function openSession(project) {
  const settingsManager = SettingsManager.inMemory({
    retry: { enabled: false }, compaction: { enabled: false }, cacheWarming: { enabled: false },
  });
  const requests = [];
  const cost = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
  const provider = {
    baseUrl: "https://example.invalid", apiKey: "offline-fixture", api: "openai-completions",
    models: [{ id: "offline", name: "Offline fixture", input: ["text"], reasoning: false,
      contextWindow: 128_000, maxTokens: 1024, cost }],
    streamSimple(model, context) {
      requests.push(JSON.stringify(context.messages));
      const stream = createAssistantMessageEventStream();
      const response = { role: "assistant", content: [{ type: "text", text: "Completion received." }],
        api: model.api, provider: model.provider, model: model.id, stopReason: "stop", timestamp: Date.now(),
        usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { ...cost, total: 0 } } };
      stream.push({ type: "done", reason: "stop", message: response });
      stream.end(response);
      return stream;
    },
  };
  const resourceLoader = new DefaultResourceLoader({
    cwd: project, agentDir, settingsManager, additionalExtensionPaths: EXTENSIONS,
    noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true,
    extensionFactories: [{ name: "reload-subagent-provider", factory(pi) {
      pi.registerProvider("reload-subagent", provider);
    } }],
  });
  await resourceLoader.reload();
  assert.deepEqual(resourceLoader.getExtensions().errors, []);
  const modelRuntime = await ModelRuntime.create({
    credentials: new InMemoryCredentialStore(), refreshOnCreate: false,
    modelsPath: join(agentDir, "models.json"),
    modelsStorePath: join(agentDir, "models-store.json"),
  });
  modelRuntime.registerProvider("reload-subagent", provider);
  const { session } = await createAgentSession({
    cwd: project, agentDir, resourceLoader, modelRuntime, settingsManager,
    model: modelRuntime.getModel("reload-subagent", "offline"),
    sessionManager: SessionManager.inMemory(project), noTools: "builtin",
  });
  const sent = [];
  const errors = [];
  const sendCustomMessage = session.sendCustomMessage.bind(session);
  session.sendCustomMessage = (message, options) => {
    sent.push({ ...message, options });
    return sendCustomMessage(message, options);
  };
  return {
    session,
    sent,
    requests,
    errors,
    sessionId: session.sessionManager.getSessionId(),
    start: () => session.bindExtensions({ onError: (error) => errors.push(error) }),
    // Tools are looked up per call: after a reload they belong to the new extension instances.
    async call(name, params) {
      const tool = session.agent.state.tools.find((candidate) => candidate.name === name);
      assert.ok(tool, `${name} is registered`);
      const result = await tool.execute(`call-${name}-${Date.now()}`, params, new AbortController().signal);
      return result.content.map((part) => part.text ?? "").join("\n");
    },
    completions: (id) => sent.filter((m) => m.customType === "background-completion-batch" && String(m.content).includes(id)),
    notices: (id) => sent.filter((m) => m.customType === "subagent-restart-notice" && String(m.content).includes(id)),
  };
}

test("a real /reload stops a live subagent child and delivers nothing that could start a turn", async () => {
  process.env.PATH = `${fakeBin}:${originalPath}`;
  process.env.PI_BETTER_CALLBACK_BATCH_MS = "50";
  const project = dir("live-project");
  const host = await openSession(project);
  let pid;
  try {
    await host.start();
    const spawned = await host.call("subagent_spawn", { prompt: "reload stops", clean: true, sandbox: false, cwd: project });
    const id = spawned.match(/id=(\S+)/)?.[1];
    pid = Number(spawned.match(/\(pid (\d+)\)/)?.[1]);
    assert.ok(id && pid);
    await waitFor("the child to start writing", () => {
      try { return readFileSync(registry.logPathFor(id), "utf8").includes("reload-survives answer"); } catch { return false; }
    });
    assert.equal(registry.readMeta(id).status, "running");
    const requestsBefore = host.requests.length;

    await host.session.reload();

    await waitFor("the child to be stopped", () => !childAlive(pid));
    const stopped = registry.readMeta(id);
    assert.equal(stopped.status, "killed", "reload stops delegated work instead of leaving it detached");
    assert.equal(stopped.stoppedReason, "shutdown");
    assert.equal(stopped.supervisionInterruptedAt, undefined, "a confirmed stop leaves no interruption marker");
    assert.equal(typeof stopped.completionCallbackSuppressedAt, "number", "a run stopped by shutdown owes no completion");

    // Nothing is delivered for it, in this session or after another reload, and no turn runs.
    await delay(600);
    await host.session.reload();
    await delay(600);
    assert.deepEqual(host.sent.filter((m) => String(m.content).includes(id)), [], "no completion or notice is delivered");
    assert.equal(host.requests.length, requestsBefore, "the model was never asked anything because of the stop");
    assert.equal(registry.readMeta(id).status, "killed");
    assert.match(await host.call("subagent_result", { id }), /killed|stopped/i);
    assert.deepEqual(host.errors, []);
  } finally {
    try { writeFileSync(release, ""); } catch { /* ignore */ }
    if (pid) { try { process.kill(-pid, "SIGKILL"); } catch { /* gone */ } }
    host.session.dispose();
    process.env.PATH = originalPath;
  }
});

test("a real /reload finalizes interrupted work from the child's own log, not as lost", async () => {
  process.env.PATH = `${fakeBin}:${originalPath}`;
  process.env.PI_BETTER_CALLBACK_BATCH_MS = "50";
  const project = dir("adopted-project");
  const host = await openSession(project);
  // PID above the platform maximum: guaranteed dead, never a live group.
  const deadPid = 4_194_304;
  const seededId = "sa_reload_adopted_1";
  try {
    mkdirSync(registry.runDir(seededId), { recursive: true });
    writeFileSync(registry.logPathFor(seededId), [
      { type: "message_end", message: { role: "assistant", content: [{ type: "text", text: "recovered-after-reload answer" }] } },
      { type: "agent_end", messages: [{ role: "assistant", content: [{ type: "text", text: "recovered-after-reload answer" }] }] },
    ].map((event) => JSON.stringify(event)).join("\n") + "\n");
    // A run whose owning instance is gone: it was recorded as interrupted while
    // its child was still alive, and the child has since exited.
    registry.writeMeta({
      id: seededId, name: seededId, status: "running", pid: deadPid, pgid: deadPid,
      spawnPid: process.pid, cwd: project, promptPreview: "recovered after reload",
      startedAt: Date.now() - 5_000, logPath: registry.logPathFor(seededId), sessionId: `${seededId}-child`,
      callbackOrigin: { cwd: project, sessionId: host.sessionId },
      supervisionInterruptedAt: Date.now() - 2_000, supervisionInterruptedReason: "reload",
    });

    const requestsBefore = host.requests.length;
    await host.start();
    await host.session.reload();

    // session_start recovers the interrupted record from its coherent log instead
    // of leaving it for health reconciliation to call `lost`.
    await waitFor("the recovered terminal record", () => {
      const meta = registry.readMeta(seededId);
      return meta?.status === "completed" ? meta : undefined;
    });
    const done = registry.readMeta(seededId);
    assert.equal(done.lifecycleClassification, "complete");
    assert.equal(done.exitCode, null, "no exit code is invented after the observer is gone");
    // The run was started by a session that has since shut down: its completion is a
    // notice appended to the conversation, never a turn-triggering batch.
    await waitFor("the recovered completion notice", () => host.notices(seededId).length > 0);
    await delay(300);
    assert.equal(host.notices(seededId).length, 1);
    assert.equal(host.notices(seededId)[0].options?.triggerTurn, false, "the notice starts no turn");
    assert.deepEqual(host.completions(seededId), [], "nothing goes through the turn-triggering batch");
    assert.equal(host.requests.length, requestsBefore, "the model was never asked anything because of the notice");
    assert.match(await host.call("subagent_result", { id: seededId }), /recovered-after-reload answer/);
    assert.ok(existsSync(registry.logPathFor(seededId)));
    assert.deepEqual(host.errors, []);
  } finally {
    host.session.dispose();
    rmSync(registry.runDir(seededId), { recursive: true, force: true });
    process.env.PATH = originalPath;
  }
});
