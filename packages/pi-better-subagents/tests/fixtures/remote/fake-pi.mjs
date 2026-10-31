// Fake remote `pi --mode rpc` for unit tests. Behaviour is selected by the prompt text:
//   contains "hang"    -> keeps running until aborted (or killed)
//   contains "persist" -> additionally ignores stdin EOF
//   contains "stubborn" -> acknowledges abort but keeps running (only a kill ends it)
//   contains "silent"  -> accepts the prompt and then stays quiet (no events at all) until killed
//   contains "wait"    -> finishes only after a steer / follow_up arrives
//   contains "grandchild" -> additionally starts a detached (own process group) sleeper, pid in $FAKE_GRANDCHILD_FILE
// Sandbox launch audit entry (get_entries), selected by FAKE_PI_SANDBOX: unset/"active" = active entry for
// $FAKE_SANDBOX_PROFILE; "none" = no entry; "inactive" = active:false; "wrong" = other profile;
// "stale" = only an old (previous process) active entry; "nohash" = active without hashes.
// Otherwise it answers and settles. Records argv/env/commands under FAKE_PI_LOG.
import { appendFileSync } from "node:fs";
import { spawn } from "node:child_process";
const startedIso = new Date().toISOString();
function sandboxEntries() {
  const kind = process.env.FAKE_PI_SANDBOX ?? "active";
  const entry = (data, timestamp = startedIso, id = "e1") => ({ type: "custom", id, parentId: null, timestamp, customType: "pi-better-sandbox-read-confinement", data });
  const base = { version: 1, active: true, profile: process.env.FAKE_PI_ENTRY_PROFILE ?? process.env.FAKE_SANDBOX_PROFILE, policyHash: process.env.FAKE_PI_POLICY_HASH ?? "policy-hash-1", planHash: "plan-hash-1" };
  if (kind === "none") return [];
  if (kind === "inactive") return [entry({ ...base, active: false })];
  if (kind === "wrong") return [entry({ ...base, profile: "some-other-profile" })];
  if (kind === "stale") return [entry(base, "2000-01-01T00:00:00.000Z", "old")];
  if (kind === "nohash") return [entry({ active: true, profile: base.profile })];
  return [entry(base, "2000-01-01T00:00:00.000Z", "old"), entry(base)];
}
const log = (kind, value) => process.env.FAKE_PI_LOG && appendFileSync(process.env.FAKE_PI_LOG, `${JSON.stringify({ kind, value })}\n`);
log("argv", process.argv.slice(2));
log("env", { PROFILE: process.env.FAKE_SANDBOX_PROFILE, EXTRA: process.env.FAKE_EXTRA, cwd: process.cwd(), AGENT_DIR: process.env.PI_CODING_AGENT_DIR });
const out = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
let mode = "";
let running = false;
let steers = 0;
function assistant(text) {
  return { role: "assistant", content: [{ type: "text", text }], usage: { input: 10, output: 5, cacheRead: 2, cost: { total: 0.001 } } };
}
function finish(text, aborted = false) {
  out({ type: "message_end", message: assistant(text) });
  out({ type: "agent_end", messages: [assistant(text)], willRetry: false });
  out({ type: "agent_settled", aborted });
  running = false;
}
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line) continue;
    const cmd = JSON.parse(line);
    log("cmd", cmd);
    const ok = (data) => out({ id: cmd.id, type: "response", command: cmd.type, success: true, ...(data ? { data } : {}) });
    if (cmd.type === "prompt") {
      mode = cmd.message;
      if (mode.includes("grandchild") && process.env.FAKE_GRANDCHILD_FILE) {
        // Own process group (job control), same session: what a pi bash child looks like.
        spawn("bash", ["-c", 'set -m; sleep 1000 & echo $! > "$FAKE_GRANDCHILD_FILE"'], { stdio: "ignore" }).unref();
      }
      log("prompt-received", true);
      ok({ disposition: "started" });
      running = true;
      if (mode.includes("silent")) continue;
      out({ type: "agent_start" });
      if (mode.includes("hang") || mode.includes("wait") || mode.includes("grandchild")) { out({ type: "message_end", message: assistant("working") }); continue; }
      setTimeout(() => finish("remote done"), 50);
    } else if (cmd.type === "steer" || cmd.type === "follow_up") {
      steers += 1;
      ok({ disposition: "queued" });
      out({ type: "message_end", message: { role: "user", content: cmd.message } });
      if (mode.includes("wait")) setTimeout(() => finish(`steered: ${cmd.message}`), 50);
    } else if (cmd.type === "abort") {
      log("aborted", true);
      ok();
      if (running && !mode.includes("stubborn")) finish("aborted", true);
    } else if (cmd.type === "get_entries") {
      ok({ entries: sandboxEntries(), leafId: "e1" });
    } else if (cmd.type === "get_session_stats") {
      ok({ sessionId: "x", tokens: { input: 111, output: 22, cacheRead: 333, cacheWrite: 4, total: 470 }, cost: 0.5 });
    } else ok();
  }
});
process.stdin.on("end", () => { if (!mode.includes("persist")) process.exit(0); });
if (process.env.FAKE_PI_KEEPALIVE !== "0") setInterval(() => {}, 1000);
