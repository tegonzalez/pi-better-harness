/**
 * Local bridge for a remote subagent run.
 *
 * The parent spawns this like any other child (detached, stdout+stderr -> the run log). It owns
 * one ssh channel carrying `pi --mode rpc` on the remote host and translates:
 *   - RPC session events           -> the run log, verbatim (same shapes as `--mode json`)
 *   - steer file (steer.json)      -> RPC `steer` / `follow_up`, then a `.delivered` receipt
 *   - SIGUSR2                      -> RPC `abort`, then an abort-done marker (stop sequence step 1)
 *   - agent_settled                -> RPC `get_session_stats` (logged as `remote_session_stats`), stdin close
 *
 * Start sequence: the environment payload goes to the launch script's stdin (never a command
 * line); the bridge then reads the remote session's entries (RPC get_entries) and requires the
 * sandbox launch audit entry (custom entry, `active: true`, the expected `profile`, `policyHash`,
 * `planHash`) written by THIS pi process. Only then is the prompt sent. Anything else fails closed:
 * an incident is written and the remote session is stopped (verified) before this bridge exits.
 *
 * Remote session termination on a normal stop is NOT done here: `stopRun` does it (and verifies it)
 * after the abort marker, so it also works when this bridge is gone. Configuration comes from a JSON
 * file (argv[2]) written by the parent; this file names no host, path, or model.
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";

const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
const REQUEST_TIMEOUT_MS = 15_000;

let nextId = 0;
const pending = new Map();
let settled = false;
let sawEvent = false;
let stopping = false;
let finished = false;
let stderrTail = "";
const delivered = new Set();
let startedMs;
let failedClosed = false;
// Set just before the prompt is written: from then on the remote may be doing work.
let promptSent = false;
const STARTED_RE = /^pi-remote-started (\d+)$/;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function log(line) {
    process.stdout.write(`${line}\n`);
}

function writeJson(path, value) {
    try {
        writeFileSync(`${path}.tmp`, JSON.stringify(value));
        renameSync(`${path}.tmp`, path);
    } catch { /* best effort */ }
}

const child = spawn(config.argv[0], config.argv.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
// A remote that exits before reading stdin (pi missing, ...) must not crash the bridge with EPIPE.
child.stdin.on("error", () => {});

// Environment payload: stdin only, from a 0600 local file that is removed as soon as it is read.
try {
    const payload = readFileSync(config.envPath, "utf8");
    try { unlinkSync(config.envPath); } catch { /* ignore */ }
    child.stdin.write(payload);
} catch { /* no payload: the launch script then fails closed */ }

function send(command, timeoutMs = REQUEST_TIMEOUT_MS) {
    return new Promise((resolve) => {
        const id = `b${++nextId}`;
        const timer = setTimeout(() => { pending.delete(id); resolve({ success: false, error: `no response to ${command.type}` }); }, timeoutMs);
        pending.set(id, (response) => { clearTimeout(timer); resolve(response); });
        try {
            child.stdin.write(`${JSON.stringify({ ...command, id })}\n`);
        } catch (error) {
            clearTimeout(timer); pending.delete(id);
            resolve({ success: false, error: String(error) });
        }
    });
}

function handleRecord(line) {
    let record;
    try { record = JSON.parse(line); } catch {
        const started = STARTED_RE.exec(line);
        if (started) { startedMs = Number(started[1]); return; }
        log(`[remote stdout] ${line}`);
        return;
    }
    if (record?.type === "response") {
        const resolve = record.id !== undefined ? pending.get(record.id) : undefined;
        if (resolve) { pending.delete(record.id); resolve(record); }
        return;
    }
    if (record?.type === "extension_ui_request") {
        // Headless: dialogs that wait for an answer are cancelled so the remote never blocks on a UI.
        if (["select", "confirm", "input", "editor"].includes(record.method)) {
            try { child.stdin.write(`${JSON.stringify({ type: "extension_ui_response", id: record.id, cancelled: true })}\n`); } catch { /* ignore */ }
        }
        return;
    }
    sawEvent = true;
    log(line);
    if (record?.type === "agent_settled" && !settled) {
        settled = true;
        void finishSettled();
    }
}

let buffer = "";
child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index).replace(/\r$/, "");
        buffer = buffer.slice(index + 1);
        if (line) handleRecord(line);
    }
});
child.stderr.setEncoding("utf8");
child.stderr.on("data", (chunk) => {
    stderrTail = (stderrTail + chunk).slice(-4000);
    for (const line of String(chunk).split("\n")) if (line.trim()) log(`[remote stderr] ${line}`);
});

async function finishSettled() {
    const stats = await send({ type: "get_session_stats" });
    if (stats.success && stats.data) log(JSON.stringify({ type: "remote_session_stats", data: stats.data }));
    writeJson(config.settledPath, { at: Date.now() });
    try { child.stdin.end(); } catch { /* ignore */ }
    setTimeout(() => { if (!finished) child.kill("SIGTERM"); }, 15_000).unref();
}

function classify(code) {
    // After the prompt went out, a dropped channel is "lost" (never finalized): the remote may be working.
    const tail = stderrTail.trim().split("\n").filter(Boolean).pop() ?? "";
    if (code === 255) return sawEvent || promptSent
        ? { kind: "channel-lost", summary: "SSH channel to the remote host was lost while the run was active; the remote process may still be running. Use subagent_stop to terminate it.", code }
        : { kind: "ssh-failed", summary: `SSH connection failed: ${tail || "no detail"}`, code };
    if (code === 127) return { kind: "pi-missing", summary: tail || "remote pi was not found", code };
    if (code === 95) return { kind: "setsid-missing", summary: tail || "setsid is required on the remote host", code };
    if (code === 94) return { kind: "session-missing", summary: tail || "the session to resume was not found on the remote host", code };
    if (code === 96) return { kind: "sandbox-unavailable", summary: tail || "required remote sandbox could not be enabled", code };
    if (code === 97) return { kind: "cwd-missing", summary: tail || "remote working directory not found", code };
    if (code === 99) return { kind: "cwd-denied", summary: tail || "the working folder is outside the target's allowed cwdRoots", code };
    if (code === 98) return { kind: "remote-dir", summary: tail || "remote run directory could not be created", code };
    return { kind: "remote-exit", summary: `remote pi exited with code ${code}${tail ? `: ${tail}` : ""}`, code };
}

child.on("error", (error) => {
    writeJson(config.failurePath, { kind: "ssh-failed", summary: `could not run ssh: ${error.message}`, code: 127 });
    process.exit(127);
});

// `exit` fires when the ssh client itself ends; `close` additionally waits for every holder of its
// pipes. A remote process that outlived a dropped channel must not keep this bridge waiting.
let closed = false;
child.on("exit", (code, signal) => setTimeout(() => onClosed(code, signal), 500).unref());
child.on("close", (code, signal) => onClosed(code, signal));
function onClosed(code, signal) {
    if (closed) return;
    closed = true;
    finished = true;
    if (failedClosed) return;
    if (!settled && !stopping) {
        const exitCode = code ?? 1;
        if ((exitCode !== 0 || !sawEvent) && !existsSync(config.failurePath)) writeJson(config.failurePath, classify(exitCode));
        process.exit(exitCode === 0 ? 1 : exitCode);
    }
    process.exit(signal ? 1 : (code ?? 0));
}

process.on("SIGUSR2", () => {
    if (stopping) return;
    stopping = true;
    void (async () => {
        await send({ type: "abort" }, config.abortTimeoutMs ?? 5_000);
        writeJson(config.abortDonePath, { at: Date.now() });
    })();
});
process.on("SIGTERM", () => process.exit(143));

// Steer file: parent-authored {id, text, mode?: "steer" | "follow_up"}; each id is delivered once.
setInterval(async () => {
    if (stopping || settled) return;
    let request;
    try { request = JSON.parse(readFileSync(config.steerPath, "utf8")); } catch { return; }
    if (typeof request?.id !== "string" || typeof request.text !== "string" || !request.text.trim() || delivered.has(request.id)) return;
    delivered.add(request.id);
    const response = await send({ type: request.mode === "follow_up" ? "follow_up" : "steer", message: request.text });
    if (response.success) writeJson(`${config.steerPath}.delivered`, { id: request.id, at: Date.now() });
    else log(`[bridge] ${request.mode === "follow_up" ? "follow_up" : "steer"} ${request.id} rejected: ${response.error ?? "unknown"}`);
}, 500).unref();

/** Run the remote stop script over ssh and say whether it verified the session gone. */
function runRemoteStop() {
    return new Promise((resolve) => {
        let out = "";
        const stop = spawn(config.stopArgv[0], config.stopArgv.slice(1), { stdio: ["ignore", "pipe", "ignore"] });
        const timer = setTimeout(() => { stop.kill("SIGKILL"); resolve(false); }, 90_000);
        stop.stdout.on("data", (c) => { out += c; });
        stop.on("error", () => { clearTimeout(timer); resolve(false); });
        stop.on("close", () => { clearTimeout(timer); resolve(out.trim().split("\n").pop() === "gone"); });
    });
}

/** Fail closed: incident, verified remote stop, exit. If the stop cannot be verified the run is NOT finalized. */
async function failClosed(kind, summary) {
    if (failedClosed) return;
    failedClosed = true;
    // Assume the remote is still running until the stop is verified: a bridge killed in between
    // must leave the "may still run" marker, not one that reads as surely gone.
    writeJson(config.failurePath, { kind: "remote-unstopped", summary: `${summary}; stopping the remote process (not yet verified). Use subagent_stop if this persists.`, code: 96 });
    log(`[bridge] ${summary}`);
    try { child.stdin.end(); } catch { /* ignore */ }
    const stopped = await runRemoteStop();
    if (stopped) writeJson(config.failurePath, { kind, summary, code: 96 });
    else writeJson(config.failurePath, { kind: "remote-unstopped", summary: `${summary}; the remote process could not be verified stopped. Use subagent_stop.`, code: 96 });
    try { child.kill("SIGTERM"); } catch { /* ignore */ }
    process.exit(96);
}

/**
 * Require the sandbox launch audit entry of THIS pi process: entries older than the remote's own
 * start stamp (a resumed session carries earlier processes' entries) never count.
 */
async function verifySandbox() {
    const want = config.sandbox;
    const deadline = Date.now() + want.timeoutMs;
    let reason = "the remote did not report a sandbox launch entry";
    while (Date.now() < deadline && !finished) {
        if (startedMs === undefined) { reason = "the remote did not report its start time"; await sleep(200); continue; }
        const response = await send({ type: "get_entries" }, 10_000);
        if (response.success) {
            const entries = (response.data?.entries ?? []).filter((e) => e?.type === "custom" && e.customType === want.entryType && Date.parse(e.timestamp) >= startedMs);
            const entry = entries[entries.length - 1];
            reason = "the remote did not report a sandbox launch entry";
            if (entry) {
                const d = entry.data ?? {};
                if (d.active !== true) return { ok: false, reason: `the remote sandbox reports it is not active (profile ${JSON.stringify(d.profile)})` };
                if (d.profile !== want.entryProfile) return { ok: false, reason: `the remote sandbox profile is ${JSON.stringify(d.profile)}, expected ${JSON.stringify(want.entryProfile)}` };
                if (typeof d.policyHash !== "string" || !d.policyHash || typeof d.planHash !== "string" || !d.planHash) return { ok: false, reason: "the remote sandbox entry carries no policyHash/planHash" };
                if (want.policyHash && d.policyHash.toLowerCase() !== want.policyHash) return { ok: false, reason: `the remote sandbox policyHash ${d.policyHash} does not match the pinned sandbox.policyHash` };
                return { ok: true, value: { profile: d.profile, requested: want.profile, policyHash: d.policyHash, planHash: d.planHash, ...(typeof entry.id === "string" ? { entryId: entry.id } : {}), at: Date.now() } };
            }
        } else reason = `get_entries failed: ${response.error ?? "no response"}`;
        await sleep(300);
    }
    return { ok: false, reason: `${reason} (waited ${want.timeoutMs}ms)` };
}

// Start: verify the remote sandbox, then send the prompt, so a missing pi / inactive sandbox fails before any work.
void (async () => {
    let prompt;
    try { prompt = readFileSync(config.promptPath, "utf8"); } catch (error) {
        writeJson(config.failurePath, { kind: "remote-exit", summary: `prompt unreadable: ${error.message}`, code: 1 });
        child.kill("SIGTERM");
        return;
    }
    const verdict = await verifySandbox();
    if (finished) return;
    if (!verdict.ok) {
        await failClosed("sandbox-unverified", `Remote sandbox profile ${config.sandbox.profile} could not be verified: ${verdict.reason}. The prompt was not sent.`);
        return;
    }
    writeJson(config.sandbox.verifiedPath, verdict.value);
    log(JSON.stringify({ type: "remote_sandbox_verified", data: verdict.value }));
    promptSent = true;
    const response = await send({ type: "prompt", message: prompt }, config.startTimeoutMs ?? 120_000);
    if (!response.success && !finished) {
        writeJson(config.failurePath, { kind: "remote-exit", summary: `remote pi rejected the prompt: ${response.error ?? "no response"}`, code: 1 });
        try { child.stdin.end(); } catch { /* ignore */ }
    } else if (response.data?.disposition === "handled" && !settled) {
        settled = true;
        void finishSettled();
    }
})();
