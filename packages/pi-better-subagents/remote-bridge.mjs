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
 * Remote process-group termination is NOT done here: `stopRun` does it (and verifies it) after the
 * abort marker, so it also works when this bridge is gone. Configuration comes from a JSON file
 * (argv[2]) written by the parent; this file names no host, path, or model.
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

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
    try { record = JSON.parse(line); } catch { log(`[remote stdout] ${line}`); return; }
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
    try { child.stdin.end(); } catch { /* ignore */ }
    setTimeout(() => { if (!finished) child.kill("SIGTERM"); }, 15_000).unref();
}

function classify(code) {
    const tail = stderrTail.trim().split("\n").filter(Boolean).pop() ?? "";
    if (code === 255) return sawEvent
        ? { kind: "channel-lost", summary: "SSH channel to the remote host was lost while the run was active; the remote process may still be running. Use subagent_stop to terminate it.", code }
        : { kind: "ssh-failed", summary: `SSH connection failed: ${tail || "no detail"}`, code };
    if (code === 127) return { kind: "pi-missing", summary: tail || "remote pi was not found", code };
    if (code === 96) return { kind: "sandbox-unavailable", summary: tail || "required remote sandbox could not be enabled", code };
    if (code === 97) return { kind: "cwd-missing", summary: tail || "remote working directory not found", code };
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

// Start: send the prompt only after the remote answers, so a missing pi / sandbox fails before any work.
void (async () => {
    let prompt;
    try { prompt = readFileSync(config.promptPath, "utf8"); } catch (error) {
        writeJson(config.failurePath, { kind: "remote-exit", summary: `prompt unreadable: ${error.message}`, code: 1 });
        child.kill("SIGTERM");
        return;
    }
    const response = await send({ type: "prompt", message: prompt }, config.startTimeoutMs ?? 120_000);
    if (!response.success && !finished) {
        writeJson(config.failurePath, { kind: "remote-exit", summary: `remote pi rejected the prompt: ${response.error ?? "no response"}`, code: 1 });
        try { child.stdin.end(); } catch { /* ignore */ }
    } else if (response.data?.disposition === "handled" && !settled) {
        settled = true;
        void finishSettled();
    }
})();
