/**
 * Shared test support for the remote session-limit tests (`resources.session`, decision D5).
 * Generic: no host, user, path, model or site value.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const here = dirname(fileURLToPath(import.meta.url));
export const fixtures = join(here, "fixtures", "remote");
export const sessionFixtures = join(here, "fixtures", "remote-session");
export const stubBin = join(sessionFixtures, "bin");
export const piStub = join(sessionFixtures, "pi-stub.sh");

/** Frozen interface: the five session keys and the systemd property each maps to. */
export const SESSION_KEYS = {
    memoryMax: "MemoryMax",
    memorySwapMax: "MemorySwapMax",
    tasksMax: "TasksMax",
    cpuQuota: "CPUQuota",
    runtimeMaxSec: "RuntimeMaxSec",
};

/** A valid target configuration (the same shape the existing remote tests use). */
export function targetConfig(over = {}, piCommand) {
    return {
        host: "example-alias",
        cwd: "~/work",
        pi: piCommand ?? { command: process.execPath, args: [join(fixtures, "fake-pi.mjs")] },
        env: { EXAMPLE_VAR: "example value" },
        sandbox: { profile: "profile-a", env: { FAKE_SANDBOX_PROFILE: "{profile}" }, args: ["--sandbox-profile", "{profile}"], verifyTimeoutMs: 20_000 },
        termGraceSeconds: 2,
        ...over,
    };
}

const UNITS = { K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 };

/**
 * Normalize one `Name=value` property to a canonical comparable form, whatever spelling the
 * launcher chose (systemd accepts `64M` and `67108864` alike; `RuntimeMaxSec=90` and `90s` alike).
 * Returns [name, canonical] or undefined when the spelling is not a valid systemd value.
 */
export function normalizeProperty(text) {
    const eq = text.indexOf("=");
    if (eq < 0) return undefined;
    const name = text.slice(0, eq);
    const value = text.slice(eq + 1);
    if (name === "MemoryMax" || name === "MemorySwapMax") {
        const m = /^(\d+)([KMGT])?$/.exec(value);
        return m ? [name, String(Number(m[1]) * (m[2] ? UNITS[m[2]] : 1))] : undefined;
    }
    if (name === "TasksMax") return /^\d+$/.test(value) ? [name, value] : undefined;
    if (name === "CPUQuota") { const m = /^(\d+)%$/.exec(value); return m ? [name, `${m[1]}%`] : undefined; }
    if (name === "RuntimeMaxSec") { const m = /^(\d+)(s)?$/.exec(value); return m ? [name, m[1]] : undefined; }
    return [name, value];
}

/** The properties a config's session limits must produce, canonical form. */
export function expectedProperties(session) {
    const out = {};
    for (const [key, name] of Object.entries(SESSION_KEYS)) {
        if (session[key] === undefined) continue;
        const value = String(session[key]);
        out[name] = normalizeProperty(`${name}=${name === "CPUQuota" ? `${value}%` : value}`)[1];
    }
    return out;
}

/** Parse the stub systemd-run log into one record per invocation. */
export function readStubCalls(logPath) {
    if (!existsSync(logPath)) return [];
    const calls = [];
    let cur = { flags: [], props: [], opts: [], cmd: "" };
    for (const line of readFileSync(logPath, "utf8").split("\n")) {
        if (!line) continue;
        const [tag, ...rest] = line.split("\t");
        const text = rest.join("\t");
        if (tag === "FLAG") cur.flags.push(text);
        else if (tag === "PROP") cur.props.push(text);
        else if (tag === "OPT") cur.opts.push(text);
        else if (tag === "CMD") cur.cmd = text;
        else if (tag === "END") { calls.push(cur); cur = { flags: [], props: [], opts: [], cmd: "" }; }
    }
    return calls;
}

/** Canonical property map of one recorded call; throws on a spelling systemd would reject. */
export function propertyMap(call) {
    const map = {};
    for (const raw of call.props) {
        const norm = normalizeProperty(raw);
        if (!norm) throw new Error(`invalid systemd property spelling: ${raw}`);
        if (norm[0] in map) throw new Error(`property set twice: ${norm[0]}`);
        map[norm[0]] = norm[1];
    }
    return map;
}

/** True when `text` shows the configured value in some canonical spelling (raw or, for sizes, bytes). */
export function mentionsValue(text, key, raw) {
    const forms = new Set([String(raw)]);
    if (key === "memoryMax" || key === "memorySwapMax") forms.add(normalizeProperty(`MemoryMax=${raw}`)[1]);
    for (const form of forms) {
        const escaped = form.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        if (new RegExp(`(?<![0-9A-Za-z_.-])${escaped}(?![0-9A-Za-z_-])`).test(text)) return true;
    }
    return false;
}

/** systemd time span ("10min", "1h 5min", "500ms", "3s", "infinity") to seconds. */
export function spanSeconds(text) {
    if (text.trim() === "infinity") return Infinity;
    const units = { us: 1e-6, ms: 1e-3, s: 1, sec: 1, min: 60, h: 3600, hr: 3600, d: 86400 };
    let total = 0;
    for (const part of text.trim().split(/\s+/)) {
        const m = /^(\d+(?:\.\d+)?)([a-z]+)$/.exec(part);
        if (!m || !(m[2] in units)) return NaN;
        total += Number(m[1]) * units[m[2]];
    }
    return total;
}
