/**
 * Remote subagent targets: configuration schema, launch/stop command builders, and the
 * synchronous remote stop used by `stopRun`.
 *
 * Generic mechanism only. Every host, working directory, pi invocation, environment and sandbox
 * profile comes from configuration (`remoteTargets` in the subagents settings, selected by a
 * spawn option or by `remoteAgents`). Nothing here names a host, user, path, or model.
 *
 * A remote run is an ordinary run whose local process is a small bridge
 * (`remote-bridge.mjs`) that owns an ssh channel carrying `pi --mode rpc`. The log, metadata,
 * steer file, navigator row and health semantics are the same as for a local child.
 */

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
    createSshMuxController,
    resolveSshCommand,
    type CommandResult,
    type CommandSpec,
    type RemoteRunner,
} from "./shared-ssh-core/index.ts";
import {
    hasCommandLimits,
    parseCommandLimits,
    resourceScopeArguments,
    resourceScopeCheckScript,
    COMMAND_LIMIT_KEYS,
    type CommandLimits,
} from "./shared-sandbox-core.ts";

export interface RemoteSandboxPolicy {
    /** Remote sandbox profile the remote pi must apply. Required: a remote run is never unconfined by omission. */
    profile: string;
    /** Extra remote pi arguments; `{profile}` is replaced by the profile. */
    args?: string[];
    /** Extra remote environment; `{profile}` is replaced by the profile. */
    env?: Record<string, string>;
    /** Optional remote shell command that must exit 0 before launch (backend present, policy installed, ...). */
    verifyCommand?: string;
    /**
     * `customType` of the session entry the remote sandbox writes at launch (fields `active`,
     * `profile`, `policyHash`, `planHash`). The bridge requires it before any prompt is sent.
     */
    entryType?: string;
    /**
     * `profile` value the audit entry must carry. Default: `profile`. The pi-better-sandbox audit entry
     * reports the permission profile it applies (`"main"`), which need not equal the name passed to it.
     */
    entryProfile?: string;
    /** How long the bridge waits for that entry. Default 30000. */
    verifyTimeoutMs?: number;
    /**
     * Expected `policyHash` (sha256 hex) of the remote sandbox policy. When set, any other value in the
     * audit entry fails closed; when omitted the hash is only recorded.
     */
    policyHash?: string;
}

/** Resource bounds a target applies (see docs/remote-subagents.md#session-limits). */
export interface RemoteResources {
    /**
     * Limits for the whole remote pi process and every child: the launch script starts pi inside ONE
     * `systemd-run --user --scope`. Same keys and forms as the sandbox policy's `resources.command`.
     * A limit that cannot be applied fails the launch closed; pi never runs unbounded instead.
     */
    session?: CommandLimits;
}

export interface RemoteTarget {
    /** SSH Host alias (resolved by the user's ssh configuration). */
    host: string;
    user?: string;
    port?: number;
    /** Remote working directory; `~/` is expanded on the remote. Default: the remote login directory. */
    cwd?: string;
    /**
     * Allowed working-folder roots (absolute or `~/`). When set, a spawn may pass its own `cwd`; the
     * remote launch script resolves it (and these roots) with `pwd -P` and refuses to start pi unless it
     * lies inside one of them. The check also applies to `cwd` / the login directory. Without roots a
     * spawn `cwd` is rejected and `cwd` is fixed.
     */
    cwdRoots?: string[];
    /**
     * Agent dir for the remote pi (`PI_CODING_AGENT_DIR`; absolute or `~/`). With `sandboxReadConfinement` in
     * that dir's settings the policy location travels with the workspace, as for a plain
     * `PI_CODING_AGENT_DIR=<dir> pi` run by the owner in the same working folder.
     */
    agentDir?: string;
    /** Remote run directories live under this root (relative = under the remote $HOME). */
    root?: string;
    pi: {
        /** Remote pi executable (name on the remote PATH or an absolute path). */
        command: string;
        /** Fixed arguments placed before the generated ones. */
        args?: string[];
        /** Start through the remote user's login shell so profile-provided PATH applies. */
        login?: boolean;
    };
    env?: Record<string, string>;
    sandbox: RemoteSandboxPolicy;
    /** Optional resource bounds for the remote pi (`resources.session`). */
    resources?: RemoteResources;
    /** How long stop waits for the RPC abort to be acknowledged. Default 3000. */
    abortWaitMs?: number;
    /** Seconds between remote TERM and KILL during stop. Default 5. */
    termGraceSeconds?: number;
}

export type RemoteTargets = Record<string, RemoteTarget>;

export const DEFAULT_REMOTE_ROOT = ".pi-better-subagents/runs";
export const DEFAULT_ABORT_WAIT_MS = 3_000;
/** Session `customType` written by the pi-better-sandbox launch audit (contract: active, profile, policyHash, planHash). */
export const DEFAULT_SANDBOX_ENTRY_TYPE = "pi-better-sandbox-read-confinement";
export const DEFAULT_SANDBOX_VERIFY_TIMEOUT_MS = 30_000;
export const DEFAULT_TERM_GRACE_SECONDS = 5;

export const AGENT_DIR_ENV = "PI_CODING_AGENT_DIR";
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SAFE_ROOT = /^[A-Za-z0-9._/@+-]+$/;
const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function fail(where: string, message: string): never {
    throw new Error(`Invalid remote target ${where}: ${message}`);
}
function plainObject(value: unknown, where: string): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(where, "must be an object");
    return value as Record<string, unknown>;
}
function noUnknown(obj: Record<string, unknown>, allowed: readonly string[], where: string): void {
    for (const key of Object.keys(obj)) if (!allowed.includes(key)) fail(where, `unknown field "${key}"`);
}
function str(value: unknown, where: string, options: { allowSpace?: boolean } = {}): string {
    if (typeof value !== "string" || value.trim() === "") fail(where, "must be a non-empty string");
    if (/[\0\r\n]/.test(value)) fail(where, "must not contain control characters");
    if (!options.allowSpace && /\s/.test(value)) fail(where, "must not contain whitespace");
    return value;
}
function strList(value: unknown, where: string): string[] {
    if (!Array.isArray(value)) fail(where, "must be an array of strings");
    return value.map((item, index) => str(item, `${where}[${index}]`, { allowSpace: true }));
}
/** Remote directory word: absolute or `~/…` (expanded remotely); roots must not be `/` or `~`. */
function remoteDirectory(value: string, where: string, options: { root?: boolean } = {}): void {
    if (!(value.startsWith("/") || value.startsWith("~/") || value === "~")) fail(where, "must be absolute or start with ~/");
    if (options.root && (/^\/+$/.test(value) || value === "~" || value === "~/")) fail(where, "must not be the filesystem root or the whole home directory");
}
function envMap(value: unknown, where: string): Record<string, string> {
    const obj = plainObject(value, where);
    const out: Record<string, string> = {};
    for (const [name, v] of Object.entries(obj)) {
        if (!ENV_NAME.test(name)) fail(where, `invalid environment variable name ${JSON.stringify(name)}`);
        if (typeof v !== "string" || /[\0]/.test(v)) fail(where, `${name} must be a string`);
        out[name] = v;
    }
    return out;
}

/** Validate one target (schema: see docs/remote-subagents.md). Throws a descriptive error. */
export function parseRemoteTarget(value: unknown, name: string): RemoteTarget {
    const where = `"${name}"`;
    if (!TARGET_NAME.test(name)) fail(where, "target names use letters, digits, '.', '_' and '-'");
    const obj = plainObject(value, where);
    noUnknown(obj, ["host", "user", "port", "cwd", "cwdRoots", "agentDir", "root", "pi", "env", "sandbox", "resources", "abortWaitMs", "termGraceSeconds"], where);
    const target: RemoteTarget = {
        host: str(obj.host, `${where}.host`),
        pi: undefined as never,
        sandbox: undefined as never,
    };
    if (/^-/.test(target.host)) fail(`${where}.host`, "must not start with '-'");
    if (obj.user !== undefined) {
        target.user = str(obj.user, `${where}.user`);
        if (/^-/.test(target.user)) fail(`${where}.user`, "must not start with '-'");
    }
    if (obj.port !== undefined) {
        if (!Number.isInteger(obj.port) || (obj.port as number) < 1 || (obj.port as number) > 65_535) fail(`${where}.port`, "must be an integer between 1 and 65535");
        target.port = obj.port as number;
    }
    if (obj.cwd !== undefined) target.cwd = str(obj.cwd, `${where}.cwd`, { allowSpace: true });
    if (obj.cwdRoots !== undefined) {
        const roots = strList(obj.cwdRoots, `${where}.cwdRoots`);
        if (roots.length === 0) fail(`${where}.cwdRoots`, "must list at least one root");
        roots.forEach((root, i) => remoteDirectory(root, `${where}.cwdRoots[${i}]`, { root: true }));
        target.cwdRoots = roots;
    }
    if (obj.agentDir !== undefined) {
        target.agentDir = str(obj.agentDir, `${where}.agentDir`, { allowSpace: true });
        remoteDirectory(target.agentDir, `${where}.agentDir`);
    }
    if (obj.root !== undefined) {
        const root = str(obj.root, `${where}.root`);
        if (!SAFE_ROOT.test(root) || root.split("/").includes("..")) fail(`${where}.root`, "may contain letters, digits and . _ / @ + - only, without '..'");
        target.root = root;
    }
    const pi = plainObject(obj.pi, `${where}.pi`);
    noUnknown(pi, ["command", "args", "login"], `${where}.pi`);
    target.pi = { command: str(pi.command, `${where}.pi.command`, { allowSpace: true }) };
    if (pi.args !== undefined) target.pi.args = strList(pi.args, `${where}.pi.args`);
    if (pi.login !== undefined) {
        if (typeof pi.login !== "boolean") fail(`${where}.pi.login`, "must be a boolean");
        target.pi.login = pi.login;
    }
    if (obj.env !== undefined) target.env = envMap(obj.env, `${where}.env`);
    if (target.agentDir !== undefined && (AGENT_DIR_ENV in (target.env ?? {}))) fail(`${where}.env`, `${AGENT_DIR_ENV} is set by agentDir; remove it from env`);
    if (obj.sandbox === undefined) fail(`${where}.sandbox`, "a remote sandbox profile is required");
    const sandbox = plainObject(obj.sandbox, `${where}.sandbox`);
    noUnknown(sandbox, ["profile", "args", "env", "verifyCommand", "entryType", "entryProfile", "verifyTimeoutMs", "policyHash"], `${where}.sandbox`);
    target.sandbox = { profile: str(sandbox.profile, `${where}.sandbox.profile`) };
    if (sandbox.args !== undefined) target.sandbox.args = strList(sandbox.args, `${where}.sandbox.args`);
    if (sandbox.env !== undefined) target.sandbox.env = envMap(sandbox.env, `${where}.sandbox.env`);
    if (target.agentDir !== undefined && (AGENT_DIR_ENV in (target.sandbox.env ?? {}))) fail(`${where}.sandbox.env`, `${AGENT_DIR_ENV} is set by agentDir; remove it from sandbox.env`);
    if (sandbox.verifyCommand !== undefined) target.sandbox.verifyCommand = str(sandbox.verifyCommand, `${where}.sandbox.verifyCommand`, { allowSpace: true });
    if (sandbox.entryType !== undefined) target.sandbox.entryType = str(sandbox.entryType, `${where}.sandbox.entryType`);
    if (sandbox.entryProfile !== undefined) target.sandbox.entryProfile = str(sandbox.entryProfile, `${where}.sandbox.entryProfile`);
    if (sandbox.policyHash !== undefined) {
        const hash = str(sandbox.policyHash, `${where}.sandbox.policyHash`);
        if (!/^[0-9a-f]{64}$/i.test(hash)) fail(`${where}.sandbox.policyHash`, "must be a 64-character hex sha256 digest");
        target.sandbox.policyHash = hash.toLowerCase();
    }
    if (sandbox.verifyTimeoutMs !== undefined) {
        if (!Number.isInteger(sandbox.verifyTimeoutMs) || (sandbox.verifyTimeoutMs as number) < 1 || (sandbox.verifyTimeoutMs as number) > 600_000) fail(`${where}.sandbox.verifyTimeoutMs`, "must be an integer between 1 and 600000");
        target.sandbox.verifyTimeoutMs = sandbox.verifyTimeoutMs as number;
    }
    // The profile must reach the remote pi. Without a carrier the profile would be a label, not a request.
    const carriesProfile = [...(target.sandbox.args ?? []), ...Object.values(target.sandbox.env ?? {})].some((v) => v.includes("{profile}"));
    if (!carriesProfile) fail(`${where}.sandbox`, "no way to pass the profile to the remote pi: reference {profile} in sandbox.args or sandbox.env");
    if (obj.resources !== undefined) {
        const resources = plainObject(obj.resources, `${where}.resources`);
        noUnknown(resources, ["session"], `${where}.resources`);
        target.resources = {};
        if (resources.session !== undefined) target.resources.session = parseCommandLimits(resources.session, `${where}.resources.session`, fail);
    }
    for (const key of ["abortWaitMs", "termGraceSeconds"] as const) {
        if (obj[key] === undefined) continue;
        if (!Number.isInteger(obj[key]) || (obj[key] as number) < 0 || (obj[key] as number) > 600_000) fail(`${where}.${key}`, "must be a non-negative integer");
        target[key] = obj[key] as number;
    }
    return target;
}

export function parseRemoteTargets(value: unknown): RemoteTargets {
    if (value === undefined || value === null) return {};
    const obj = plainObject(value, "remoteTargets");
    const out: RemoteTargets = {};
    for (const [name, raw] of Object.entries(obj)) out[name] = parseRemoteTarget(raw, name);
    return out;
}

export interface RemoteSettings {
    remoteTargets?: unknown;
    remoteAgents?: Record<string, string> | null;
}

/**
 * The target a launch uses, or undefined for a local run. An explicit `remote` spawn option wins,
 * then the `remoteAgents` mapping from the launched agent id. An unknown name fails closed.
 */
export function selectRemoteTarget(
    settings: RemoteSettings,
    selection: { remote?: string; agent?: string },
): { name: string; target: RemoteTarget } | undefined {
    const agentMapped = selection.agent && settings.remoteAgents ? settings.remoteAgents[selection.agent] : undefined;
    const name = selection.remote ?? agentMapped;
    if (name === undefined) return undefined;
    const targets = parseRemoteTargets(settings.remoteTargets);
    const target = targets[name];
    if (!target) {
        throw new Error(`Remote target "${name}" is not configured (remoteTargets). Configured: ${Object.keys(targets).join(", ") || "none"}.`);
    }
    return { name, target };
}

// ---- command construction -------------------------------------------------

export function shellQuote(value: string): string {
    return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** The run-scoped remote directory expression (expanded by the remote shell). */
export function remoteRunDir(target: RemoteTarget, runId: string): string {
    if (!/^[A-Za-z0-9_-]+$/.test(runId)) throw new Error("Invalid run ID.");
    const root = target.root ?? DEFAULT_REMOTE_ROOT;
    return `${root.startsWith("/") ? "" : "$HOME/"}${root.replace(/\/+$/, "")}/${runId}`;
}

function cwdWord(cwd: string): string {
    return cwd.startsWith("~/") ? `"$HOME"/${shellQuote(cwd.slice(2))}` : cwd === "~" ? `"$HOME"` : shellQuote(cwd);
}

function substitute(value: string, profile: string): string {
    return value.split("{profile}").join(profile);
}

export interface RemotePiOptions {
    model?: string;
    thinking?: string;
    tools?: string;
    excludeTools?: string;
    approve?: boolean;
    /** Working folder for this spawn (needs the target's `cwdRoots`); replaces the target's `cwd`. */
    cwd?: string;
    /**
     * Resume: re-attach to the kept session of this earlier run id (a new pi process continues it).
     * The pid file and stop identity stay run-scoped to the NEW run.
     */
    resumeSessionOf?: string;
}

/** Remote session directory expression for a run id. */
export function remoteSessionDir(target: RemoteTarget, runId: string): string {
    return `${remoteRunDir(target, runId)}/session`;
}

/** Remote pi words after the executable: fixed args, RPC mode, run-scoped session, selection, sandbox. */
export function remotePiWords(target: RemoteTarget, runId: string, options: RemotePiOptions): string[] {
    const words = (target.pi.args ?? []).map(shellQuote);
    words.push("--mode", "rpc", "--session-dir", `"$SD"`);
    if (options.resumeSessionOf) words.push("--continue");
    else words.push("--session-id", shellQuote(runId));
    if (options.model) words.push("--model", shellQuote(options.model));
    if (options.thinking) words.push("--thinking", shellQuote(options.thinking));
    if (options.tools) words.push("--tools", shellQuote(options.tools));
    if (options.excludeTools) words.push("--exclude-tools", shellQuote(options.excludeTools));
    if (options.approve) words.push("--approve");
    for (const arg of target.sandbox.args ?? []) words.push(shellQuote(substitute(arg, target.sandbox.profile)));
    return words;
}

export const REMOTE_EXIT = { sessionMissing: 94, setsidMissing: 95, sandboxVerify: 96, cwdMissing: 97, dirFailed: 98, cwdDenied: 99, sessionLimits: 100, piMissing: 127, sshFailed: 255 } as const;

/** Line that ends the environment section the bridge writes to the launch script's stdin. */
export function envSentinel(runId: string): string {
    return `__PI_REMOTE_ENV_END_${runId}__`;
}

/** Marker the launch script prints (stdout) just before pi starts: `pi-remote-started <epoch ms>` (remote clock). */
export const STARTED_MARKER = "pi-remote-started";

/**
 * Environment payload for the launch script's stdin (never on a command line). Values may be
 * secrets for the remote's own use, but the documented rule is: no secrets in target.env.
 */
export function buildEnvPayload(target: RemoteTarget, runId: string): string {
    const env = { ...(target.env ?? {}), ...Object.fromEntries(Object.entries(target.sandbox.env ?? {}).map(([k, v]) => [k, substitute(v, target.sandbox.profile)])) };
    const sentinel = envSentinel(runId);
    const lines: string[] = [];
    for (const [name, value] of Object.entries(env).sort(([a], [b]) => a.localeCompare(b))) {
        if (!ENV_NAME.test(name)) throw new Error(`invalid remote environment variable name: ${JSON.stringify(name)}`);
        if (value.split("\n").includes(sentinel)) throw new Error(`remote environment variable ${name} contains a reserved line`);
        lines.push(`export ${name}=${shellQuote(value)}`);
    }
    if (target.agentDir !== undefined) lines.push(`export ${AGENT_DIR_ENV}=${cwdWord(target.agentDir)}`);
    lines.push(sentinel);
    return `${lines.join("\n")}\n`;
}

// ---- session limits (resources.session) ---------------------------------------

/** The target's configured session limits, or undefined when none is set (an empty object counts as none). */
export function sessionLimitsOf(target: RemoteTarget): CommandLimits | undefined {
    const limits = target.resources?.session;
    return hasCommandLimits(limits) ? limits : undefined;
}

/** The configured limits as written, only the keys that are set, in the documented order. */
export function sessionLimitsRecord(limits: CommandLimits): CommandLimits {
    const out: CommandLimits = {};
    for (const key of COMMAND_LIMIT_KEYS) if (limits[key] !== undefined) (out as Record<string, string | number>)[key] = limits[key]!;
    return out;
}

const SESSION_SCOPE_SUBJECT = "remote session limits";
/** The scope's check as one line: it travels inside a command line, which scope tooling and logs show whole. */
function oneLine(script: string): string {
    return script.split("\n").join("; ");
}
const SESSION_PI_STARTER = `sh -c 'echo $$ > "$0/pid"; exec "$@"'`;

/**
 * POSIX sh lines that run before pi is staged and refuse the launch (exit `REMOTE_EXIT.sessionLimits`) unless a
 * resource scope with the configured limits can really be started here: `systemd-run` exists, the user's
 * systemd user manager is reachable, and a probe scope carries every controller the limits need. Over ssh the
 * user manager is reachable only while the user has lingering enabled or an active login session; the reason
 * (and the success note) say which applies. There is no unscoped fallback.
 */
function sessionLimitPreflight(limits: CommandLimits): string[] {
    const scopeWords = resourceScopeArguments(limits, { stopGrace: false }).map(shellQuote).join(" ");
    const probe = shellQuote(oneLine(resourceScopeCheckScript(limits, "exit 0", SESSION_SCOPE_SUBJECT)));
    return [
        `limit_fail() { echo "pi-remote: resources.session cannot be applied: $1; pi is not started without the bound" >&2; exit ${REMOTE_EXIT.sessionLimits}; }`,
        `command -v systemd-run >/dev/null 2>&1 || limit_fail "systemd-run is not available on the remote host (session limits need a systemd user scope)"`,
        `uid=$(id -u)`,
        // The user manager's runtime directory; a non-login ssh command may not have it in its environment.
        `case "\${XDG_RUNTIME_DIR:-}" in /*) ;; *) XDG_RUNTIME_DIR="/run/user/$uid";; esac; export XDG_RUNTIME_DIR`,
        // Why the user manager exists for this launch: lingering, or an active login session that holds it.
        `case "$(loginctl show-user "$uid" -p Linger --value 2>/dev/null)" in yes) basis="lingering is enabled";; no) basis="lingering is not enabled, so the user manager exists only while a login session is active";; *) basis="lingering and login-session state could not be read";; esac`,
        `if [ -z "\${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ ! -S "$XDG_RUNTIME_DIR/bus" ] && [ ! -S "$XDG_RUNTIME_DIR/systemd/private" ]; then limit_fail "no systemd user manager is reachable for user $uid ($basis)"; fi`,
        `probe_out=$(systemd-run ${scopeWords} -- sh -c ${probe} pi-session-scope-probe 2>&1) || limit_fail "a systemd user scope with the configured limits cannot be started: $(printf '%s\\n' "$probe_out" | tail -n 1) ($basis)"`,
        `echo "pi-remote: session limits are applied through the systemd user manager ($basis)" >&2`,
    ];
}

/** The launch words that start pi inside one resource scope (the scope's own check runs first, inside it). */
function sessionScopeLaunch(limits: CommandLimits): string {
    const scopeWords = resourceScopeArguments(limits, { stopGrace: false }).map(shellQuote).join(" ");
    const check = shellQuote(oneLine(resourceScopeCheckScript(limits, 'exec "$@"', SESSION_SCOPE_SUBJECT)));
    return `systemd-run ${scopeWords} -- sh -c ${check} pi-session-scope`;
}

/**
 * POSIX sh script that prepares the run directory and execs remote pi in its own session.
 * Requires `setsid`: stop works by session id and must reach every process the run started.
 * The environment arrives on stdin (see buildEnvPayload) and is staged in a 0600 file that is
 * removed once sourced; it never appears on a command line.
 *
 * With `resources.session` the script first checks that the limits can be applied (see
 * sessionLimitPreflight) and then runs pi inside one `systemd-run --user --scope` placed under setsid: the
 * recorded pid is still the session leader that becomes pi, and the scope holds pi and every child. Without
 * `resources.session` the script is exactly the unscoped one.
 */
export function buildLaunchScript(target: RemoteTarget, runId: string, options: RemotePiOptions): string {
    const cwd = effectiveRemoteCwd(target, options.cwd);
    const pi = shellQuote(target.pi.command);
    const sessionRun = options.resumeSessionOf ?? runId;
    const lines = [
        `RD="${remoteRunDir(target, runId)}"`,
        `SD="${remoteSessionDir(target, sessionRun)}"`,
        `command -v ${pi} >/dev/null 2>&1 || { echo ${shellQuote(`pi-remote: pi command not found on remote: ${target.pi.command}`)} >&2; exit ${REMOTE_EXIT.piMissing}; }`,
        `command -v setsid >/dev/null 2>&1 || { echo "pi-remote: setsid is required on the remote host (stop works by session id)" >&2; exit ${REMOTE_EXIT.setsidMissing}; }`,
        `mkdir -p "$RD" || { echo "pi-remote: cannot create run directory" >&2; exit ${REMOTE_EXIT.dirFailed}; }`,
        options.resumeSessionOf
            ? `[ -d "$SD" ] || { echo "pi-remote: session to resume not found" >&2; exit ${REMOTE_EXIT.sessionMissing}; }`
            : `mkdir -p "$SD" || { echo "pi-remote: cannot create run directory" >&2; exit ${REMOTE_EXIT.dirFailed}; }`,
    ];
    if (target.sandbox.verifyCommand) {
        lines.push(`( ${target.sandbox.verifyCommand} ) >&2 || { echo ${shellQuote(`pi-remote: sandbox profile ${target.sandbox.profile} cannot be enabled (verification failed)`)} >&2; exit ${REMOTE_EXIT.sandboxVerify}; }`);
    }
    if (cwd) lines.push(`cd ${cwdWord(cwd)} 2>/dev/null || { echo "pi-remote: remote cwd not found" >&2; exit ${REMOTE_EXIT.cwdMissing}; }`);
    if (target.cwdRoots) {
        // Fail closed: the physical working folder must lie inside an allowed root (both sides realpath'd remotely).
        lines.push(`CWD_REAL=$(pwd -P) || { echo "pi-remote: cannot resolve the working folder" >&2; exit ${REMOTE_EXIT.cwdMissing}; }`, `cwd_ok=0`);
        for (const root of target.cwdRoots) {
            lines.push(`ROOT_REAL=$(cd ${cwdWord(root)} 2>/dev/null && pwd -P) && case "$CWD_REAL" in "$ROOT_REAL"|"$ROOT_REAL"/*) cwd_ok=1;; esac`);
        }
        lines.push(`[ "$cwd_ok" = 1 ] || { echo "pi-remote: the working folder is outside the target's allowed cwdRoots" >&2; exit ${REMOTE_EXIT.cwdDenied}; }`);
    }
    const sessionLimits = sessionLimitsOf(target);
    if (sessionLimits) lines.push(...sessionLimitPreflight(sessionLimits));
    const sentinel = shellQuote(envSentinel(runId));
    const piWords = [pi, ...remotePiWords(target, runId, options)].join(" ");
    lines.push(
        `EF="$RD/env.$$"`,
        `( umask 077; : > "$EF" ) && chmod 600 "$EF" || { echo "pi-remote: cannot stage environment" >&2; exit ${REMOTE_EXIT.dirFailed}; }`,
        `got=0; while IFS= read -r envline; do if [ "$envline" = ${sentinel} ]; then got=1; break; fi; printf '%s\\n' "$envline" >> "$EF"; done`,
        `[ "$got" = 1 ] || { rm -f "$EF"; echo "pi-remote: environment was not delivered" >&2; exit ${REMOTE_EXIT.dirFailed}; }`,
        `. "$EF"; rm -f "$EF"`,
        `now=$(date +%s%3N 2>/dev/null); case "$now" in ''|*[!0-9]*) now="$(date +%s)000";; esac`,
        `echo "${STARTED_MARKER} $now"`,
        sessionLimits
            ? `exec setsid -w ${sessionScopeLaunch(sessionLimits)} ${SESSION_PI_STARTER} "$RD" ${piWords}`
            : `exec setsid -w sh -c 'echo $$ > "$0/pid"; exec "$@"' "$RD" ${piWords}`,
    );
    return lines.join("\n");
}

/**
 * The working folder a launch uses: the spawn's `cwd` (only when the target declares `cwdRoots`), else
 * the target's fixed `cwd`. A spawn `cwd` for a target without roots is refused, never ignored.
 */
export function effectiveRemoteCwd(target: RemoteTarget, spawnCwd: string | undefined): string | undefined {
    if (spawnCwd === undefined) return target.cwd;
    if (!target.cwdRoots) throw new Error("cwd is not accepted by this remote target: it declares no cwdRoots (the working folder is fixed by the target's cwd).");
    str(spawnCwd, "cwd", { allowSpace: true });
    remoteDirectory(spawnCwd, "cwd");
    return spawnCwd;
}

/** Wrap a script as one remote command: `sh -c` directly, or through the remote login shell. */
export function wrapRemoteScript(script: string, login: boolean): string {
    const inner = `sh -c ${shellQuote(script)}`;
    return login ? `"$SHELL" -lc ${shellQuote(inner)}` : inner;
}

/**
 * Stop script: TERM then KILL every process of the run's SESSION (sid == the recorded pid, which
 * the launch script made a session leader with setsid), then verify none remain. Detached children
 * in their own process groups share the session and are covered; a process that starts yet another
 * session is out of reach. Refuses (prints `unsafe`, exit 1) when the recorded pid is alive but is
 * not a session leader, and when `ps` cannot report sessions: it never guesses. Guarded by an
 * identity check on a live leader so a recycled pid is never signalled. Prints `gone`, `alive`,
 * `unsafe` or `unknown`.
 */
export function buildStopScript(target: RemoteTarget, runId: string, sessionRunId: string = runId): string {
    const grace = target.termGraceSeconds ?? DEFAULT_TERM_GRACE_SECONDS;
    return [
        `RD="${remoteRunDir(target, runId)}"`,
        `SD="${remoteSessionDir(target, sessionRunId)}"`,
        `[ -f "$RD/pid" ] || { echo gone; exit 0; }`,
        `pid=$(cat "$RD/pid" 2>/dev/null)`,
        `case "$pid" in ''|*[!0-9]*) echo gone; exit 0;; esac`,
        `ps -eo pid=,sid=,stat= >/dev/null 2>&1 || { echo "pi-remote: ps cannot report sessions" >&2; echo unknown; exit 1; }`,
        // Members of the session (zombies are dead: they only await reaping).
        `members() { ps -eo pid=,sid=,stat= 2>/dev/null | awk -v s="$pid" '$2==s && $3 !~ /^Z/ {print $1}'; }`,
        `leader_alive() { kill -0 "$pid" 2>/dev/null || return 1; case "$(ps -o stat= -p "$pid" 2>/dev/null)" in Z*) return 1;; esac; return 0; }`,
        `if leader_alive; then`,
        `  lsid=$(ps -o sid= -p "$pid" 2>/dev/null | tr -d ' ')`,
        `  [ "$lsid" = "$pid" ] || { echo "pi-remote: recorded pid is not a session leader; refusing to guess" >&2; echo unsafe; exit 1; }`,
        `  case "$(ps -o args= -p "$pid" 2>/dev/null)" in *"$SD"*) ;; *) echo gone; exit 0;; esac`,
        `fi`,
        `[ -n "$(members)" ] || { echo gone; exit 0; }`,
        `kill_members() { for m in $(members); do kill -"$1" "$m" 2>/dev/null; done; }`,
        `kill_members TERM >&2`,
        `i=0; while [ -n "$(members)" ] && [ "$i" -lt ${grace} ]; do sleep 1; i=$((i+1)); done`,
        `i=0; while [ -n "$(members)" ] && [ "$i" -lt 3 ]; do kill_members KILL >&2; sleep 1; i=$((i+1)); done`,
        `if [ -n "$(members)" ]; then echo alive; exit 1; fi`,
        `echo gone`,
    ].join("\n");
}

// ---- run metadata + bridge configuration ---------------------------------

/** Durable description of a remote run (RunMeta.remote). No secrets: ssh argv carries only options. */
export interface RemoteRunMeta {
    target: string;
    host: string;
    /** Remote run directory expression (holds the pid file and the retained session). */
    remoteDir: string;
    /** ssh argv up to and excluding the remote command (includes the ControlPath options). */
    sshArgv: string[];
    login: boolean;
    abortDonePath: string;
    abortWaitMs: number;
    termGraceSeconds: number;
    stopScript: string;
    /** Working folder this run used (as configured or spawned; `~/` expands remotely). */
    cwd?: string;
    /** Agent dir the remote pi ran with (`PI_CODING_AGENT_DIR`), when the target sets one. */
    agentDir?: string;
    /** Run this one resumed (same remote session, new pi process). */
    resumedFrom?: string;
    /** Session limits the remote pi was bound by (one systemd user scope), as configured; absent when none is set. */
    sessionLimits?: CommandLimits;
    /** Set by the parent after the bridge verified the remote sandbox launch audit entry. */
    sandbox?: RemoteSandboxVerification;
}

/** What the bridge verified before sending the prompt (from the remote sandbox's launch audit entry). */
export interface RemoteSandboxVerification {
    profile: string;
    policyHash: string;
    planHash: string;
    entryId?: string;
    at: number;
}

export interface BridgeConfig {
    /** ssh argv including the remote launch command as the last element. */
    argv: string[];
    promptPath: string;
    steerPath: string;
    abortDonePath: string;
    failurePath: string;
    startTimeoutMs: number;
    /** Local 0600 file with the environment payload for the launch script's stdin; deleted once sent. */
    envPath: string;
    /** ssh argv (with the stop script as the last element) the bridge runs when verification fails. */
    stopArgv: string[];
    /** Written when the remote agent settled: the remote work is over. */
    settledPath: string;
    sandbox: { profile: string; entryProfile: string; entryType: string; timeoutMs: number; verifiedPath: string; policyHash?: string };
}

export function remoteFailurePath(runDirPath: string): string {
    return join(runDirPath, "remote-failure.json");
}
export function remoteSettledPath(runDirPath: string): string {
    return join(runDirPath, "remote-settled.json");
}
export function remoteSandboxPath(runDirPath: string): string {
    return join(runDirPath, "remote-sandbox.json");
}
export function bridgeConfigPath(runDirPath: string): string {
    return join(runDirPath, "remote-bridge.json");
}

export interface RemotePlan {
    meta: RemoteRunMeta;
    bridge: BridgeConfig;
}

/** Compose the ssh argv (sans command) for a target, optionally rewritten through a mux controller. */
export function sshBaseArgv(target: RemoteTarget, mux?: { withMux(spec: CommandSpec): CommandSpec }): string[] {
    const resolved = resolveSshCommand({ command: "true", ssh: { host: target.host, ...(target.user ? { user: target.user } : {}), ...(target.port !== undefined ? { port: target.port } : {}) } });
    const spec = mux ? mux.withMux(resolved.commandSpec) : resolved.commandSpec;
    return spec.argv!.slice(0, -1);
}

export function buildRemotePlan(input: {
    target: RemoteTarget;
    targetName: string;
    runId: string;
    runDirPath: string;
    options: RemotePiOptions;
    sshArgv: string[];
}): RemotePlan {
    const { target, runId, runDirPath } = input;
    const login = target.pi.login === true;
    const launch = wrapRemoteScript(buildLaunchScript(target, runId, input.options), login);
    const abortDonePath = join(runDirPath, "remote-abort.done");
    const stopScript = buildStopScript(target, runId, input.options.resumeSessionOf ?? runId);
    return {
        meta: {
            target: input.targetName,
            host: target.host,
            remoteDir: remoteRunDir(target, runId),
            sshArgv: input.sshArgv,
            login,
            abortDonePath,
            abortWaitMs: target.abortWaitMs ?? DEFAULT_ABORT_WAIT_MS,
            termGraceSeconds: target.termGraceSeconds ?? DEFAULT_TERM_GRACE_SECONDS,
            stopScript,
            ...(effectiveRemoteCwd(target, input.options.cwd) ? { cwd: effectiveRemoteCwd(target, input.options.cwd)! } : {}),
            ...(target.agentDir ? { agentDir: target.agentDir } : {}),
            ...(input.options.resumeSessionOf ? { resumedFrom: input.options.resumeSessionOf } : {}),
            ...(sessionLimitsOf(target) ? { sessionLimits: sessionLimitsRecord(sessionLimitsOf(target)!) } : {}),
        },
        bridge: {
            argv: [...input.sshArgv, launch],
            promptPath: join(runDirPath, "prompt.md"),
            steerPath: join(runDirPath, "steer.json"),
            abortDonePath,
            failurePath: remoteFailurePath(runDirPath),
            startTimeoutMs: 120_000,
            envPath: join(runDirPath, "remote-env"),
            stopArgv: [...input.sshArgv, wrapRemoteScript(stopScript, login)],
            settledPath: remoteSettledPath(runDirPath),
            sandbox: {
                profile: target.sandbox.profile,
                entryProfile: target.sandbox.entryProfile ?? target.sandbox.profile,
                entryType: target.sandbox.entryType ?? DEFAULT_SANDBOX_ENTRY_TYPE,
                timeoutMs: target.sandbox.verifyTimeoutMs ?? DEFAULT_SANDBOX_VERIFY_TIMEOUT_MS,
                verifiedPath: remoteSandboxPath(runDirPath),
                ...(target.sandbox.policyHash ? { policyHash: target.sandbox.policyHash } : {}),
            },
        },
    };
}

export function writeBridgeConfig(runDirPath: string, config: BridgeConfig, envPayload?: string): string {
    mkdirSync(runDirPath, { recursive: true });
    const path = bridgeConfigPath(runDirPath);
    writeFileSync(path, JSON.stringify(config), { mode: 0o600 });
    if (envPayload !== undefined) writeFileSync(config.envPath, envPayload, { mode: 0o600 });
    return path;
}

// ---- ssh mux (shared ssh-core) --------------------------------------------

/** One-shot command runner for mux control operations (`ssh -O check` etc.). */
export const processRunner: RemoteRunner = {
    spawn() {
        throw new Error("detached remote spawn is not used by subagents");
    },
    runOnce(spec: CommandSpec, _max?: number, timeoutMs = 30_000): Promise<CommandResult> {
        const argv = spec.argv ?? [];
        const startedAt = Date.now();
        return new Promise((resolve) => {
            const child = spawn(argv[0]!, argv.slice(1), { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...spec.env } });
            let stdout = ""; let stderr = ""; let timedOut = false;
            child.stdout.on("data", (c: Buffer) => { stdout += c.toString(); });
            child.stderr.on("data", (c: Buffer) => { stderr += c.toString(); });
            const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, timeoutMs);
            const done = (exitCode: number | null, signal: NodeJS.Signals | null) => {
                clearTimeout(timer);
                resolve({ exitCode, signal, stdout, stderr, startedAt, endedAt: Date.now(), ...(timedOut ? { timedOut } : {}) });
            };
            child.on("error", (error) => { stderr += String(error); done(127, null); });
            child.on("close", done);
        });
    },
};

/**
 * Open (or reuse) the reusable ControlMaster for a target and return the ssh argv that rides it.
 * Fails closed: a master that cannot be established is an error, not a silent direct connection.
 */
export async function ensureRemoteMux(
    target: RemoteTarget,
    options: { runner?: RemoteRunner; controlPathRoot?: string; sessionScope?: string } = {},
): Promise<string[]> {
    const resolved = resolveSshCommand({ command: "true", ssh: { host: target.host, ...(target.user ? { user: target.user } : {}), ...(target.port !== undefined ? { port: target.port } : {}) } });
    const mux = createSshMuxController({
        ...resolved,
        runner: options.runner ?? processRunner,
        sessionScope: options.sessionScope ?? "pi-better-subagents",
        ...(options.controlPathRoot ? { controlPathRoot: options.controlPathRoot } : {}),
    });
    await mux.ensure();
    return sshBaseArgv(target, mux);
}

// ---- remote stop ------------------------------------------------------------

export type RemoteStopResult = { verified: true } | { verified: false; reason: string };

export interface RunOutput { status: number | null; stdout: string; stderr: string; error?: Error }

export interface RemoteStopDeps {
    run?: (argv: string[], timeoutMs: number) => RunOutput;
    runAsync?: (argv: string[], timeoutMs: number) => Promise<RunOutput>;
}

function defaultRun(argv: string[], timeoutMs: number): RunOutput {
    const result = spawnSync(argv[0]!, argv.slice(1), { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] });
    return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "", ...(result.error ? { error: result.error } : {}) };
}

function defaultRunAsync(argv: string[], timeoutMs: number): Promise<RunOutput> {
    return new Promise((resolve) => {
        let stdout = ""; let stderr = ""; let settled = false;
        const done = (value: RunOutput) => { if (!settled) { settled = true; clearTimeout(timer); resolve(value); } };
        const child = spawn(argv[0]!, argv.slice(1), { stdio: ["ignore", "pipe", "pipe"] });
        const timer = setTimeout(() => { child.kill("SIGKILL"); done({ status: null, stdout, stderr, error: new Error(`timed out after ${timeoutMs}ms`) }); }, timeoutMs);
        child.stdout.on("data", (c: Buffer) => { stdout += c.toString(); });
        child.stderr.on("data", (c: Buffer) => { stderr += c.toString(); });
        child.on("error", (error) => done({ status: null, stdout, stderr, error }));
        child.on("close", (status) => done({ status, stdout, stderr }));
    });
}

function stopTimeoutMs(remote: RemoteRunMeta): number {
    return (remote.termGraceSeconds + 8) * 1000 + 10_000;
}

function interpretStop(remote: RemoteRunMeta, result: RunOutput): RemoteStopResult {
    if (result.error) return { verified: false, reason: `ssh could not run the remote stop: ${result.error.message}` };
    if (result.status === REMOTE_EXIT.sshFailed || result.status === null) {
        return { verified: false, reason: `ssh to ${remote.host} failed during remote stop${result.stderr.trim() ? `: ${result.stderr.trim().split("\n").pop()}` : ""}` };
    }
    const verdict = result.stdout.trim().split("\n").pop();
    if (verdict === "gone") return { verified: true };
    const what = verdict === "alive" ? "survived TERM and KILL" : verdict === "unsafe" ? "was not stopped because the recorded pid is not a session leader" : "state is unknown";
    return { verified: false, reason: `remote process ${what} on ${remote.host}${result.stderr.trim() ? ` (${result.stderr.trim().split("\n").pop()})` : ""}` };
}

/**
 * Terminate the remote session and verify it is gone. Never throws; an unverifiable outcome is
 * reported so the caller fails closed instead of recording a stop that did not happen.
 * Prefer `stopRemoteProcessAsync`: this variant blocks the caller for the whole stop.
 */
export function stopRemoteProcess(remote: RemoteRunMeta, deps: RemoteStopDeps = {}): RemoteStopResult {
    const run = deps.run ?? defaultRun;
    return interpretStop(remote, run([...remote.sshArgv, wrapRemoteScript(remote.stopScript, remote.login)], stopTimeoutMs(remote)));
}

/** Non-blocking `stopRemoteProcess`. */
export async function stopRemoteProcessAsync(remote: RemoteRunMeta, deps: RemoteStopDeps = {}): Promise<RemoteStopResult> {
    const run = deps.runAsync ?? defaultRunAsync;
    return interpretStop(remote, await run([...remote.sshArgv, wrapRemoteScript(remote.stopScript, remote.login)], stopTimeoutMs(remote)));
}

/** Options a remote run cannot honour. A remote target never silently drops them. */
export function assertRemoteOptionsSupported(p: { sandbox?: unknown; sandbox_dir?: unknown; cwd?: unknown; git_clone_workspace?: unknown; allow_nested?: unknown; clean?: unknown }, target?: RemoteTarget): void {
    const unsupported: string[] = [];
    if (p.sandbox !== undefined) unsupported.push("sandbox (the remote target's own sandbox profile applies)");
    if (p.sandbox_dir !== undefined) unsupported.push("sandbox_dir");
    if (p.cwd !== undefined && !(target?.cwdRoots)) unsupported.push("cwd (this target declares no cwdRoots; set the target's cwd)");
    if (p.git_clone_workspace !== undefined) unsupported.push("git_clone_workspace");
    if (p.allow_nested !== undefined) unsupported.push("allow_nested");
    if (p.clean !== undefined) unsupported.push("clean");
    if (unsupported.length) throw new Error(`Option(s) not supported with a remote target: ${unsupported.join(", ")}. Remove them or run locally.`);
}
