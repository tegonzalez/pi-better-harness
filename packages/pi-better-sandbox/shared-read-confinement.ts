// Generated from packages/sandbox-core/read-confinement.ts. Do not edit directly.
/**
 * Linux read-confinement planning (mechanism only; all policy is data).
 *
 * Given a validated policy, a project root and the launching environment, this
 * computes the mount plan for `outsideProject: "off"`: which extra paths are
 * bound read-only, which stay writable, which caches live on a private tmpfs,
 * the synthetic PATH holding only approved tools, and an audit record of every
 * bind and every refusal. Nothing here names a host, user, project or tool:
 * every environment-specific decision comes from the policy document.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
    closeSync,
    existsSync,
    lstatSync,
    mkdirSync,
    mkdtempSync,
    openSync,
    readdirSync,
    readFileSync,
    readlinkSync,
    readSync,
    realpathSync,
    statSync,
    symlinkSync,
    writeSync,
    constants as fsConstants,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import {
    broadCredentialPaths,
    bubblewrapExecutable,
    hardeningStates,
    HARDENING_MEASURES,
    resolveHardening,
    RUNTIME_ROOTS,
    type HardeningState,
    type HardeningSwitches,
    type ReadConfinementMounts,
    type ResolvedHardening,
    type SandboxSeams,
} from "./shared-sandbox-core.ts";

// ---------------------------------------------------------------------------
// Policy schema
// ---------------------------------------------------------------------------

export type ReadConfinementTool = {
    /** Executable name looked up on the launching PATH. Exactly one of `name` / `path`. */
    name?: string;
    /** Absolute path to the executable (used instead of a PATH lookup). */
    path?: string;
    /** Read-only config paths: absolute, `~/…` or `${VAR}/…`. */
    config?: string[];
    /** Cache paths the tool may write: a private tmpfs, or persistent when `cachePersistent`. */
    cache?: string[];
    cachePersistent?: boolean;
    /** Extra read-only paths the tool needs (plugin or data dirs). */
    bind?: string[];
    /** `file` binds only the executable; `prefix` binds its install prefix (`<prefix>/bin/x`). */
    install?: "file" | "prefix";
};

export type ReadConfinementPolicy = {
    version: 1;
    limits?: { maxSymlinks?: number; maxDepth?: number; maxWalkEntries?: number; maxBinds?: number; maxWalkMs?: number; minPrefixDepth?: number; maxWildcardMatches?: number };
    /**
     * Generic read-only paths (for example shared folders): absolute, `~/…` or `${VAR}/…`. Each is
     * realpath'd, must pass the deny list and must not contain a writable root. Symlinks inside are not followed.
     */
    readOnly?: string[];
    /** Environment names the confined child may inherit; everything else is cleared. */
    env?: { allow?: string[] };
    /** Directory base names never descended into by the symlink walk. */
    walkSkipDirNames?: string[];
    deny?: { paths?: string[]; credentialList?: boolean; otherHomes?: boolean };
    /**
     * `approvedPathDirs` entries and a tool `path` may hold single-segment `*` wildcards (never `**`). They are
     * expanded at launch; every match must realpath into an approved or bound location (a `readOnly` path,
     * a tool `bind`, or a runtime root) and is recorded in the audit.
     */
    tools?: { approved?: (string | ReadConfinementTool)[]; approvedPathDirs?: string[]; builtinDefaults?: boolean };
    secretDetector?: { useDefaults?: boolean; patterns?: string[]; maxScanBytes?: number; maxScanFiles?: number };
    caches?: { persistentDir?: string };
    /** Where the synthetic PATH directory appears inside the sandbox. */
    syntheticPathMount?: string;
    /**
     * Confined-launch hardening. Every boolean defaults to `true`; `false` removes exactly that measure.
     * `ipc`: private SysV/POSIX IPC. `uts`: private hostname (`hostname`, default "sandbox").
     * `userns`: no user namespaces inside. `keyring`: keyctl/add_key/request_key denied by a seccomp
     * filter. `fds`: only descriptors 0-2 (and the filter's own) survive into the child.
     */
    hardening?: HardeningSwitches;
};

const DEFAULT_LIMITS = { maxSymlinks: 2000, maxDepth: 8, maxWalkEntries: 200_000, maxBinds: 500, maxWalkMs: 15_000, minPrefixDepth: 3 };
/** Cap on the matches one wildcard pattern may expand to (policy `limits.maxWildcardMatches`). */
export const DEFAULT_MAX_WILDCARD_MATCHES = 64;
/** Environment names every confined child may inherit; policy `env.allow` extends this. */
export const DEFAULT_ENV_ALLOW: readonly string[] = Object.freeze(["PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR", "TZ"]);
/** Generic secret shapes; `(?i)` prefix = case-insensitive. Replaceable via `secretDetector.useDefaults: false`. */
export const DEFAULT_SECRET_PATTERNS: readonly string[] = Object.freeze([
    "-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "\\bAKIA[0-9A-Z]{16}\\b",
    "\\bgh[pousr]_[A-Za-z0-9]{30,}\\b",
    "_authToken\\s*=",
    "\\bxox[abprs]-[A-Za-z0-9-]{10,}\\b",
    "(?i)(password|passwd|secret|api[_-]?key|token)\\s*[=:]\\s*\\S{8,}",
    "://[^/\\s:@]+:[^/\\s@]+@",
    "(?i)authorization\\s*:",
    "(?i)\\b(password|passwd|pass)\\s*=\\s*\\S",
]);
/** Generic widely standard locations; removable with `tools.builtinDefaults: false` or overridden per tool. */
export const BUILTIN_TOOL_DEFAULTS: Readonly<Record<string, ReadConfinementTool>> = Object.freeze({
    // Only the files git needs to run; never the whole directory (it can hold a credential store).
    git: { name: "git", config: [
        "~/.gitconfig",
        "${XDG_CONFIG_HOME}/git/config", "${XDG_CONFIG_HOME}/git/ignore", "${XDG_CONFIG_HOME}/git/attributes",
        "~/.config/git/config", "~/.config/git/ignore", "~/.config/git/attributes",
    ] },
});

function fail(path: string, message: string): never {
    throw new Error(`Invalid read-confinement policy at ${path}: ${message}`);
}

function checkKeys(value: unknown, path: string, allowed: readonly string[]): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(path, "expected an object");
    for (const key of Object.keys(value)) {
        if (key === "planTtlMs") fail(`${path}.${key}`, "removed: the plan is computed once at pi launch and frozen for the session; delete this key");
        if (!allowed.includes(key)) fail(`${path}.${key}`, "unknown key");
    }
    return value as Record<string, unknown>;
}

function stringList(value: unknown, path: string): string[] | undefined {
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry === "" || entry.includes("\0"))) {
        fail(path, "expected an array of non-empty strings");
    }
    return value as string[];
}

function boolean(value: unknown, path: string): boolean | undefined {
    if (value !== undefined && typeof value !== "boolean") fail(path, "expected a boolean");
    return value as boolean | undefined;
}

function count(value: unknown, path: string, min = 1): number | undefined {
    if (value === undefined) return undefined;
    if (typeof value !== "number" || !Number.isInteger(value) || value < min) fail(path, `expected an integer >= ${min}`);
    return value;
}

/** A wildcard pattern: absolute, `*` only inside a single segment, never `**`, no `..`. */
function wildcardPath(entry: string, path: string): void {
    if (!isAbsolute(entry)) fail(path, "must be absolute");
    if (entry.includes("**")) fail(path, '"**" is not supported; use a single-segment "*"');
    if (entry.includes("*") && entry.split(sep).includes("..")) fail(path, 'a wildcard pattern must not contain ".." segments');
}

function pathLike(entry: string, path: string): void {
    if (!isAbsolute(entry) && !entry.startsWith("~/") && !entry.startsWith("${")) {
        fail(path, `"${entry}" must be absolute, "~/…" or "\${VAR}/…"`);
    }
}

/** A leading `(?i)` makes the pattern case-insensitive. */
function compilePattern(pattern: string, path: string): RegExp {
    try {
        return pattern.startsWith("(?i)") ? new RegExp(pattern.slice(4), "i") : new RegExp(pattern);
    } catch (error) {
        return fail(path, `invalid regular expression (${error instanceof Error ? error.message : String(error)})`);
    }
}

/** Strictly validate a policy document; unknown keys and malformed values fail closed. */
export function parseReadConfinementPolicy(value: unknown): ReadConfinementPolicy {
    const root = checkKeys(value, "$", ["version", "limits", "walkSkipDirNames", "deny", "tools", "secretDetector", "caches", "syntheticPathMount", "env", "readOnly", "hardening"]);
    if (root.version !== 1) fail("$.version", "must be 1");
    const policy: ReadConfinementPolicy = { version: 1 };
    if (root.limits !== undefined) {
        const l = checkKeys(root.limits, "$.limits", ["maxSymlinks", "maxDepth", "maxWalkEntries", "maxBinds", "maxWalkMs", "minPrefixDepth", "maxWildcardMatches"]);
        policy.limits = {};
        for (const key of ["maxSymlinks", "maxDepth", "maxWalkEntries", "maxBinds", "maxWalkMs", "minPrefixDepth", "maxWildcardMatches"] as const) {
            const n = count(l[key], `$.limits.${key}`);
            if (n !== undefined) policy.limits[key] = n;
        }
    }
    const skip = stringList(root.walkSkipDirNames, "$.walkSkipDirNames");
    if (skip) policy.walkSkipDirNames = skip;
    const readOnly = stringList(root.readOnly, "$.readOnly");
    readOnly?.forEach((entry, i) => {
        pathLike(entry, `$.readOnly[${i}]`);
        if (entry.includes("*")) fail(`$.readOnly[${i}]`, "wildcards are not supported here; list the paths");
    });
    if (readOnly) policy.readOnly = readOnly;
    if (root.deny !== undefined) {
        const d = checkKeys(root.deny, "$.deny", ["paths", "credentialList", "otherHomes"]);
        const paths = stringList(d.paths, "$.deny.paths");
        paths?.forEach((entry, i) => pathLike(entry, `$.deny.paths[${i}]`));
        const credentialList = boolean(d.credentialList, "$.deny.credentialList");
        const otherHomes = boolean(d.otherHomes, "$.deny.otherHomes");
        policy.deny = {
            ...(paths && { paths }),
            ...(credentialList !== undefined && { credentialList }),
            ...(otherHomes !== undefined && { otherHomes }),
        };
    }
    if (root.tools !== undefined) {
        const t = checkKeys(root.tools, "$.tools", ["approved", "approvedPathDirs", "builtinDefaults"]);
        policy.tools = {};
        if (t.approved !== undefined) {
            if (!Array.isArray(t.approved)) fail("$.tools.approved", "expected an array");
            policy.tools.approved = t.approved.map((entry, i): string | ReadConfinementTool => {
                const at = `$.tools.approved[${i}]`;
                if (typeof entry === "string") {
                    if (entry === "" || entry.includes("\0")) fail(at, "empty tool");
                    return entry;
                }
                const e = checkKeys(entry, at, ["name", "path", "config", "cache", "cachePersistent", "bind", "install"]);
                if ((e.name === undefined) === (e.path === undefined)) fail(at, "exactly one of name or path is required");
                if (e.name !== undefined && (typeof e.name !== "string" || e.name === "" || e.name.includes("/"))) fail(`${at}.name`, "expected a bare executable name");
                if (e.path !== undefined && (typeof e.path !== "string" || !isAbsolute(e.path))) fail(`${at}.path`, "expected an absolute path");
                if (typeof e.path === "string") wildcardPath(e.path, `${at}.path`);
                if (e.install !== undefined && e.install !== "file" && e.install !== "prefix") fail(`${at}.install`, 'expected "file" or "prefix"');
                const tool: ReadConfinementTool = {};
                if (e.name !== undefined) tool.name = e.name as string;
                if (e.path !== undefined) tool.path = e.path as string;
                for (const key of ["config", "cache", "bind"] as const) {
                    const list = stringList(e[key], `${at}.${key}`);
                    list?.forEach((p, j) => pathLike(p, `${at}.${key}[${j}]`));
                    if (list) tool[key] = list;
                }
                const persistent = boolean(e.cachePersistent, `${at}.cachePersistent`);
                if (persistent !== undefined) tool.cachePersistent = persistent;
                if (e.install) tool.install = e.install as "file" | "prefix";
                return tool;
            });
        }
        const dirs = stringList(t.approvedPathDirs, "$.tools.approvedPathDirs");
        dirs?.forEach((entry, i) => wildcardPath(entry, `$.tools.approvedPathDirs[${i}]`));
        if (dirs) policy.tools.approvedPathDirs = dirs;
        const builtin = boolean(t.builtinDefaults, "$.tools.builtinDefaults");
        if (builtin !== undefined) policy.tools.builtinDefaults = builtin;
    }
    if (root.secretDetector !== undefined) {
        const s = checkKeys(root.secretDetector, "$.secretDetector", ["useDefaults", "patterns", "maxScanBytes", "maxScanFiles"]);
        const patterns = stringList(s.patterns, "$.secretDetector.patterns");
        patterns?.forEach((pattern, i) => compilePattern(pattern, `$.secretDetector.patterns[${i}]`));
        const useDefaults = boolean(s.useDefaults, "$.secretDetector.useDefaults");
        const maxScanBytes = count(s.maxScanBytes, "$.secretDetector.maxScanBytes");
        const maxScanFiles = count(s.maxScanFiles, "$.secretDetector.maxScanFiles");
        policy.secretDetector = {
            ...(useDefaults !== undefined && { useDefaults }),
            ...(patterns && { patterns }),
            ...(maxScanBytes !== undefined && { maxScanBytes }),
            ...(maxScanFiles !== undefined && { maxScanFiles }),
        };
    }
    if (root.caches !== undefined) {
        const c = checkKeys(root.caches, "$.caches", ["persistentDir"]);
        policy.caches = {};
        if (c.persistentDir !== undefined) {
            if (typeof c.persistentDir !== "string") fail("$.caches.persistentDir", "expected a string");
            pathLike(c.persistentDir, "$.caches.persistentDir");
            policy.caches.persistentDir = c.persistentDir;
        }
    }
    if (root.syntheticPathMount !== undefined) {
        if (typeof root.syntheticPathMount !== "string" || !isAbsolute(root.syntheticPathMount) || root.syntheticPathMount === sep) {
            fail("$.syntheticPathMount", "expected an absolute non-root path");
        }
        policy.syntheticPathMount = root.syntheticPathMount;
    }
    if (root.env !== undefined) {
        const e = checkKeys(root.env, "$.env", ["allow"]);
        const allow = stringList(e.allow, "$.env.allow");
        allow?.forEach((name, i) => { if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) fail(`$.env.allow[${i}]`, "expected an environment variable name"); });
        policy.env = allow ? { allow } : {};
    }
    if (root.hardening !== undefined) {
        const h = checkKeys(root.hardening, "$.hardening", [...HARDENING_MEASURES, "hostname"]);
        policy.hardening = {};
        for (const measure of HARDENING_MEASURES) {
            const value = boolean(h[measure], `$.hardening.${measure}`);
            if (value !== undefined) policy.hardening[measure] = value;
        }
        if (h.hostname !== undefined) {
            if (typeof h.hostname !== "string" || !/^[A-Za-z0-9]([A-Za-z0-9.-]{0,62}[A-Za-z0-9])?$/.test(h.hostname)) {
                fail("$.hardening.hostname", "expected a host name: 1-64 letters, digits, dots or hyphens, starting and ending with a letter or digit");
            }
            policy.hardening.hostname = h.hostname;
        }
    }
    return policy;
}

export type LoadedReadConfinementPolicy = { policy: ReadConfinementPolicy; source: string; sha256: string };

/** Hash of the parsed policy, independent of whitespace and key order in the source file. */
export function hashPolicy(policy: ReadConfinementPolicy): string {
    const canonical = (value: unknown): unknown => Array.isArray(value) ? value.map(canonical)
        : value && typeof value === "object"
            ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : 1).map(([k, v]) => [k, canonical(v)])) : value;
    return createHash("sha256").update(JSON.stringify(canonical(policy))).digest("hex");
}

export function loadReadConfinementPolicyFile(file: string): LoadedReadConfinementPolicy {
    let text: string;
    try { text = readFileSync(file, "utf8"); } catch (error) {
        throw new Error(`Cannot read read-confinement policy ${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch (error) {
        throw new Error(`Read-confinement policy ${file} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
    const policy = parseReadConfinementPolicy(parsed);
    return { policy, source: resolve(file), sha256: hashPolicy(policy) };
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

export type ReadConfinementSeams = {
    /** Launching process environment (PATH, XDG_*, …). Defaults to `process.env`. */
    env?: NodeJS.ProcessEnv;
    /** The current user's home. Defaults to `os.homedir()`. */
    home?: string;
    /** Home directories of all accounts. Defaults to parsing the passwd database. */
    passwdHomes?: () => string[];
    /** Lists shared libraries an ELF executable needs, as absolute lexical paths. Defaults to the loader's `--list`. */
    listLibraries?: (executable: string) => string[];
    /** Creates the host directory holding the synthetic PATH links. */
    makeSyntheticDir?: () => string;
    /** Distinguishes persistent caches per agent. */
    agentId?: string;
    /** Further directories some active profile can write; the policy file must not be inside any of them. */
    extraWritableRoots?: readonly string[];
    /** Where the hardening measures are checked against bubblewrap (executable lookup, `--help` text, architecture). */
    hardening?: Pick<SandboxSeams, "lookupExecutable" | "bwrapHelp" | "arch">;
};

/** The state of each confined-launch hardening measure, as recorded in the audit. */
export type ReadConfinementHardeningAudit = { readonly [measure in (typeof HARDENING_MEASURES)[number]]: HardeningState } & { readonly hostname: string };

export type ReadConfinementAudit = {
    version: 1;
    policy: { source: string; sha256: string };
    project: string;
    gitDirs: string[];
    binds: { path: string; mode: "ro" | "rw" | "tmpfs"; kind: "file" | "dir"; reason: string }[];
    symlinkMounts: { path: string; text: string }[];
    denied: { path: string; reason: string; via?: string }[];
    skipped: { path: string; reason: string; via?: string }[];
    syntheticPath: { mount: string; tools: { name: string; target: string; implicit: boolean }[] } | undefined;
    limits: { maxSymlinks: number; maxDepth: number; maxWalkEntries: number; maxBinds: number; maxWalkMs: number; minPrefixDepth: number; maxWildcardMatches?: number };
    /** Wildcard expansions (only present when the policy uses a wildcard): every match and whether it was accepted. */
    wildcards?: { pattern: string; kind: "approvedPathDir" | "toolPath"; matches: { path: string; real?: string; accepted: boolean; reason?: string }[] }[];
    symlinksFollowed: number;
    /** Environment names the confined child inherits; every other variable is cleared. */
    envAllow: string[];
    /** Paths inside writable git dirs that stay write-denied (hooks, config, alternates, sibling worktrees, ...). */
    denyWrite: string[];
    /** Per measure: `on`, `off` (by policy) or `unavailable` with its reason (the launch then fails closed). */
    hardening: ReadConfinementHardeningAudit;
};

export type ReadConfinementPlan = ReadConfinementMounts & {
    hardening: ResolvedHardening;
    audit: ReadConfinementAudit;
    /** Stable digest of the audit. */
    hash: string;
    /** Host directory holding the synthetic PATH links; remove it when the plan is discarded. */
    syntheticDir: string | undefined;
};

/** Raised when a cap is exceeded or the project cannot be confined; callers must not launch. */
export class ReadConfinementError extends Error {
    constructor(message: string) {
        super(`Read confinement failed closed: ${message}`);
        this.name = "ReadConfinementError";
    }
}

function contains(root: string, target: string): boolean {
    return target === root || target.startsWith(root.endsWith(sep) ? root : root + sep);
}

function expandPath(entry: string, home: string, env: NodeJS.ProcessEnv): string | undefined {
    if (entry === "~") return home;
    if (entry.startsWith("~/")) return resolve(home, entry.slice(2));
    const match = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(\/.*)?$/.exec(entry);
    if (match) {
        const base = env[match[1]!];
        return base && isAbsolute(base) ? resolve(base, (match[2] ?? "").replace(/^\//, "")) : undefined;
    }
    return isAbsolute(entry) ? resolve(entry) : undefined;
}

function realOrUndefined(path: string): string | undefined {
    try { return realpathSync.native(path); } catch { return undefined; }
}

function passwdHomesDefault(): string[] {
    try {
        return readFileSync("/etc/passwd", "utf8").split("\n")
            .map((line) => line.split(":")[5]).filter((home): home is string => Boolean(home));
    } catch { return []; }
}

function isExecutableFile(path: string): boolean {
    try { const info = statSync(path); return info.isFile() && (info.mode & 0o111) !== 0; } catch { return false; }
}

function readHead(path: string, bytes: number): Buffer {
    const fd = openSync(path, "r");
    try {
        const buffer = Buffer.alloc(bytes);
        return buffer.subarray(0, readSync(fd, buffer, 0, bytes, 0));
    } finally { closeSync(fd); }
}

/** ELF64 little-endian PT_INTERP loader path, if any. */
function elfInterpreter(path: string): string | undefined {
    let head: Buffer;
    try { head = readHead(path, 4096); } catch { return undefined; }
    if (head.length < 64 || head.readUInt32BE(0) !== 0x7f454c46 || head[4] !== 2 || head[5] !== 1) return undefined;
    const phoff = Number(head.readBigUInt64LE(0x20));
    const phentsize = head.readUInt16LE(0x36);
    const phnum = head.readUInt16LE(0x38);
    for (let i = 0; i < phnum; i++) {
        const at = phoff + i * phentsize;
        if (at + 56 > head.length) return undefined;
        if (head.readUInt32LE(at) !== 3) continue;
        const offset = Number(head.readBigUInt64LE(at + 8));
        const size = Number(head.readBigUInt64LE(at + 32));
        try {
            const fd = openSync(path, "r");
            try {
                const buffer = Buffer.alloc(size);
                readSync(fd, buffer, 0, size, offset);
                return buffer.toString("utf8").replace(/\0[\s\S]*$/, "");
            } finally { closeSync(fd); }
        } catch { return undefined; }
    }
    return undefined;
}

/** Ask the executable's own dynamic loader which libraries (DT_NEEDED, RPATH, RUNPATH) it resolves. */
function loaderListLibraries(executable: string): string[] {
    const loader = elfInterpreter(executable);
    if (!loader || !isAbsolute(loader) || !existsSync(loader)) return [];
    const result = spawnSync(loader, ["--list", executable], {
        encoding: "utf8", timeout: 5000, maxBuffer: 1 << 20, env: { LANG: "C" },
    });
    if (result.status !== 0) return [];
    const libs = new Set<string>([loader]);
    for (const line of result.stdout.split("\n")) {
        const match = /=>\s+(\/\S+)/.exec(line) ?? /^\s*(\/\S+)\s+\(0x/.exec(line);
        if (match) libs.add(match[1]!);
    }
    return [...libs];
}

type Bound = { path: string; mode: "ro" | "rw" | "tmpfs"; dir: boolean; reason: string; source?: string; late?: boolean };

/** Per git dir: write-denied entries. `create` = an empty node is harmless, so absence is blocked too. */
const GIT_GUARDED: readonly { rel: string; dir: boolean; create: boolean; content?: string }[] = [
    { rel: "hooks", dir: true, create: true },
    { rel: "config", dir: false, create: true },
    { rel: "config.worktree", dir: false, create: true },
    { rel: join("info", "attributes"), dir: false, create: true },
    { rel: join("objects", "info", "alternates"), dir: false, create: true },
    { rel: join("objects", "info", "http-alternates"), dir: false, create: true },
    // Absent in a main repo or submodule git dir. A creatable path would let the agent redirect git, so a
    // placeholder is written at planning time and then mounted read-only. `commondir` must hold `.` (an empty
    // one breaks git: "failed to read commondir"); an empty `gitdir` is ignored by git outside a linked worktree.
    { rel: "commondir", dir: false, create: true, content: ".\n" },
    { rel: "gitdir", dir: false, create: true, content: "" },
];
type ToolSpec = { name: string; lexical: string; implicit: boolean; spec: ReadConfinementTool };

/** Compute the mount plan. Throws `ReadConfinementError` when a cap is hit or the project cannot be confined. */
export function planReadConfinement(
    loaded: LoadedReadConfinementPolicy,
    projectRoot: string,
    seams: ReadConfinementSeams = {},
): ReadConfinementPlan {
    const { policy } = loaded;
    const env = seams.env ?? process.env;
    const home = realOrUndefined(seams.home ?? homedir()) ?? resolve(seams.home ?? homedir());
    const limits = { ...DEFAULT_LIMITS, ...policy.limits };
    const project = realpathSync.native(projectRoot);
    const skipNames = new Set(policy.walkSkipDirNames ?? []);

    const runtimeLexical = RUNTIME_ROOTS.filter((root) => existsSync(root));
    const runtimeReal = [...new Set(runtimeLexical.map((root) => realpathSync.native(root)))];

    const denied: ReadConfinementAudit["denied"] = [];
    const skipped: ReadConfinementAudit["skipped"] = [];
    const bound = new Map<string, Bound>();
    const symlinkMounts = new Map<string, string>();
    const gitDirs: string[] = [];
    let gitFile: { path: string; dirs: string[] } | undefined;
    let symlinksFollowed = 0;
    let walked = 0;
    const walkedDirs = new Set<string>();
    const startedAt = Date.now();

    // ---- deny list -------------------------------------------------------
    const denyEntries = new Set<string>();
    const addDeny = (path: string): void => {
        denyEntries.add(resolve(path));
        const real = realOrUndefined(path);
        if (real) denyEntries.add(real);
    };
    if (policy.deny?.credentialList !== false) {
        // The broad list: keyrings, gpg, rclone, agent tokens and the narrow list alike.
        for (const entry of broadCredentialPaths(home, {})) addDeny(entry);
    }
    for (const entry of policy.deny?.paths ?? []) {
        const expanded = expandPath(entry, home, env);
        if (expanded) addDeny(expanded);
    }
    if (policy.deny?.otherHomes !== false) {
        for (const other of (seams.passwdHomes ?? passwdHomesDefault)()) {
            const real = realOrUndefined(other);
            if (!real || real === sep || real === home || contains(home, real) || contains(real, home) ||
                contains(real, project) || runtimeReal.some((root) => contains(root, real))) continue;
            denyEntries.add(real);
        }
    }
    const denyMatch = (path: string, dir: boolean): string | undefined => {
        if (path === sep) return "filesystem root";
        for (const entry of denyEntries) {
            if (contains(entry, path)) return `inside denied path ${entry}`;
            if (dir && contains(path, entry) && !contains(project, entry)) return `contains denied path ${entry}`;
        }
        return undefined;
    };

    const lexicalRuntime = (path: string): boolean => runtimeLexical.some((root) => contains(root, path));
    const covered = (path: string): boolean =>
        contains(project, path) || runtimeReal.some((root) => contains(root, path)) ||
        [...bound.values()].some((b) => b.mode !== "tmpfs" && (b.dir ? contains(b.path, path) : b.path === path));

    const deny = (path: string, reason: string, via?: string): void => {
        if (!denied.some((d) => d.path === path && d.reason === reason)) denied.push({ path, reason, ...(via && { via }) });
    };
    const skip = (path: string, reason: string, via?: string): void => {
        if (!skipped.some((d) => d.path === path && d.reason === reason)) skipped.push({ path, reason, ...(via && { via }) });
    };

    const addBind = (path: string, mode: "ro" | "rw", reason: string, via?: string): boolean => {
        const dir = statSync(path).isDirectory();
        const why = denyMatch(path, dir);
        if (why) { deny(path, why, via); return false; }
        const existing = bound.get(path);
        if (existing && (existing.mode === "rw" || mode === "ro")) return true;
        if (mode === "ro" && covered(path)) return true;
        if (!existing && bound.size >= limits.maxBinds) {
            throw new ReadConfinementError(`more than ${limits.maxBinds} binds are required (policy limits.maxBinds); raise the cap or narrow the project's symlinks.`);
        }
        bound.set(path, { path, mode, dir, reason });
        return true;
    };

    /**
     * A read-only mount laid over part of a writable bind (hooks, config): never skipped as "already covered".
     * `boundary` is the directory the agent controls the layout below (the git dir): no component below it may be
     * a symlink (a mount cannot land on one, and creating below one would follow it), or planning fails closed.
     * A missing node that must be blocked is created here, with non-following operations, as a real readable
     * placeholder, so the plan is the same before and after the first launch and nothing is a /dev/null mount.
     */
    const denyWriteSet = new Set<string>();
    const refuseSymlinkBelow = (boundary: string, path: string, reason: string): void => {
        let current = boundary;
        for (const part of relative(boundary, path).split(sep).filter(Boolean)) {
            current = join(current, part);
            let link = false;
            try { link = lstatSync(current).isSymbolicLink(); } catch { return; }
            if (link) {
                deny(current, "refused: a symbolic link inside a git directory cannot be protected", reason);
                throw new ReadConfinementError(`${current} is a symbolic link inside the git directory ${boundary} (${reason}). Remove it; the sandbox cannot protect or create paths below a link.`);
            }
        }
    };
    const makeDirsBelow = (boundary: string, dir: string): boolean => {
        let current = boundary;
        for (const part of relative(boundary, dir).split(sep).filter(Boolean)) {
            current = join(current, part);
            try { mkdirSync(current, { mode: 0o755 }); } catch { /* exists, or not creatable: checked next */ }
            try { if (!lstatSync(current).isDirectory()) return false; } catch { return false; }
        }
        return true;
    };
    const addRoOverlay = (path: string, reason: string, absent?: { dir: boolean; content?: string }, boundary?: string): void => {
        denyWriteSet.add(path);
        if (boundary !== undefined) refuseSymlinkBelow(boundary, path, reason);
        let info;
        try { info = statSync(path); } catch {
            if (!absent) { skip(path, "absent: write denied in-process, creation not blocked in the sandbox", reason); return; }
            if (denyMatch(path, absent.dir)) return;
            // Placeholders are written now, at planning time (never following a link), then mounted read-only
            // like any existing node: an absent directory becomes an empty directory, a file an empty (or
            // content-bearing) file.
            if (boundary !== undefined && makeDirsBelow(boundary, absent.dir ? path : dirname(path))) {
                if (absent.dir) { try { info = lstatSync(path); } catch { /* fall through */ } }
                else {
                    try {
                        const fd = openSync(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o644);
                        try { if (absent.content) writeSync(fd, absent.content); } finally { closeSync(fd); }
                        info = lstatSync(path);
                    } catch { /* fall through */ }
                }
            }
            if (!info) {
                // Could not create it (read-only host path): the sandbox cannot create it either when the
                // node is mounted over, so an empty read-only node is bound in its place.
                bound.set(path, { path, mode: "ro", dir: false, reason: `${reason}; creation blocked`, source: "/dev/null", late: contains(project, path) });
                return;
            }
        }
        if (denyMatch(path, info.isDirectory())) return;
        bound.set(path, { path, mode: "ro", dir: info.isDirectory(), reason, late: contains(project, path) });
    };

    const capSymlinks = (): ReadConfinementError => new ReadConfinementError(
        `more than ${limits.maxSymlinks} symlinks need following (policy limits.maxSymlinks); raise the cap or add directories to walkSkipDirNames.`);

    // ---- symlink resolution ---------------------------------------------
    /**
     * Resolve `lexical` as the sandbox kernel will. Symlink components that
     * would not exist in the sandbox become `--symlink` mounts. Returns the
     * real path, or undefined when dangling.
     */
    const resolveChain = (lexical: string, via: string): string | undefined => {
        if (lexicalRuntime(lexical)) return realOrUndefined(lexical);
        let current: string = sep;
        let pending = lexical.split(sep).filter(Boolean);
        let hops = 0;
        while (pending.length) {
            const component = pending.shift()!;
            if (component === ".") continue;
            if (component === "..") { current = dirname(current); continue; }
            const next = join(current, component);
            let link: boolean;
            try { link = lstatSync(next).isSymbolicLink(); } catch { skip(lexical, "dangling or missing", via); return undefined; }
            if (!link) { current = next; continue; }
            if (++hops > 40) { skip(lexical, "symlink loop", via); return undefined; }
            const text = readlinkSync(next);
            if (!covered(current) && !lexicalRuntime(next) && !symlinkMounts.has(next)) {
                if (++symlinksFollowed > limits.maxSymlinks) throw capSymlinks();
                symlinkMounts.set(next, text);
            }
            const parts = text.split(sep).filter(Boolean);
            if (isAbsolute(text)) current = sep;
            pending = [...parts, ...pending];
        }
        return current;
    };

    const bindResolved = (lexical: string, via: string, depth: number, reason: string): string | undefined => {
        const real = resolveChain(lexical, via);
        if (real === undefined) return undefined;
        if (!covered(real) && !addBind(real, "ro", reason, via)) return undefined;
        if (statSync(real).isDirectory() && !contains(project, real) && !runtimeReal.some((root) => contains(root, real))) walk(real, depth);
        return real;
    };

    const followSymlink = (link: string, depth: number, seen: Set<string>): void => {
        if (seen.has(link)) { skip(link, "symlink cycle"); return; }
        seen.add(link);
        if (++symlinksFollowed > limits.maxSymlinks) throw capSymlinks();
        let text: string;
        try { text = readlinkSync(link); } catch { return; }
        if (depth >= limits.maxDepth) {
            throw new ReadConfinementError(`symlink closure deeper than ${limits.maxDepth} levels at ${link} (policy limits.maxDepth).`);
        }
        bindResolved(resolve(dirname(link), text), link, depth + 1, `symlink target of ${link}`);
    };

    const walk = (dir: string, depth: number): void => {
        if (walkedDirs.has(dir)) return;
        walkedDirs.add(dir);
        const seen = new Set<string>();
        const stack = [dir];
        while (stack.length) {
            const current = stack.pop()!;
            let entries;
            try { entries = readdirSync(current, { withFileTypes: true }); } catch { continue; }
            for (const entry of entries) {
                if (walked % 512 === 0 && Date.now() - startedAt > limits.maxWalkMs) {
                    throw new ReadConfinementError(`planning took longer than ${limits.maxWalkMs} ms (policy limits.maxWalkMs); add large directories to walkSkipDirNames or raise the cap.`);
                }
                if (++walked > limits.maxWalkEntries) {
                    throw new ReadConfinementError(`walked more than ${limits.maxWalkEntries} entries below ${dir} (policy limits.maxWalkEntries); add large directories to walkSkipDirNames or raise the cap.`);
                }
                const path = join(current, entry.name);
                if (entry.isSymbolicLink()) followSymlink(path, depth, seen);
                else if (entry.isDirectory() && !skipNames.has(entry.name)) stack.push(path);
            }
        }
    };

    // ---- project, git dir ------------------------------------------------
    // The `.git` file is agent-writable, so a redirect is only honoured when the
    // target proves it belongs to this worktree (back-pointer) and is a real git
    // dir (HEAD). Anything else is refused and recorded; nothing is bound.
    const persistentBase = policy.caches?.persistentDir ? expandPath(policy.caches.persistentDir, home, env) : undefined;
    const persistentReal = persistentBase ? realOrUndefined(persistentBase) ?? persistentBase : undefined;
    const writeRoots = new Set<string>([project]);
    const extraWritable = (seams.extraWritableRoots ?? []).map((root) => realOrUndefined(root) ?? root);
    /** A root the sandboxed agent can write (or the project owns), as far as planning knows at this point. */
    const ownWritable = [project, ...extraWritable, ...(persistentReal ? [persistentReal] : [])];
    const writableOverlap = (path: string): string | undefined => ownWritable.find((root) => contains(root, path) || contains(path, root));
    const cacheSources = new Set<string>();
    const dotGit = join(project, ".git");
    const isFile = (path: string): boolean => { try { return statSync(path).isFile(); } catch { return false; } };
    const isDir = (path: string): boolean => { try { return statSync(path).isDirectory(); } catch { return false; } };
    const readText = (path: string): string | undefined => { try { return readFileSync(path, "utf8"); } catch { return undefined; } };
    const belongsToProject = (gitdir: string): boolean => {
        const back = readText(join(gitdir, "gitdir"))?.trim();
        if (back) return realOrUndefined(resolve(gitdir, back)) === realOrUndefined(dotGit);
        // Submodule layout: no back-pointer file; the config names the worktree.
        const worktree = /^\s*worktree\s*=\s*(.+)$/m.exec(readText(join(gitdir, "config")) ?? "")?.[1]?.trim();
        return worktree !== undefined && realOrUndefined(resolve(gitdir, worktree)) === project;
    };
    /** Alternates are read grants: each target must be a git object dir and pass the deny rules, or the plan fails closed. */
    const readOnlyReal = (): string[] => (policy.readOnly ?? []).map((entry) => realOrUndefined(resolve(entry))).filter((entry): entry is string => entry !== undefined);
    /** `within`: a git dir the agent did not own (nested modules): targets must lie inside it or a policy readOnly entry. */
    const checkAlternates = (objectsDir: string, within?: string): void => {
        const file = join(objectsDir, "info", "alternates");
        for (const line of (readText(file) ?? "").split("\n")) {
            const alt = line.trim();
            if (!alt || alt.startsWith("#")) continue;
            const target = resolve(objectsDir, alt);
            const realAlt = realOrUndefined(target);
            if (!realAlt) { skip(target, "alternates entry not found", file); continue; }
            if (within !== undefined && !contains(within, realAlt) && !readOnlyReal().some((entry) => contains(entry, realAlt))) {
                const reason = "refused: alternates entry of a nested git directory points outside it and outside policy readOnly";
                deny(realAlt, reason, file);
                throw new ReadConfinementError(`${file} lists ${realAlt}: ${reason.replace("refused: ", "")}. Remove the entry, or list the target in the policy readOnly paths.`);
            }
            const why = denyMatch(realAlt, true);
            const objectDir = isDir(realAlt) && (isFile(join(dirname(realAlt), "HEAD")) || isDir(join(realAlt, "pack")));
            if (why || !objectDir) {
                const reason = why ? `refused: alternates entry ${why}` : "refused: alternates entry is not a git object directory";
                deny(realAlt, reason, file);
                throw new ReadConfinementError(`${file} lists ${realAlt}: ${reason.replace("refused: ", "")}. Remove the entry or move the repository.`);
            }
            bindResolved(target, file, 1, "git alternates (read-only)");
        }
    };
    /**
     * One write-deny set for a git dir the agent can write. Refs, objects, index, logs and
     * packed-refs stay writable; everything that would later run code or redirect git is denied
     * (here for the sandbox, and in `denyWrite` for the in-process file tools).
     */
    const guardGitDir = (real: string, label: string, own: string | undefined, depth = 0): void => {
        // Nothing is written into a git dir the agent can redirect: the boundary itself must not be a link.
        if (depth > 0) {
            let link = false;
            try { link = lstatSync(real).isSymbolicLink(); } catch { /* checked by the caller */ }
            if (link) {
                deny(real, "refused: a symbolic link cannot be a nested git directory", label);
                throw new ReadConfinementError(`${real} is a symbolic link (${label}). Remove it; the sandbox cannot protect a git directory behind a link.`);
            }
        }
        for (const g of GIT_GUARDED) {
            addRoOverlay(join(real, g.rel), `${g.rel} of ${label}, read-only`, g.create ? { dir: g.dir, ...(g.content !== undefined && { content: g.content }) } : undefined, real);
        }
        checkAlternates(join(real, "objects"), depth > 0 ? realOrUndefined(real) ?? real : undefined);
        // Other worktrees' admin dirs (HEAD, gitdir, commondir, config, hooks ...) belong to them.
        let siblings: string[] = [];
        try { siblings = readdirSync(join(real, "worktrees")); } catch { /* none */ }
        for (const name of siblings) {
            const sibling = join(real, "worktrees", name);
            if (own !== undefined && realOrUndefined(sibling) === own) continue;
            if (isDir(sibling)) addRoOverlay(sibling, `worktree ${name} of ${label}, read-only`, undefined, real);
        }
        if (depth >= 4) return;
        let modules: string[] = [];
        try { modules = readdirSync(join(real, "modules")); } catch { /* none */ }
        for (const name of modules) {
            const module = join(real, "modules", name);
            let link = false;
            try { link = lstatSync(join(real, "modules")).isSymbolicLink() || lstatSync(module).isSymbolicLink(); } catch { /* gone */ }
            if (link) {
                deny(module, "refused: a symbolic link inside a git directory cannot be protected", `modules of ${label}`);
                throw new ReadConfinementError(`${module} is (or lies below) a symbolic link inside the git directory ${real}. Remove it; the sandbox cannot protect or create paths below a link.`);
            }
            if (!isDir(module)) continue;
            if (isFile(join(module, "HEAD"))) guardGitDir(module, `submodule ${name} of ${label}`, undefined, depth + 1);
            else if (isDir(join(module, "modules"))) guardGitDir(module, `submodule ${name} of ${label}`, undefined, depth + 1);
        }
    };
    const bindGitDir = (real: string, via: string, own?: string): boolean => {
        if (!addBind(real, "rw", via, dotGit)) return false;
        gitDirs.push(real);
        writeRoots.add(real);
        guardGitDir(real, via, own);
        walk(real, 1);
        return true;
    };
    try {
        if (lstatSync(dotGit).isFile()) {
            // The `.git` file itself is read-only in the sandbox (rename and unlink fail with EBUSY, the project
            // root being the mount point that anchors it), so the redirect cannot change under a running session.
            addRoOverlay(dotGit, ".git file of the project, read-only");
            const match = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, "utf8"));
            const candidate = match ? resolve(project, match[1]!.trim()) : undefined;
            const real = candidate ? realOrUndefined(candidate) : undefined;
            // A target the agent can write is a target the agent can forge: refuse it instead of trusting it.
            const refuseWritable = (target: string, what: string): void => {
                const root = writableOverlap(target);
                if (root === undefined) return;
                const reason = `refused: ${what} lies inside or around the writable root ${root}`;
                deny(target, reason, dotGit);
                throw new ReadConfinementError(`${dotGit} points to ${target}: ${reason.replace("refused: ", "")}. A git dir the agent can write cannot be trusted; place it outside every writable root.`);
            };
            if (!candidate) skip(dotGit, "no gitdir: line");
            else if (!real) skip(candidate, "git dir not found");
            else {
                refuseWritable(real, "the .git redirect target");
                if (!isFile(join(real, "HEAD"))) deny(real, "refused: .git redirect target is not a git dir (no HEAD)", dotGit);
                else if (!belongsToProject(real)) deny(real, "refused: .git redirect target does not point back to this worktree", dotGit);
                else if (bindGitDir(real, "git dir of worktree", real)) {
                    const dirs = [real];
                    const commonText = readText(join(real, "commondir"))?.trim();
                    const common = commonText ? realOrUndefined(resolve(real, commonText)) : undefined;
                    if (commonText && !common) skip(resolve(real, commonText), "git common dir not found", real);
                    else if (common && common !== real) {
                        refuseWritable(common, "the commondir");
                        if (!isFile(join(common, "HEAD")) || !isDir(join(common, "objects")) || !contains(join(common, "worktrees"), real)) {
                            deny(common, "refused: commondir is not the common git dir of this worktree", real);
                        } else if (bindGitDir(common, "common git dir of worktree", real)) dirs.push(common);
                    }
                    gitFile = { path: dotGit, dirs };
                }
            }
        }
        else if (lstatSync(dotGit).isDirectory()) {
            gitDirs.push(realpathSync.native(dotGit));
            guardGitDir(realpathSync.native(dotGit), "git dir of the project", undefined);
        }
    } catch (error) {
        if (error instanceof ReadConfinementError) throw error;
        /* not a git checkout */
    }
    // The project's own symlinks (and those below the project's git dir if it is inside).
    walk(project, 0);

    // ---- the policy file must not be agent-writable -----------------------
    if (isAbsolute(loaded.source)) {
        const realSource = realOrUndefined(loaded.source) ?? loaded.source;
        const scratch = [tmpdir(), "/tmp", "/var/tmp", "/dev/shm"].map((root) => realOrUndefined(root) ?? root);
        const extra = extraWritable;
        const exposed = [...writeRoots, ...(persistentReal ? [persistentReal] : []), ...scratch, ...extra].find((root) => contains(root, realSource));
        if (exposed) {
            throw new ReadConfinementError(`the policy file ${realSource} is inside ${exposed}, which the sandboxed agent can write or the project owns; move it outside the project, writable roots and temp directories.`);
        }
    }

    // ---- read-only paths (policy `readOnly`) -----------------------------
    const approvedLocations: string[] = [...runtimeReal];
    for (const entry of policy.readOnly ?? []) {
        const via = "readOnly";
        const expanded = expandPath(entry, home, env);
        if (!expanded) { skip(entry, "path variable is unset or path is relative", via); continue; }
        const real = realOrUndefined(expanded);
        if (!real) { skip(expanded, "not found", via); continue; }
        const dir = statSync(real).isDirectory();
        const why = denyMatch(expanded, false) ?? denyMatch(real, dir);
        if (why) { deny(real, why, via); continue; }
        const containing = [...writeRoots].find((root) => contains(real, root));
        if (containing) { deny(real, `refused: readOnly path contains the writable root ${containing}`, via); continue; }
        // A read-only mount cannot be laid over what is writable anyway, and must never count as an approved location.
        const writableRoot = [...writeRoots, ...extraWritable, ...(persistentReal ? [persistentReal] : [])].find((root) => contains(root, real) || contains(real, root));
        if (writableRoot) { deny(real, `refused: readOnly path lies inside or around the writable root ${writableRoot}`, via); continue; }
        // /tmp in the sandbox is a private tmpfs: a bind there would replace it with host files or hide the scratch space.
        const scratch = realOrUndefined("/tmp") ?? "/tmp";
        if (contains(scratch, real) || contains(real, scratch)) { deny(real, `refused: readOnly path overlaps the sandbox's private ${scratch}`, via); continue; }
        if (covered(real)) { skip(real, "already readable or writable through the project or another bind", via); approvedLocations.push(real); continue; }
        // The path itself is resolved as the kernel would; symlinks inside a shared folder are not followed.
        const resolvedReal = resolveChain(expanded, via);
        if (resolvedReal !== undefined && addBind(resolvedReal, "ro", `read-only path from policy readOnly (${entry})`, via)) approvedLocations.push(resolvedReal);
    }

    // ---- approved tools --------------------------------------------------
    const pathDirs = (env.PATH ?? "").split(delimiter).filter((entry) => isAbsolute(entry));
    const lookup = (name: string): string | undefined => {
        for (const dir of pathDirs) {
            const candidate = join(dir, name);
            if (isExecutableFile(candidate)) return candidate;
        }
        return undefined;
    };
    const defaults = policy.tools?.builtinDefaults === false ? {} : BUILTIN_TOOL_DEFAULTS;
    const resolved = new Map<string, ToolSpec & { real: string }>();
    const queue: ToolSpec[] = [];

    // ---- limited wildcards (single-segment `*`, expanded now, every match checked and audited) ----
    const maxMatches = limits.maxWildcardMatches ?? DEFAULT_MAX_WILDCARD_MATCHES;
    const wildcardAudit: NonNullable<ReadConfinementAudit["wildcards"]> = [];
    for (const entry of policy.tools?.approved ?? []) {
        if (typeof entry === "object") for (const bind of entry.bind ?? []) {
            const expanded = expandPath(bind, home, env);
            const real = expanded ? realOrUndefined(expanded) : undefined;
            if (real && !denyMatch(real, statSync(real).isDirectory())) approvedLocations.push(real);
        }
    }
    const wildcardMatcher = (segment: string): RegExp => new RegExp(`^${segment.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*")}$`);
    /** Expand `pattern` against the filesystem; throws when it would exceed the match cap. */
    const expandWildcard = (pattern: string): string[] => {
        let current: string[] = [sep];
        for (const segment of pattern.split(sep).filter(Boolean)) {
            const next: string[] = [];
            const matcher = segment.includes("*") ? wildcardMatcher(segment) : undefined;
            for (const base of current) {
                if (!matcher) { const candidate = join(base, segment); if (existsSync(candidate)) next.push(candidate); continue; }
                let names: string[] = [];
                try { names = readdirSync(base).sort(); } catch { continue; }
                for (const name of names) {
                    // As in a shell, `*` does not match a leading dot.
                    if (matcher.test(name) && (segment.startsWith(".") || !name.startsWith("."))) next.push(join(base, name));
                }
            }
            if (next.length > maxMatches) {
                throw new ReadConfinementError(`wildcard ${pattern} matches more than ${maxMatches} paths (policy limits.maxWildcardMatches); narrow the pattern or raise the cap.`);
            }
            current = next;
        }
        return current;
    };
    /** Accepted matches of one pattern; every match is recorded, and one outside approved/bound locations is denied. */
    const acceptedMatches = (pattern: string, kind: "approvedPathDir" | "toolPath", via: string): string[] => {
        const record: NonNullable<ReadConfinementAudit["wildcards"]>[number] = { pattern, kind, matches: [] };
        wildcardAudit.push(record);
        const accepted: string[] = [];
        for (const match of expandWildcard(pattern)) {
            const real = realOrUndefined(match);
            if (!real) { record.matches.push({ path: match, accepted: false, reason: "not resolvable" }); continue; }
            const location = approvedLocations.find((root) => contains(root, real));
            if (!location) {
                const reason = "refused: wildcard match is not inside an approved or bound location (readOnly path, tool bind or runtime root)";
                record.matches.push({ path: match, real, accepted: false, reason });
                deny(real, reason, via);
                continue;
            }
            record.matches.push({ path: match, real, accepted: true });
            accepted.push(match);
        }
        if (!record.matches.length) skip(pattern, "wildcard matched nothing", via);
        return accepted;
    };

    for (const entry of policy.tools?.approved ?? []) {
        const spec: ReadConfinementTool = typeof entry === "string" ? (entry.startsWith("/") ? { path: entry } : { name: entry }) : entry;
        const candidates: ReadConfinementTool[] = spec.path?.includes("*")
            ? acceptedMatches(spec.path, "toolPath", "approved tool path").map((match) => ({ ...spec, path: match }))
            : [spec];
        for (const one of candidates) {
            const name = one.name ?? basename(one.path!);
            const lexical = one.path ?? lookup(name);
            if (!lexical || !isExecutableFile(lexical)) { skip(one.path ?? name, "approved tool not found on PATH"); continue; }
            const builtin = defaults[name];
            queue.push({ name, lexical, implicit: false, spec: { ...(builtin && one.config === undefined ? { config: builtin.config } : {}), ...one } });
        }
    }
    for (const patternEntry of policy.tools?.approvedPathDirs ?? []) {
        const dirEntries = patternEntry.includes("*") ? acceptedMatches(patternEntry, "approvedPathDir", "approved PATH directory") : [patternEntry];
        for (const dirEntry of dirEntries) {
            const realDir = realOrUndefined(dirEntry);
            if (!realDir) { skip(dirEntry, "approved PATH directory not found"); continue; }
            if (!pathDirs.some((dir) => realOrUndefined(dir) === realDir)) { skip(dirEntry, "approved PATH directory is not on the launching PATH"); continue; }
            for (const name of readdirSync(realDir).sort()) {
                const lexical = join(dirEntry, name);
                const builtin = defaults[name];
                if (isExecutableFile(lexical)) queue.push({ name, lexical, implicit: false, spec: { name, ...(builtin ? { config: builtin.config } : {}) } });
            }
        }
    }

    const bindLibraries = (real: string, via: string): void => {
        for (const lib of (seams.listLibraries ?? loaderListLibraries)(real)) {
            if (isAbsolute(lib)) bindResolved(lib, via, 1, `library of ${via}`);
        }
    };

    const bindExtra = (entry: string, reason: string): void => {
        const expanded = expandPath(entry, home, env);
        if (!expanded) { skip(entry, "path variable is unset or path is relative", reason); return; }
        if (!existsSync(expanded)) { skip(expanded, "not found", reason); return; }
        bindResolved(expanded, reason, 1, reason);
    };

    const processTool = (tool: ToolSpec, depth: number): void => {
        if (resolved.has(tool.name)) return;
        const real = realOrUndefined(tool.lexical);
        if (!real) { skip(tool.lexical, "approved tool not resolvable"); return; }
        const why = denyMatch(real, false);
        if (why) { deny(real, why, `approved tool ${tool.name}`); return; }
        // A tool the agent can write is a tool the agent can replace.
        const writable = [...writeRoots, ...(persistentReal ? [persistentReal] : [])].find((root) => contains(root, real));
        if (writable) { deny(real, `refused: approved tool resolves under writable root ${writable}`, `approved tool ${tool.name}`); return; }
        if (!covered(real)) {
            if (tool.spec.install === "prefix") {
                const bin = dirname(real);
                const prefix = /^s?bin$/.test(basename(bin)) ? dirname(bin) : bin;
                const depth = prefix.split(sep).filter(Boolean).length;
                const refusal = depth < limits.minPrefixDepth ? `shallower than ${limits.minPrefixDepth} levels (policy limits.minPrefixDepth)`
                    : contains(prefix, home) || contains(prefix, project) || contains(home, prefix) || writeRoots.has(prefix)
                        || [...writeRoots].some((root) => contains(prefix, root)) ? "contains or lies in the home, the project or a writable root"
                    : undefined;
                if (refusal) { deny(prefix, `refused: install prefix ${refusal}`, `approved tool ${tool.name}`); return; }
                if (!addBind(prefix, "ro", `install prefix of ${tool.name}`, real)) return;
            } else if (!addBind(real, "ro", `approved tool ${tool.name}`)) return;
        }
        resolved.set(tool.name, { ...tool, real });
        let head: Buffer;
        try { head = readHead(real, 256); } catch { head = Buffer.alloc(0); }
        if (head.length > 2 && head[0] === 0x23 && head[1] === 0x21 && depth < 5) {
            const parts = head.toString("utf8").split("\n")[0]!.slice(2).trim().split(/\s+/);
            const interpreter = parts[0];
            if (interpreter && isAbsolute(interpreter)) {
                bindResolved(interpreter, real, 1, `interpreter of ${tool.name}`);
                const interpreterReal = realOrUndefined(interpreter);
                if (interpreterReal && elfInterpreter(interpreterReal)) bindLibraries(interpreterReal, interpreter);
                if (basename(interpreter) === "env") {
                    const target = parts.slice(1).find((arg) => !arg.startsWith("-") && !arg.includes("="));
                    const found = target && !target.includes("/") ? lookup(target) : undefined;
                    if (found) processTool({ name: target!, lexical: found, implicit: true, spec: { name: target! } }, depth + 1);
                    else if (target) skip(target, "interpreter not found on PATH", real);
                }
            }
        }
        if (elfInterpreter(real)) bindLibraries(real, real);
        for (const extra of tool.spec.bind ?? []) bindExtra(extra, `bind of ${tool.name}`);
    };

    for (const tool of queue) processTool(tool, 0);

    // ---- configs, caches -------------------------------------------------
    const detectors = [
        ...(policy.secretDetector?.useDefaults === false ? [] : DEFAULT_SECRET_PATTERNS),
        ...(policy.secretDetector?.patterns ?? []),
    ].map((pattern) => ({ pattern, regex: compilePattern(pattern, "secret pattern") }));
    const maxScanBytes = policy.secretDetector?.maxScanBytes ?? 1 << 20;
    const maxScanFiles = policy.secretDetector?.maxScanFiles ?? 2000;
    const scanForSecrets = (root: string): string | undefined => {
        let files = 0;
        const visited = new Set<string>();
        const visit = (path: string): string | undefined => {
            const real = realOrUndefined(path);
            if (!real || visited.has(real)) return undefined;
            visited.add(real);
            const info = statSync(real);
            if (info.isDirectory()) {
                for (const name of readdirSync(real).sort()) {
                    const hit = visit(join(real, name));
                    if (hit) return hit;
                }
                return undefined;
            }
            if (!info.isFile()) return undefined;
            if (++files > maxScanFiles) throw new ReadConfinementError(`config entry ${root} has more than ${maxScanFiles} files to scan (policy secretDetector.maxScanFiles).`);
            if (info.size > maxScanBytes) return `${real} is larger than the scan limit of ${maxScanBytes} bytes (policy secretDetector.maxScanBytes)`;
            const text = readHead(real, Math.max(info.size, 1)).toString("latin1");
            const found = detectors.find((d) => d.regex.test(text));
            return found ? `${real} matches secret pattern ${JSON.stringify(found.pattern)}` : undefined;
        };
        return visit(root);
    };

    for (const tool of resolved.values()) {
        if (tool.implicit && !tool.spec.config && !tool.spec.cache) continue;
        for (const entry of tool.spec.config ?? []) {
            const via = `config of ${tool.name}`;
            const expanded = expandPath(entry, home, env);
            if (!expanded) { skip(entry, "path variable is unset", via); continue; }
            const real = realOrUndefined(expanded);
            if (!real) { skip(expanded, "not found", via); continue; }
            const why = denyMatch(expanded, false) ?? denyMatch(real, statSync(real).isDirectory());
            if (why) { deny(real, why, via); continue; }
            const secret = scanForSecrets(real);
            if (secret) { deny(real, `secret detected: ${secret}`, via); continue; }
            bindResolved(expanded, via, 1, via);
        }
        for (const entry of tool.spec.cache ?? []) {
            const via = `cache of ${tool.name}`;
            const expanded = expandPath(entry, home, env);
            if (!expanded) { skip(entry, "path variable is unset", via); continue; }
            const why = denyMatch(realOrUndefined(expanded) ?? expanded, true);
            if (why) { deny(expanded, why, via); continue; }
            if (tool.spec.cachePersistent) {
                if (!persistentBase) { skip(expanded, "persistent cache requested but policy caches.persistentDir is unset", tool.name); continue; }
                const source = join(persistentBase, seams.agentId ?? "agent", `${tool.name}-${createHash("sha256").update(expanded).digest("hex").slice(0, 10)}`);
                mkdirSync(source, { recursive: true });
                const realSource = realpathSync.native(source);
                bound.set(expanded, { path: expanded, mode: "rw", dir: true, reason: `persistent cache of ${tool.name}`, source: realSource });
                // In-process tools see the per-agent directory the sandbox maps there, never the host path.
                writeRoots.add(realSource);
                cacheSources.add(realSource);
            } else {
                bound.set(expanded, { path: expanded, mode: "tmpfs", dir: true, reason: `private cache of ${tool.name}` });
            }
        }
    }

    // ---- synthetic PATH --------------------------------------------------
    const mount = policy.syntheticPathMount ?? "/run/pi-confined/bin";
    let syntheticDir: string | undefined;
    const syntheticTools = [...resolved.values()].sort((a, b) => a.name < b.name ? -1 : 1);
    if (syntheticTools.length) {
        syntheticDir = (seams.makeSyntheticDir ?? (() => mkdtempSync(join(tmpdir(), "pi-confined-path-"))))();
        for (const tool of syntheticTools) symlinkSync(tool.real, join(syntheticDir, tool.name));
    }

    // ---- mount anchors ---------------------------------------------------
    // A read-only overlay under a writable directory is not enough: the directory itself could be renamed
    // away and rebuilt without the overlay. Every directory between a writable region's root and a
    // write-denied entry or a nested writable git dir becomes a mount point (self-bind): rename and
    // rmdir of it fail with EBUSY. Computed from the deny list, not a fixed list of git paths.
    const anchors = new Set<string>();
    const regionRoots = [...writeRoots].sort((a, b) => b.length - a.length);
    for (const path of [...denyWriteSet, ...[...writeRoots].filter((root) => root !== project)]) {
        const region = regionRoots.find((root) => root !== path && contains(root, path));
        if (region === undefined) continue;
        for (let dir = dirname(path); dir !== region && contains(region, dir); dir = dirname(dir)) anchors.add(dir);
    }
    for (const dir of anchors) {
        if (bound.has(dir) || !isDir(dir) || denyMatch(dir, true)) continue;
        bound.set(dir, { path: dir, mode: "rw", dir: true, reason: "mount anchor: protected overlays below cannot be renamed away", late: contains(project, dir) });
    }
    const denyRemove = [...new Set([...anchors, ...[...writeRoots].filter((root) => root !== project && !cacheSources.has(root))])].sort();

    // ---- render ----------------------------------------------------------
    const entries = [...bound.values()].sort((a, b) => a.path.length - b.path.length);
    const args: string[] = [];
    // Overlays inside the project must come after the project's own writable bind (added by the launcher).
    const overlayArgs: string[] = [];
    for (const b of entries.filter((e) => e.late)) overlayArgs.push(b.mode === "rw" ? "--bind" : "--ro-bind", b.source ?? b.path, b.path);
    for (const b of entries.filter((e) => !e.late)) {
        if (b.mode === "tmpfs") args.push("--tmpfs", b.path);
        else if (b.mode === "rw") args.push("--bind", b.source ?? b.path, b.path);
        else args.push("--ro-bind", b.source ?? b.path, b.path);
    }
    for (const [path, text] of [...symlinkMounts].sort(([a], [b]) => a.length - b.length)) args.push("--symlink", text, path);
    if (syntheticDir) args.push("--ro-bind", syntheticDir, mount);
    const pathValue = syntheticDir ? mount : "/nonexistent-pi-confined";
    const envAllow = [...new Set([...DEFAULT_ENV_ALLOW, ...(policy.env?.allow ?? [])])].sort();
    args.push("--setenv", "PATH", pathValue);
    // Other allowlisted names are copied from the launching process when each command is built
    // (see `sandbox-core`), so per-command values such as TERM or TMPDIR stay current.

    const hardening = resolveHardening(policy.hardening);
    const hardeningSeams: SandboxSeams = { ...(seams.hardening ?? {}), env };
    const hardeningBwrap = bubblewrapExecutable(hardeningSeams);
    const readRoots = [...new Set([project, ...cacheSources, ...entries.filter((b) => b.mode !== "tmpfs" && !b.source).map((b) => b.path)])].sort();
    const audit: ReadConfinementAudit = {
        version: 1,
        policy: { source: loaded.source, sha256: loaded.sha256 },
        project,
        gitDirs: [...new Set(gitDirs)],
        binds: [{ path: project, mode: "rw", kind: "dir", reason: "project root" },
            ...entries.map((b): ReadConfinementAudit["binds"][number] => ({ path: b.path, mode: b.mode, kind: b.dir ? "dir" : "file", reason: b.reason }))],
        symlinkMounts: [...symlinkMounts].map(([path, text]) => ({ path, text })),
        denied,
        skipped,
        syntheticPath: syntheticDir ? { mount, tools: syntheticTools.map((t) => ({ name: t.name, target: t.real, implicit: t.implicit })) } : undefined,
        limits,
        ...(wildcardAudit.length ? { wildcards: wildcardAudit } : {}),
        symlinksFollowed,
        envAllow,
        denyWrite: [...denyWriteSet].sort(),
        hardening: { ...hardeningStates(hardening, hardeningBwrap, hardeningSeams), hostname: hardening.hostname },
    };
    return {
        args,
        readRoots,
        writeRoots: [...writeRoots].sort(),
        denyWrite: audit.denyWrite,
        overlayArgs,
        denyRemove,
        ...(gitFile && { gitFile }),
        audit,
        project,
        envAllow,
        pathValue,
        hardening,
        hash: createHash("sha256").update(JSON.stringify(audit)).digest("hex"),
        syntheticDir,
    };
}

/** Human summary for the diagnostics command. */
export function formatReadConfinementAudit(audit: ReadConfinementAudit, hash?: string): string {
    const lines = [
        `Read confinement: project ${audit.project}`,
        `  policy ${audit.policy.source} sha256:${audit.policy.sha256.slice(0, 12)}${hash ? ` · plan ${hash.slice(0, 12)}` : ""}`,
        `  binds (${audit.binds.length}):`,
        ...audit.binds.map((b) => `    ${b.mode.padEnd(5)} ${b.path} — ${b.reason}`),
    ];
    if (audit.symlinkMounts.length) lines.push(`  symlink mounts (${audit.symlinkMounts.length}):`, ...audit.symlinkMounts.map((s) => `    ${s.path} -> ${s.text}`));
    if (audit.denied.length) lines.push(`  denied (${audit.denied.length}):`, ...audit.denied.map((d) => `    ${d.path} — ${d.reason}${d.via ? ` (via ${d.via})` : ""}`));
    if (audit.skipped.length) lines.push(`  skipped (${audit.skipped.length}):`, ...audit.skipped.map((d) => `    ${d.path} — ${d.reason}${d.via ? ` (via ${d.via})` : ""}`));
    lines.push(...formatHardening(audit.hardening).map((line) => `  ${line}`));
    lines.push(audit.syntheticPath
        ? `  PATH ${audit.syntheticPath.mount}: ${audit.syntheticPath.tools.map((t) => t.name + (t.implicit ? "*" : "")).join(" ")} (* = needed interpreter)`
        : "  PATH: empty (no approved tools)");
    return lines.join("\n");
}

/** One line per hardening measure: on, off by policy, or unavailable with its reason. */
export function formatHardening(hardening: ReadConfinementHardeningAudit): string[] {
    return ["hardening:", ...HARDENING_MEASURES.map((measure) => {
        const state = hardening[measure];
        const text = state.state === "on" ? "on" : state.state === "off" ? "off by policy" : `unavailable (inactive, launches fail closed) — ${state.reason}`;
        return `  ${measure}: ${text}${measure === "uts" && state.state === "on" ? ` (hostname ${hardening.hostname})` : ""}`;
    })];
}
