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
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, resolve, sep } from "node:path";

import { credentialFilePaths, RUNTIME_ROOTS, type ReadConfinementMounts } from "./index.ts";

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
    limits?: { maxSymlinks?: number; maxDepth?: number; maxWalkEntries?: number; maxBinds?: number };
    /** Directory base names never descended into by the symlink walk. */
    walkSkipDirNames?: string[];
    deny?: { paths?: string[]; credentialList?: boolean; otherHomes?: boolean };
    tools?: { approved?: (string | ReadConfinementTool)[]; approvedPathDirs?: string[]; builtinDefaults?: boolean };
    secretDetector?: { useDefaults?: boolean; patterns?: string[]; maxScanBytes?: number; maxScanFiles?: number };
    caches?: { persistentDir?: string };
    /** Where the synthetic PATH directory appears inside the sandbox. */
    syntheticPathMount?: string;
    /** How long a computed plan may be reused, in ms. 0 recomputes on every launch. */
    planTtlMs?: number;
};

const DEFAULT_LIMITS = { maxSymlinks: 2000, maxDepth: 8, maxWalkEntries: 200_000, maxBinds: 500 };
/** Generic secret shapes; `(?i)` prefix = case-insensitive. Replaceable via `secretDetector.useDefaults: false`. */
export const DEFAULT_SECRET_PATTERNS: readonly string[] = Object.freeze([
    "-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "\\bAKIA[0-9A-Z]{16}\\b",
    "\\bgh[pousr]_[A-Za-z0-9]{30,}\\b",
    "_authToken\\s*=",
    "\\bxox[abprs]-[A-Za-z0-9-]{10,}\\b",
    "(?i)(password|passwd|secret|api[_-]?key|token)\\s*[=:]\\s*\\S{8,}",
]);
/** Generic widely standard locations; removable with `tools.builtinDefaults: false` or overridden per tool. */
export const BUILTIN_TOOL_DEFAULTS: Readonly<Record<string, ReadConfinementTool>> = Object.freeze({
    git: { name: "git", config: ["~/.gitconfig", "${XDG_CONFIG_HOME}/git", "~/.config/git"] },
});

function fail(path: string, message: string): never {
    throw new Error(`Invalid read-confinement policy at ${path}: ${message}`);
}

function checkKeys(value: unknown, path: string, allowed: readonly string[]): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(path, "expected an object");
    for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${path}.${key}`, "unknown key");
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
    const root = checkKeys(value, "$", ["version", "limits", "walkSkipDirNames", "deny", "tools", "secretDetector", "caches", "syntheticPathMount", "planTtlMs"]);
    if (root.version !== 1) fail("$.version", "must be 1");
    const policy: ReadConfinementPolicy = { version: 1 };
    if (root.limits !== undefined) {
        const l = checkKeys(root.limits, "$.limits", ["maxSymlinks", "maxDepth", "maxWalkEntries", "maxBinds"]);
        policy.limits = {};
        for (const key of ["maxSymlinks", "maxDepth", "maxWalkEntries", "maxBinds"] as const) {
            const n = count(l[key], `$.limits.${key}`);
            if (n !== undefined) policy.limits[key] = n;
        }
    }
    const skip = stringList(root.walkSkipDirNames, "$.walkSkipDirNames");
    if (skip) policy.walkSkipDirNames = skip;
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
        dirs?.forEach((entry, i) => { if (!isAbsolute(entry)) fail(`$.tools.approvedPathDirs[${i}]`, "must be absolute"); });
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
    const ttl = count(root.planTtlMs, "$.planTtlMs", 0);
    if (ttl !== undefined) policy.planTtlMs = ttl;
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
};

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
    limits: { maxSymlinks: number; maxDepth: number; maxWalkEntries: number; maxBinds: number };
    symlinksFollowed: number;
};

export type ReadConfinementPlan = ReadConfinementMounts & {
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

type Bound = { path: string; mode: "ro" | "rw" | "tmpfs"; dir: boolean; reason: string; source?: string };
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
    let symlinksFollowed = 0;
    let walked = 0;
    const walkedDirs = new Set<string>();

    // ---- deny list -------------------------------------------------------
    const denyEntries = new Set<string>();
    const addDeny = (path: string): void => {
        denyEntries.add(resolve(path));
        const real = realOrUndefined(path);
        if (real) denyEntries.add(real);
    };
    if (policy.deny?.credentialList !== false) {
        for (const entry of credentialFilePaths(home)) addDeny(entry);
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
    const writeRoots = new Set<string>([project]);
    const gitDirCandidates: string[] = [];
    try {
        const dotGit = join(project, ".git");
        if (lstatSync(dotGit).isFile()) {
            const match = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, "utf8"));
            if (match) gitDirCandidates.push(resolve(project, match[1]!.trim()));
        }
    } catch { /* not a git checkout */ }
    for (const candidate of [...gitDirCandidates]) {
        const real = realOrUndefined(candidate);
        if (!real) continue;
        try {
            const common = readFileSync(join(real, "commondir"), "utf8").trim();
            if (common) gitDirCandidates.push(resolve(real, common));
        } catch { /* a plain gitdir */ }
    }
    for (const candidate of gitDirCandidates) {
        const real = realOrUndefined(candidate);
        if (!real) { skip(candidate, "git dir not found"); continue; }
        if (contains(project, real)) { gitDirs.push(real); continue; }
        if (!addBind(real, "rw", "git dir of worktree")) continue;
        gitDirs.push(real);
        writeRoots.add(real);
        try {
            for (const line of readFileSync(join(real, "objects", "info", "alternates"), "utf8").split("\n")) {
                const alt = line.trim();
                if (alt && isAbsolute(alt)) bindResolved(alt, join(real, "objects/info/alternates"), 1, "git alternates");
            }
        } catch { /* no alternates */ }
        walk(real, 1);
    }
    // The project's own symlinks (and those below the project's git dir if it is inside).
    walk(project, 0);

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
    for (const entry of policy.tools?.approved ?? []) {
        const spec: ReadConfinementTool = typeof entry === "string" ? (entry.startsWith("/") ? { path: entry } : { name: entry }) : entry;
        const name = spec.name ?? basename(spec.path!);
        const lexical = spec.path ?? lookup(name);
        if (!lexical || !isExecutableFile(lexical)) { skip(spec.path ?? name, "approved tool not found on PATH"); continue; }
        const builtin = defaults[name];
        queue.push({ name, lexical, implicit: false, spec: { ...(builtin && spec.config === undefined ? { config: builtin.config } : {}), ...spec } });
    }
    for (const dirEntry of policy.tools?.approvedPathDirs ?? []) {
        const realDir = realOrUndefined(dirEntry);
        if (!realDir) { skip(dirEntry, "approved PATH directory not found"); continue; }
        if (!pathDirs.some((dir) => realOrUndefined(dir) === realDir)) { skip(dirEntry, "approved PATH directory is not on the launching PATH"); continue; }
        for (const name of readdirSync(realDir).sort()) {
            const lexical = join(dirEntry, name);
            const builtin = defaults[name];
            if (isExecutableFile(lexical)) queue.push({ name, lexical, implicit: false, spec: { name, ...(builtin ? { config: builtin.config } : {}) } });
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
        if (!covered(real)) {
            if (tool.spec.install === "prefix") {
                const bin = dirname(real);
                const prefix = /^s?bin$/.test(basename(bin)) ? dirname(bin) : bin;
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
            const text = readHead(real, maxScanBytes).toString("latin1");
            const found = detectors.find((d) => d.regex.test(text));
            return found ? `${real} matches secret pattern ${JSON.stringify(found.pattern)}` : undefined;
        };
        return visit(root);
    };

    const persistentBase = policy.caches?.persistentDir ? expandPath(policy.caches.persistentDir, home, env) : undefined;
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
                bound.set(expanded, { path: expanded, mode: "rw", dir: true, reason: `persistent cache of ${tool.name}`, source: realpathSync.native(source) });
                writeRoots.add(expanded);
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

    // ---- render ----------------------------------------------------------
    const entries = [...bound.values()].sort((a, b) => a.path.length - b.path.length);
    const args: string[] = [];
    for (const b of entries) {
        if (b.mode === "tmpfs") args.push("--tmpfs", b.path);
        else if (b.mode === "rw") args.push("--bind", b.source ?? b.path, b.path);
        else args.push("--ro-bind", b.path, b.path);
    }
    for (const [path, text] of [...symlinkMounts].sort(([a], [b]) => a.length - b.length)) args.push("--symlink", text, path);
    if (syntheticDir) args.push("--ro-bind", syntheticDir, mount);
    args.push("--setenv", "PATH", syntheticDir ? mount : "/nonexistent-pi-confined");

    const readRoots = [...new Set([project, ...entries.filter((b) => b.mode !== "tmpfs").map((b) => b.path)])].sort();
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
        symlinksFollowed,
    };
    return {
        args,
        readRoots,
        writeRoots: [...writeRoots].sort(),
        audit,
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
    lines.push(audit.syntheticPath
        ? `  PATH ${audit.syntheticPath.mount}: ${audit.syntheticPath.tools.map((t) => t.name + (t.implicit ? "*" : "")).join(" ")} (* = needed interpreter)`
        : "  PATH: empty (no approved tools)");
    return lines.join("\n");
}
