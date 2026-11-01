/**
 * OS-level write sandbox mechanism shared by Pi extensions.
 *
 * Legacy policies are write-only: a sandboxed process may READ anywhere and use
 * the network, but may only WRITE under a canonical root plus runtime paths.
 * Optional permissions add capability restrictions for reads, writes, launches
 * and network access. They cover known credential files, not OS keychains,
 * credential services, or tokens inherited in the child environment.
 *
 * This module owns the mechanism only: backend discovery, canonical path
 * containment, write-deny compilation, macOS SBPL profile construction, Linux
 * Bubblewrap mount construction, ordered executable/argv wrapping, and support
 * diagnostics. It owns no Pi tool, TUI, background-task, or subagent lifecycle
 * policy — callers decide when a sandbox is requested and what it may write.
 *
 * Every platform/filesystem dependency is reachable through the optional
 * `SandboxSeams` argument so callers can plan deterministically in tests.
 */

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { platform as osPlatform, tmpdir } from "node:os";
import {
    accessSync,
    closeSync,
    constants,
    existsSync,
    lstatSync,
    mkdirSync,
    openSync,
    readdirSync,
    readFileSync,
    readlinkSync,
    realpathSync,
    renameSync,
    statSync,
    unlinkSync,
    writeFileSync,
} from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";

/** Identifies which kernel mechanism a plan will use. */
export type SandboxBackendId = "macos-seatbelt" | "linux-bubblewrap";

/**
 * File access levels for the Project files and Outside project rows.
 *
 * - `off`: no access.
 * - `read`: read only.
 * - `write`: read, create and overwrite in place. Nothing can be removed or
 *   renamed away (unlink, rmdir, rename of an existing entry, or a rename that
 *   replaces one), except in the always-disposable places: temp, hidden (dot)
 *   entries of the home directory, and git worktree folders (`.worktrees/`,
 *   `*-worktrees/`). For Outside project this is the broad-write profile:
 *   writes across home and temp, and the fixed deny list.
 * - `read-write`: "Write & delete" — the historical read/write level.
 */
export type SandboxFileAccess = "off" | "read" | "write" | "read-write";

export type SandboxPermissions = {
    projectFiles: SandboxFileAccess;
    outsideProject: SandboxFileAccess;
    storedCredentials: "off" | "read" | "read-write";
    commands: boolean;
    network: boolean;
    /** Fixed process_list adapter only; omitted legacy profiles keep it Off. */
    processAccess?: "off" | "read";
};

/**
 * A precomputed Linux read-confinement mount plan (see `read-confinement.ts`).
 * It only takes effect with `outsideProject: "off"`. `args` are bubblewrap
 * mount/env arguments inserted after the runtime roots; `readRoots` and
 * `writeRoots` are the canonical allow set the in-process file tools use.
 */
export type ReadConfinementMounts = {
    args: readonly string[];
    readRoots: readonly string[];
    writeRoots: readonly string[];
    /** Canonical project the plan was computed for; a policy for another project is refused. */
    project?: string;
    /** Environment variable names the confined child may inherit (everything else is cleared). */
    envAllow?: readonly string[];
    /** Value forced for PATH (the synthetic approved-tools directory). */
    pathValue?: string;
    /**
     * Paths inside writable git dirs the in-process file tools must refuse to write (hooks, config,
     * alternates, other worktrees ...): the same set the sandbox mounts read-only.
     */
    denyWrite?: readonly string[];
    /**
     * Directories that hold or contain such a read-only overlay inside a writable region. The sandbox makes each a
     * mount point (rename/rmdir fails); the in-process tools refuse to remove or move them (or anything containing them).
     */
    denyRemove?: readonly string[];
    /** Read-only overlays inside the project; mounted after the project's own writable bind. */
    overlayArgs?: readonly string[];
    /**
     * Set when the project's `.git` is a file (linked worktree, submodule): the git dirs it resolves to. A deny entry
     * below that file (`.git/hooks`) names the same thing in each of those dirs, so it is mapped there when compiled.
     */
    gitFile?: { readonly path: string; readonly dirs: readonly string[] };
    /**
     * Confined-launch hardening (see `resolveHardening`). Absent means every measure is on with the default
     * hostname, so a plan that predates the switches is hardened rather than silently weaker.
     */
    hardening?: ResolvedHardening;
    /**
     * Resource limits (see `parseResourcesPolicy`): `command` limits run every confined launch in its own
     * systemd user scope; `tmpSize` sizes the private /tmp. Absent means no limit and an unchanged launch.
     */
    resources?: ResolvedResources;
};

/** The hardening measures a confined launch applies, each with its own policy switch. */
export const HARDENING_MEASURES = ["ipc", "uts", "userns", "keyring", "fds"] as const;
export type HardeningMeasure = (typeof HARDENING_MEASURES)[number];

/** Hostname inside a confined launch when the policy names none. A fixed, generic value. */
export const DEFAULT_HARDENING_HOSTNAME = "sandbox";

/** The policy's `hardening` object as written: every key optional. */
export type HardeningSwitches = { [measure in HardeningMeasure]?: boolean } & { hostname?: string };

/** The effective hardening of a confined launch: every switch decided, the hostname named. */
export type ResolvedHardening = { readonly [measure in HardeningMeasure]: boolean } & { readonly hostname: string };

/** Whether one measure is applied, switched off by the policy, or could not be applied (the launch then fails closed). */
export type HardeningState =
    | { readonly state: "on" }
    | { readonly state: "off" }
    | { readonly state: "unavailable"; readonly reason: string };

/** Every measure is on unless the policy switches it off. */
export function resolveHardening(switches?: HardeningSwitches): ResolvedHardening {
    return Object.freeze({
        ipc: switches?.ipc ?? true,
        uts: switches?.uts ?? true,
        userns: switches?.userns ?? true,
        keyring: switches?.keyring ?? true,
        fds: switches?.fds ?? true,
        hostname: switches?.hostname ?? DEFAULT_HARDENING_HOSTNAME,
    });
}

/** Environment variable naming the read-confinement policy file. Its presence means a profile requires confinement. */
export const READ_CONFINEMENT_POLICY_ENV = "PI_SANDBOX_READ_CONFINEMENT_POLICY";

/**
 * Process-wide read-confinement state. The plan is computed once at launch (see
 * `pi-better-sandbox`) and published here so every actor in this process that
 * launches sandboxed commands (foreground, background tasks, task runtime,
 * subagent launches) applies the same frozen plan, or fails closed. The slot
 * lives on `globalThis` because each package vendors its own copy of this module.
 */
export type ProcessReadConfinement =
    | { readonly state: "active"; readonly mounts: ReadConfinementMounts }
    | { readonly state: "failed"; readonly reason: string };
const PROCESS_READ_CONFINEMENT = Symbol.for("pi-better-harness.sandbox-core.read-confinement.owners");

const DEFAULT_OWNER = Symbol.for("pi-better-harness.sandbox-core.default-owner");

function processSlots(): Map<unknown, ProcessReadConfinement> {
    const holder = globalThis as Record<symbol, Map<unknown, ProcessReadConfinement> | undefined>;
    return (holder[PROCESS_READ_CONFINEMENT] ??= new Map());
}

/**
 * Publish (or, with `undefined`, withdraw) the plan owned by `owner`. Each controller passes
 * itself, so disposing one never clears the plan another still owns; the most recently
 * published live plan is the one in force. Without an owner, `undefined` clears every slot
 * (test reset) and a value is owned by a shared default owner.
 */
export function publishProcessReadConfinement(entry: ProcessReadConfinement | undefined, owner: unknown = DEFAULT_OWNER): void {
    const slots = processSlots();
    if (entry === undefined) {
        if (owner === DEFAULT_OWNER) slots.clear(); else slots.delete(owner);
        return;
    }
    slots.delete(owner); // re-publishing moves the owner to the front
    slots.set(owner, Object.freeze(entry));
}

export function processReadConfinement(): ProcessReadConfinement | undefined {
    return [...processSlots().values()].at(-1);
}

/** Whether any owner still has a published plan. */
export function hasProcessReadConfinement(): boolean {
    return processSlots().size > 0;
}

/**
 * The child environment for a read-confined launch: only allowlisted names from
 * `env`, with PATH forced to the synthetic approved-tools directory. Callers that
 * pass an environment through the wrapped command (for example `env -i K=V`) must
 * filter it with this, or the bubblewrap `--clearenv` is undone from inside.
 */
export function confinedEnvironment(
    mounts: Pick<ReadConfinementMounts, "envAllow" | "pathValue"> | undefined,
    env: Readonly<Record<string, string | undefined>>,
): Record<string, string | undefined> {
    if (!mounts) return { ...env };
    const allowed = new Set(mounts.envAllow ?? []);
    const out: Record<string, string | undefined> = {};
    for (const [key, value] of Object.entries(env)) if (allowed.has(key) && value !== undefined) out[key] = value;
    if (mounts.pathValue !== undefined) out.PATH = mounts.pathValue;
    return out;
}

/** Whether a file access level allows creating and overwriting files. */
export function canWrite(mode: SandboxFileAccess | undefined): boolean {
    return mode === "write" || mode === "read-write";
}

/**
 * What a sandboxed process may write. `writableRoot` and `denyWrite` entries may
 * be relative or contain symlinks; they are canonicalized before use.
 */
export type SandboxWritePolicy = {
    /** The single directory subtree the sandboxed process may write under. */
    writableRoot: string;
    /**
     * Concrete paths that stay non-writable even inside `writableRoot`. A
     * directory entry denies its whole subtree; a file entry denies that file.
     *
     * An entry need not exist. The Linux backend needs a mount point, so it
     * materializes an absent entry as an empty file (see `materializeDenyPath`);
     * an entry that has to be a *directory* must therefore already exist when the
     * command is built. Callers denying their own state directory create it
     * first, which they do anyway to write into it.
     */
    denyWrite?: readonly string[];
    /** Home directory whose `~/.pi` state stays writable on macOS. */
    home: string;
    /** Optional capability profile; omission preserves the original write-only sandbox. */
    permissions?: SandboxPermissions;
    /** Trusted per-launch runtime state, never supplied by model tool arguments. */
    runtimeWrite?: readonly string[];
    /** Bounded historical default runtime directories; inactive without a capability profile. */
    runtimeCompatibility?: boolean;
    /** Linux `outsideProject: "off"` only: extra read-only/writable mounts and the in-process allow set. */
    readConfinement?: ReadConfinementMounts;
};

/** The executable and argv to run inside the sandbox, preserved verbatim. */
export type SandboxTarget = {
    execPath: string;
    execArgs: readonly string[];
};

export type SandboxCommandArgs = SandboxTarget & {
    /** Where the macOS backend writes its generated SBPL profile. */
    profilePath: string;
    policy: SandboxWritePolicy;
    /** Fixed internal helper only: expose its executable in a hidden Linux root. */
    internalHelperExecutable?: boolean;
};

/**
 * The wrapper command to spawn: the backend executable and its full argv.
 * `notices` are lines the caller shows with the launch output, such as a
 * placeholder the Linux backend had to leave in the user's files.
 */
export type SandboxCommand = { file: string; fileArgs: string[]; notices?: string[] };

/** The caller's default-on / explicit-request / opt-out decision. */
export type SandboxRequest = {
    sandboxEnabled: boolean;
    explicitSandbox: boolean;
    /**
     * What this caller's operator can actually do about a missing backend,
     * appended when an explicit request has to be refused. Surfaces differ: a
     * subagent tool takes `sandbox:false`, a foreground session takes
     * `/sandbox off`, so the remedy cannot be stated here.
     */
    remedy?: string;
};

/** Injectable platform and filesystem dependencies. Defaults hit the real OS. */
export type SandboxSeams = {
    /** Defaults to `os.platform()`. */
    platform?: () => string;
    /** Environment read for the read-confinement allowlist. Defaults to `process.env`. */
    env?: NodeJS.ProcessEnv;
    /** Defaults to a PATH scan that stats and access-checks without executing. */
    lookupExecutable?: (name: string) => string | undefined;
    /**
     * Defaults to `fs.realpathSync.native`, which (unlike the JS `realpathSync`)
     * returns the on-disk case of every existing component on a case-insensitive
     * volume, as the kernel sees it. Must throw when the path does not exist.
     */
    canonicalize?: (path: string) => string;
    /** Defaults to `fs.writeFileSync`. */
    writeProfile?: (path: string, contents: string) => void;
    /**
     * Defaults to creating an empty placeholder file for an absent denied path
     * (see `materializeDenyPath`). Returns whether the path exists afterwards.
     * Injected by tests that plan Linux argv for paths that do not exist on the
     * host running them.
     */
    materializeDenyPath?: (path: string) => boolean;
    /** Defaults to /usr/bin/getconf with a minimal environment (macOS only). */
    getconf?: (name: "DARWIN_USER_TEMP_DIR" | "DARWIN_USER_CACHE_DIR") => string | undefined;
    /** Broad-write Linux planning: directory listing (defaults to `readdirSync`). */
    listDirectory?: (path: string) => { name: string; directory: boolean; symlink: boolean }[];
    /** Broad-write Linux planning: existence (defaults to `existsSync`). */
    pathExists?: (path: string) => boolean;
    /** Broad-write Linux planning: whether an existing path is a directory. */
    isDirectory?: (path: string) => boolean;
    /** Broad-write Linux planning: create an absent directory-type deny entry. */
    makeDirectory?: (path: string) => void;
    /** Broad-write Linux planning: empty mode-000 mask sources. */
    maskSources?: (profilePath: string) => { directory: string; file: string };
    /** Confined-launch hardening: the text of `bwrap --help` (defaults to running it once per executable). */
    bwrapHelp?: (bwrap: string) => string | undefined;
    /** Confined-launch hardening: the CPU architecture (defaults to `process.arch`). */
    arch?: string;
    /** Resource limits: decides whether a resource scope with these command limits can be started (a reason when not). Defaults to starting one. */
    commandScopeProbe?: (limits: CommandLimits) => string | undefined;
    /** Resource limits: lets a test fake which user-manager sockets exist. */
    userManagerPathExists?: (path: string) => boolean;
};

/** A policy with every path canonicalized, deduplicated, and ordered. */
export type CompiledSandboxWritePolicy = {
    readonly writableRoot: string;
    readonly denyWrite: readonly string[];
    readonly home: string;
    readonly permissions?: SandboxPermissions;
    readonly credentialPaths?: readonly string[];
    readonly runtimeWrite?: readonly string[];
    readonly compatibilityWrite?: readonly string[];
    /** Present only for the broad-write profile (Outside project = `write`). */
    readonly broad?: CompiledBroadWrite;
    readonly readConfinement?: ReadConfinementMounts;
    /** Deny entries mapped out of a `.git` file into the git dirs it redirects to (see `ReadConfinementMounts.gitFile`). */
    readonly redirectedDeny?: readonly string[];
};

/** The canonical inputs of a broad-write profile. */
export type CompiledBroadWrite = {
    /** Canonical home directory. Writes are allowed under it, minus the deny list. */
    readonly home: string;
    /** Canonical temp roots (writable and removal-allowed). */
    readonly tempRoots: readonly string[];
    /** Canonical removal-allowed roots besides temp, dot entries and worktree folders: a Write & delete workspace and runtime scratch. */
    readonly deleteRoots: readonly string[];
    /** Code that runs later: never writable, removable or renamable. Still readable. */
    readonly codePaths: readonly string[];
};

/** Why a write target is or is not permitted by a compiled policy. */
export type WriteAccessDecision =
    | { allowed: true; path: string }
    | {
          allowed: false;
          path: string;
          reason: "outside-writable-root" | "write-denied" | "permission-denied" | "delete-denied";
          /** The compiled deny entry that matched, for `write-denied` only. */
          deniedBy?: string;
      };

export type ReadAccessDecision =
    | { allowed: true; path: string }
    | { allowed: false; path: string; reason: "read-denied" };

/** What the current platform can enforce, and why it cannot when it cannot. */
export type SandboxSupport =
    | { supported: true; platform: string; backend: SandboxBackendId; executable: string }
    | {
          supported: false;
          platform: string;
          backend: undefined;
          executable: undefined;
          reason: string;
      };

type SandboxBackend = {
    id: SandboxBackendId;
    executable: string;
    buildCommand(args: SandboxCommandArgs, seams: SandboxSeams): SandboxCommand;
};

const MACOS_SANDBOX_EXEC = "/usr/bin/sandbox-exec";

const CREDENTIAL_LOCATIONS = [
    ".ssh", ".aws", ".config/gh", ".config/gcloud", ".azure", ".kube",
    ".docker/config.json", ".npmrc", ".netrc", ".git-credentials", ".pi/agent/auth.json",
] as const;

/** Credential stores added to the Stored credentials row by the broad-write profile. */
const BROAD_CREDENTIAL_LOCATIONS = [
    "Library/Keychains", ".claude/.credentials.json", ".claude.json", ".gnupg",
    ".codex/auth.json", ".cargo/credentials.toml", ".cargo/credentials", ".pgpass", ".config/rclone",
] as const;

/**
 * Code that runs later: shell startup files, agent/harness configuration and
 * login agents. The broad-write profile keeps them readable (skills and
 * extension sources are read by confined tasks) but never writable, removable
 * or renamable. This list is fixed; callers extend it with `denyWrite`.
 */
const CODE_LATER_LOCATIONS = [
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
    ".config/fish", ".config/git", ".gitconfig", ".config/systemd/user", ".config/autostart",
    ".pi", ".claude", ".agents", "Library/LaunchAgents",
    ".local/bin", "bin", ".git-templates", ".oh-my-zsh/custom", ".gradle/init.d",
    ".cargo/config.toml", ".cargo/config",
] as const;

/** Deny-list entries that are directories when they exist (Linux materializes them as such). */
const DIRECTORY_LOCATIONS = new Set([
    ".ssh", ".aws", ".config/gh", ".config/gcloud", ".azure", ".kube", "Library/Keychains",
    ".config/fish", ".config/git", ".config/systemd/user", ".config/autostart",
    ".pi", ".claude", ".agents", "Library/LaunchAgents", ".gnupg", ".config/rclone",
    ".local/bin", "bin", ".git-templates", ".oh-my-zsh/custom", ".gradle/init.d",
]);

const BROAD_TEMP_ROOTS: Record<string, readonly string[]> = {
    darwin: ["/private/tmp", "/private/var/folders", "/private/var/tmp"],
    linux: ["/tmp", "/var/tmp", "/dev/shm"],
};

// Executables, dynamic libraries and OS frameworks needed to start a child.
// This deliberately excludes the home directory, /etc, and credential stores.
// A process relying on /etc or /proc configuration (DNS, certificates, NSS)
// may not start or function under Linux outsideProject=off; callers must not
// silently remount these broad host trees to work around that failure.
export const RUNTIME_ROOTS = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/System/Library", "/System/Cryptexes", "/Library/Apple", "/Library/Developer", "/opt/homebrew"];
const TEMP_ROOTS = ["/private/var/folders", "/private/tmp", "/tmp", "/dev"];
const READ_RUNTIME_ROOTS = [...RUNTIME_ROOTS, "/dev"];

function systemGetconf(name: "DARWIN_USER_TEMP_DIR" | "DARWIN_USER_CACHE_DIR"): string | undefined {
    const result = spawnSync("/usr/bin/getconf", [name], {
        encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C" }, timeout: 3000, maxBuffer: 4096,
    });
    return result.status === 0 ? result.stdout.trim() : undefined;
}

function compatibilityPaths(policy: SandboxWritePolicy, seams: SandboxSeams): string[] {
    if (!policy.permissions || !policy.runtimeCompatibility || policy.permissions.outsideProject === "off") return [];
    const platform = currentPlatform(seams);
    if (platform === "linux") return [canonicalizePath("/tmp", seams)];
    if (platform !== "darwin") return [];
    const home = canonicalizePath(policy.home, seams);
    const project = canonicalizePath(policy.writableRoot, seams);
    const paths = [canonicalizePath("/tmp", seams)];
    for (const [key, leaf] of [["DARWIN_USER_TEMP_DIR", ""], ["DARWIN_USER_CACHE_DIR", "mds"]] as const) {
        const raw = (seams.getconf ?? systemGetconf)(key);
        if (!raw || !raw.startsWith("/") || raw.includes("\0") ||
            raw.split("/").some((part) => part === "." || part === "..")) {
            throw new Error(`Invalid ${key} runtime directory`);
        }
        // getconf returns /var/folders on macOS; /var is a system alias for /private/var.
        const normalized = resolve(raw.replace(/^\/var\/folders\//, "/private/var/folders/"));
        const expected = /^\/private\/var\/folders\/[^/]+\/[^/]+\/[TC]$/.test(normalized) &&
            normalized.endsWith(key === "DARWIN_USER_TEMP_DIR" ? "/T" : "/C");
        const canonical = canonicalizePath(normalized, seams);
        if (!expected || canonical !== normalized ||
            (contains(home, canonical) || contains(canonical, home) || contains(project, canonical))) {
            throw new Error(`Unsafe ${key} runtime directory`);
        }
        paths.push(leaf ? join(canonical, leaf) : canonical);
    }
    // An existing MDS symlink must not redirect the narrow write allowance.
    const mds = paths[2];
    if (!mds || canonicalizePath(mds, seams) !== mds || contains(mds, project) || contains(project, mds)) {
        throw new Error("Unsafe MDS runtime directory");
    }
    return [...new Set(paths)];
}

/** Only known on-disk credentials: keychains, services and inherited env tokens are out of scope. */
export function credentialFilePaths(home: string, seams: SandboxSeams = {}): string[] {
    const paths = CREDENTIAL_LOCATIONS.map((name) => join(home, name));
    const configuredAgentDir = process.env.PI_CODING_AGENT_DIR;
    if (configuredAgentDir) paths.push(join(configuredAgentDir.startsWith("~/")
        ? join(home, configuredAgentDir.slice(2)) : configuredAgentDir, "auth.json"));
    return [...new Set(paths.map((path) => canonicalizePath(path, seams)))].sort();
}

function currentPlatform(seams: SandboxSeams): string {
    return (seams.platform ?? osPlatform)();
}

/**
 * Resolve `path` to an absolute canonical path. Symlinks are resolved on the
 * longest existing ancestor so a target that does not exist yet still
 * canonicalizes through its real parent chain.
 */
export function canonicalizePath(path: string, seams: SandboxSeams = {}): string {
    const canonicalize = seams.canonicalize ?? realpathSync.native;
    const absolute = resolve(path);
    try {
        const resolved = canonicalize(absolute);
        // APFS firmlinks are not resolved by realpath. Normalize the Data-volume
        // alias only when both names demonstrably refer to the same inode.
        const dataPrefix = "/System/Volumes/Data";
        if (!seams.canonicalize && currentPlatform(seams) === "darwin" && resolved.startsWith(`${dataPrefix}/`)) {
            const candidate = resolved.slice(dataPrefix.length);
            try {
                const source = statSync(resolved);
                const alias = statSync(candidate);
                if (source.dev === alias.dev && source.ino === alias.ino) return realpathSync.native(candidate);
            } catch { /* An unrelated Data-volume path keeps its original identity. */ }
        }
        return resolved;
    } catch {
        // Not created yet (or unreadable): canonicalize the parent instead.
    }
    const parent = dirname(absolute);
    if (parent === absolute) return absolute;
    return join(canonicalizePath(parent, seams), basename(absolute));
}

function compile(
    policy: SandboxWritePolicy,
    seams: SandboxSeams,
    strictRoot: boolean,
): CompiledSandboxWritePolicy {
    // The Linux backend has always required the writable root to exist before it
    // bind-mounts it; the macOS backend has always tolerated a not-yet-created
    // one. Keep both behaviors rather than unifying them here.
    const writableRoot = strictRoot
        ? (seams.canonicalize ?? realpathSync.native)(policy.writableRoot)
        : canonicalizePath(policy.writableRoot, seams);

    // The broad profile also keeps each literal entry: its removal grants would
    // otherwise let a task replace a symlinked control path.
    const lexicalDeny = isBroadWritePermissions(policy.permissions);
    const rawDeny = [
        ...new Set((policy.denyWrite ?? []).flatMap((entry) => lexicalDeny
            ? [resolve(entry), ...symlinkHops(entry), canonicalizePath(entry, seams)] : [canonicalizePath(entry, seams)])),
    ];

    const readConfinement = effectiveReadConfinement(policy, writableRoot, seams);
    // Nothing can be created below a `.git` file: an entry under it stands for the same relative path in the git
    // dir(s) it redirects to (hooks live there), which is where the sandbox and the file tools must protect it.
    const gitFile = readConfinement?.gitFile;
    const redirected = new Set<string>();
    const denyWrite = [...new Set(rawDeny.flatMap((entry) => {
        if (!gitFile || entry === gitFile.path || !contains(gitFile.path, entry)) return [entry];
        const mapped = gitFile.dirs.map((dir) => join(dir, relative(gitFile.path, entry)));
        for (const path of mapped) redirected.add(path);
        return mapped;
    }))].sort();
    const broadMode = isBroadWritePermissions(policy.permissions);
    const compatibilityWrite = broadMode ? [] : compatibilityPaths(policy, seams);
    const runtimeWrite = [...new Set([
        ...(policy.runtimeWrite ?? []).map((path) => canonicalizePath(path, seams)),
        ...compatibilityWrite,
    ])];
    return {
        writableRoot, denyWrite, home: policy.home,
        ...(redirected.size && { redirectedDeny: [...redirected].sort() }),
        ...(readConfinement && {
            readConfinement: {
                args: [...readConfinement.args],
                readRoots: readConfinement.readRoots.map((path) => canonicalizePath(path, seams)),
                writeRoots: readConfinement.writeRoots.map((path) => canonicalizePath(path, seams)),
                ...(readConfinement.project !== undefined && { project: readConfinement.project }),
                ...(readConfinement.envAllow && { envAllow: [...readConfinement.envAllow] }),
                ...(readConfinement.pathValue !== undefined && { pathValue: readConfinement.pathValue }),
                ...(readConfinement.denyWrite && { denyWrite: [...new Set(readConfinement.denyWrite.map((path) => canonicalizePath(path, seams)))].sort() }),
                ...(readConfinement.denyRemove && { denyRemove: [...new Set(readConfinement.denyRemove.map((path) => canonicalizePath(path, seams)))].sort() }),
                ...(readConfinement.overlayArgs && { overlayArgs: [...readConfinement.overlayArgs] }),
                ...(readConfinement.gitFile && { gitFile: { path: readConfinement.gitFile.path, dirs: [...readConfinement.gitFile.dirs] } }),
                ...(readConfinement.hardening && { hardening: { ...readConfinement.hardening } }),
                ...(readConfinement.resources && { resources: {
                    ...(readConfinement.resources.command && { command: { ...readConfinement.resources.command } }),
                    ...(readConfinement.resources.tmpSize !== undefined && { tmpSize: readConfinement.resources.tmpSize }),
                } }),
            },
        }),
        ...(policy.permissions && {
            permissions: { ...policy.permissions },
            credentialPaths: broadMode ? broadCredentialPaths(policy.home, seams) : credentialFilePaths(policy.home, seams),
            compatibilityWrite,
            runtimeWrite,
        }),
        ...(broadMode && {
            broad: compileBroadWrite(policy, writableRoot, runtimeWrite, seams),
        }),
    };
}

/**
 * The read-confinement mounts that apply to `policy`: its own, else the process
 * plan published at launch. Required whenever `outsideProject` is `off` and a
 * policy file is configured (`READ_CONFINEMENT_POLICY_ENV` or a published plan):
 * when it cannot be applied (no plan, failed plan, other project, non-Linux
 * backend) the launch is refused rather than run with host-wide reads.
 */
function effectiveReadConfinement(
    policy: SandboxWritePolicy,
    writableRoot: string,
    seams: SandboxSeams,
): ReadConfinementMounts | undefined {
    if (policy.permissions?.outsideProject !== "off") return undefined;
    const published = processReadConfinement();
    const required = policy.readConfinement !== undefined || published !== undefined ||
        Boolean(process.env[READ_CONFINEMENT_POLICY_ENV]);
    if (!required) return undefined;
    if (currentPlatform(seams) !== "linux") {
        throw new Error("Read confinement is required by the configured policy but is only implemented for Linux bubblewrap; this launch was refused.");
    }
    if (policy.readConfinement) return policy.readConfinement;
    if (published?.state === "failed") throw new Error(`Read confinement failed closed: ${published.reason}`);
    if (!published) {
        throw new Error("Read confinement is required by the configured policy but this process has no launch plan; this launch was refused.");
    }
    if (published.mounts.project !== undefined && published.mounts.project !== writableRoot) {
        throw new Error(`Read confinement plan was computed for ${published.mounts.project}, not ${writableRoot}; this launch was refused.`);
    }
    return published.mounts;
}

/** True when a permission profile selects the broad-write profile. */
export function isBroadWritePermissions(permissions: SandboxPermissions | undefined): boolean {
    return permissions?.outsideProject === "write";
}

function expandHome(path: string, home: string): string {
    return path === "~" ? home : path.startsWith("~/") ? join(home, path.slice(2)) : path;
}

/**
 * A fixed-list location both as the literal entry under the canonical home and
 * as the path it resolves to. A dotfiles manager (stow, chezmoi) makes
 * `~/.zshrc` a symlink into an ordinary folder: guarding only the target would
 * let a task remove the link and put a real file in its place.
 */
function lexicalAndCanonical(home: string, name: string, seams: SandboxSeams): string[] {
    const lexical = join(canonicalizePath(home, seams), name);
    return [lexical, ...symlinkHops(lexical), canonicalizePath(lexical, seams)];
}

/**
 * Every symlink directory entry met while resolving `path`, component by
 * component (as `readlink` would follow them), plus where a dangling chain
 * would land. A chain such as
 * `~/.zshrc -> ~/.dotfiles/zshrc -> ~/dotfiles/zshrc` has an intermediate link
 * in a removable directory; replacing it would retarget the protected entry, so
 * each hop the user could replace is protected too. When a followed link
 * points at something missing, creating it would give the entry content, so
 * the first missing component (which covers every missing directory below it)
 * and the full path it would resolve to are protected as well. Bounded: a loop
 * or more than 40 hops stops the walk (such a path resolves to nothing).
 */
function symlinkHops(path: string): string[] {
    const { hops, unresolved } = walkSymlinks(path);
    return [...hops, ...unresolved];
}

function walkSymlinks(path: string): { hops: string[]; unresolved: string[] } {
    const hops: string[] = [];
    const seen = new Set<string>();
    let followed = 0;
    const absolute = resolve(path);
    let current = parse(absolute).root;
    let pending = absolute.slice(current.length).split(sep);
    while (pending.length) {
        const component = pending.shift()!;
        if (!component || component === ".") continue;
        if (component === "..") { current = dirname(current); continue; }
        const entry = join(current, component);
        let link: boolean;
        try {
            link = lstatSync(entry).isSymbolicLink();
        } catch {
            // Missing. Only a followed link makes this a dangling target; a
            // plain absent path is guarded as it is.
            return { hops, unresolved: followed ? [...new Set([entry, resolve(entry, ...pending)])] : [] };
        }
        if (!link) { current = entry; continue; }
        if (++followed > 40 || seen.has(entry)) break;
        seen.add(entry);
        // Only a link the user can replace matters (not e.g. macOS's root-owned /tmp -> private/tmp).
        try { accessSync(current, constants.W_OK); hops.push(entry); } catch { /* immutable entry */ }
        let target: string;
        try { target = readlinkSync(entry); } catch { break; }
        if (isAbsolute(target)) {
            current = parse(target).root;
            pending = [...target.slice(current.length).split(sep), ...pending];
        } else {
            pending = [...target.split(sep), ...pending];
        }
    }
    return { hops, unresolved: [] };
}

/** Whether a symlink resolves to nothing: dangling (ENOENT), or looping or over 40 hops (ELOOP). */
function unresolvable(path: string): boolean {
    try { statSync(path); return false; } catch { return true; }
}

export function broadCredentialPaths(home: string, seams: SandboxSeams): string[] {
    const configuredAgentDir = process.env.PI_CODING_AGENT_DIR;
    return [...new Set([
        ...credentialFilePaths(home, seams),
        ...[...CREDENTIAL_LOCATIONS, ...BROAD_CREDENTIAL_LOCATIONS].flatMap((name) => lexicalAndCanonical(home, name, seams)),
        ...(configuredAgentDir ? [resolve(expandHome(configuredAgentDir, home), "auth.json"),
            ...symlinkHops(resolve(expandHome(configuredAgentDir, home), "auth.json"))] : []),
    ])].sort();
}

function compileBroadWrite(
    policy: SandboxWritePolicy,
    writableRoot: string,
    runtimeWrite: readonly string[],
    seams: SandboxSeams,
): CompiledBroadWrite {
    const permissions = policy.permissions!;
    const home = canonicalizePath(policy.home, seams);
    if (home === sep || RUNTIME_ROOTS.some((root) => contains(canonicalizePath(root, seams), home))) {
        throw new Error("The broad-write sandbox profile needs a real home directory, not / or a system runtime root.");
    }
    if (writableRoot === home || contains(writableRoot, home)) {
        throw new Error("The broad-write sandbox profile needs a project directory inside or beside home, not home itself.");
    }
    const tempRoots = [...new Set((BROAD_TEMP_ROOTS[currentPlatform(seams)] ?? [])
        .map((path) => canonicalizePath(path, seams)))];
    const configuredAgentDir = process.env.PI_CODING_AGENT_DIR;
    const codePaths = [...new Set([
        ...CODE_LATER_LOCATIONS.flatMap((name) => lexicalAndCanonical(home, name, seams)),
        ...(configuredAgentDir ? [resolve(expandHome(configuredAgentDir, home)),
            ...symlinkHops(expandHome(configuredAgentDir, home)),
            canonicalizePath(expandHome(configuredAgentDir, home), seams)] : []),
    ])].sort();
    return {
        home,
        tempRoots,
        deleteRoots: [...new Set([
            ...(permissions.projectFiles === "read-write" ? [writableRoot] : []),
            ...runtimeWrite,
        ])].sort(),
        codePaths,
    };
}

/** Inside a git worktree folder (`.worktrees/`, `*-worktrees/`) below `root`: its contents, not the folder. */
function insideWorktreeFolder(path: string, root: string): boolean {
    if (!contains(root, path) || path === root) return false;
    return path.slice(root.length + 1).split(sep).slice(0, -1)
        .some((part) => part === ".worktrees" || /^[^/]+-worktrees$/.test(part));
}

/** Hidden entries of home, and git worktree folders anywhere under it. */
function disposableHomePath(path: string, home: string): boolean {
    if (!contains(home, path) || path === home) return false;
    return path.slice(home.length + 1).startsWith(".") || insideWorktreeFolder(path, home);
}

/**
 * Canonicalize a write policy once so containment checks and backend rules
 * agree on exactly which paths they are talking about.
 */
export function compileWritePolicy(
    policy: SandboxWritePolicy,
    seams: SandboxSeams = {},
): CompiledSandboxWritePolicy {
    return compile(policy, seams, false);
}

function contains(root: string, target: string): boolean {
    if (target === root) return true;
    return target.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

/**
 * Spell `path` the way the policy spells it when they differ only in case, on
 * macOS. `canonicalizePath` fixes the case of every existing component on a
 * case-insensitive volume, but a missing tail (`~/.NPMRC` while `~/.npmrc` is
 * absent) keeps the caller's case, and the kernel still treats it as the
 * protected name. Seatbelt matches paths case-insensitively on every volume,
 * case-sensitive APFS included, so this folds on darwin without probing the
 * volume: the pre-check decides as the kernel does (#354, #358). The longest
 * policy path that matches case-insensitively wins. Other platforms never fold.
 */
function alignCaseToPolicy(path: string, policy: CompiledSandboxWritePolicy, seams: SandboxSeams): string {
    if (currentPlatform(seams) !== "darwin") return path;
    const broad = policy.broad;
    const candidates = [policy.writableRoot, ...policy.denyWrite, ...(policy.credentialPaths ?? []),
        ...(policy.runtimeWrite ?? []), ...(policy.compatibilityWrite ?? []),
        ...(broad ? [broad.home, ...broad.tempRoots, ...broad.deleteRoots, ...broad.codePaths] : [])];
    const lower = path.toLowerCase();
    if (lower.length !== path.length) return path;
    let best: string | undefined;
    for (const candidate of candidates) {
        const folded = candidate.toLowerCase();
        if (folded.length !== candidate.length || !contains(folded, lower)) continue;
        if (!best || candidate.length > best.length) best = candidate;
    }
    if (!best || path.startsWith(best)) return path;
    return `${best}${path.slice(best.length)}`;
}

function isCredential(path: string, policy: CompiledSandboxWritePolicy): boolean {
    return (policy.credentialPaths ?? []).some((credential) => contains(credential, path));
}

function runtimeRoots(seams: SandboxSeams): string[] {
    return [...new Set(READ_RUNTIME_ROOTS.map((path) => canonicalizePath(path, seams)))];
}

/** Decide read access using the same canonical path and capability precedence as writes. */
export function evaluateReadAccess(
    target: string,
    policy: CompiledSandboxWritePolicy,
    seams: SandboxSeams = {},
): ReadAccessDecision {
    const path = alignCaseToPolicy(canonicalizePath(target, seams), policy, seams);
    const permissions = policy.permissions;
    if (!permissions) return { allowed: true, path };
    if (policy.broad) {
        const denied = (isCredential(path, policy) && permissions.storedCredentials === "off") ||
            (permissions.projectFiles === "off" && contains(policy.writableRoot, path));
        return denied ? { allowed: false, path, reason: "read-denied" } : { allowed: true, path };
    }
    const mode = isCredential(path, policy) ? permissions.storedCredentials
        : policy.runtimeWrite?.some((root) => !policy.compatibilityWrite?.includes(root) && contains(root, path)) ? "read-write"
        : contains(policy.writableRoot, path) ? permissions.projectFiles
        : policy.compatibilityWrite?.some((root) => contains(root, path)) ? "read-write"
        : path === sep || runtimeRoots(seams).some((root) => contains(root, path)) ? "read"
        : policy.readConfinement?.readRoots.some((root) => contains(root, path)) ? "read"
        : policy.readConfinement?.writeRoots.some((root) => contains(root, path)) ? "read"
        : permissions.outsideProject;
    return mode === "off" ? { allowed: false, path, reason: "read-denied" } : { allowed: true, path };
}

/**
 * Decide whether an in-process write to `target` is permitted by a compiled
 * policy. This is the same containment rule the kernel backends enforce, for
 * callers that mutate files directly instead of spawning a child.
 */
export function evaluateWriteAccess(
    target: string,
    policy: CompiledSandboxWritePolicy,
    seams: SandboxSeams = {},
): WriteAccessDecision {
    const path = alignCaseToPolicy(canonicalizePath(target, seams), policy, seams);
    if (policy.broad) return evaluateBroadWrite(path, policy, policy.broad, seams);
    if (!policy.permissions && !contains(policy.writableRoot, path)) {
        return { allowed: false, path, reason: "outside-writable-root" };
    }
    for (const denied of [...policy.denyWrite, ...(policy.readConfinement?.denyWrite ?? [])]) {
        if (contains(denied, path)) {
            return { allowed: false, path, reason: "write-denied", deniedBy: denied };
        }
    }
    if (policy.permissions) {
        const mode = isCredential(path, policy) ? policy.permissions.storedCredentials
            : policy.runtimeWrite?.some((root) => !policy.compatibilityWrite?.includes(root) && contains(root, path)) ? "read-write"
            : contains(policy.writableRoot, path) ? policy.permissions.projectFiles
            : policy.compatibilityWrite?.some((root) => contains(root, path)) ? "read-write"
            : contains(canonicalizePath("/dev", seams), path) ? "read-write"
            : policy.readConfinement?.writeRoots.some((root) => contains(root, path)) ? "read-write"
            : policy.permissions.outsideProject;
        if (!canWrite(mode)) return { allowed: false, path, reason: "permission-denied" };
    }
    return { allowed: true, path };
}

function evaluateBroadWrite(
    path: string,
    policy: CompiledSandboxWritePolicy,
    broad: CompiledBroadWrite,
    seams: SandboxSeams,
): WriteAccessDecision {
    for (const denied of [...policy.denyWrite, ...broad.codePaths]) {
        if (contains(denied, path)) return { allowed: false, path, reason: "write-denied", deniedBy: denied };
    }
    if (isCredential(path, policy)) return canWrite(policy.permissions!.storedCredentials)
        ? { allowed: true, path } : { allowed: false, path, reason: "permission-denied" };
    if (policy.runtimeWrite?.some((root) => contains(root, path))) return { allowed: true, path };
    if (contains(policy.writableRoot, path)) {
        return canWrite(policy.permissions!.projectFiles)
            ? { allowed: true, path } : { allowed: false, path, reason: "permission-denied" };
    }
    if ([...broad.tempRoots, ...broad.deleteRoots, canonicalizePath("/dev", seams)].some((root) => contains(root, path))) {
        return { allowed: true, path };
    }
    if (contains(broad.home, path)) {
        // Linux cannot separate removal from writing, so its fallback keeps
        // ordinary (non-dot) top-level home folders read-only instead.
        if (currentPlatform(seams) === "linux" && !disposableHomePath(path, broad.home)) {
            return { allowed: false, path, reason: "permission-denied" };
        }
        return { allowed: true, path };
    }
    return { allowed: false, path, reason: "permission-denied" };
}

/**
 * Decide whether `target` may be removed or renamed away (unlink, rmdir,
 * rename of the source, or rename over an existing destination). Outside the
 * broad-write profile removal follows write access.
 */
export function evaluateDeleteAccess(
    target: string,
    policy: CompiledSandboxWritePolicy,
    seams: SandboxSeams = {},
): WriteAccessDecision {
    const write = evaluateWriteAccess(target, policy, seams);
    const broad = policy.broad;
    if (!write.allowed) return write;
    const path = write.path;
    // A mount anchor (or a directory containing one) cannot be removed or moved: in the sandbox that fails with EBUSY.
    const anchor = policy.readConfinement?.denyRemove?.find((entry) => contains(path, entry));
    if (anchor !== undefined) return { allowed: false, path, reason: "delete-denied", deniedBy: anchor };
    if (!broad) {
        // Project files = Write outside the broad profile: nothing in the
        // project is removable except worktree folders' contents.
        return policy.permissions?.projectFiles === "write" && contains(policy.writableRoot, path) &&
            !insideWorktreeFolder(path, policy.writableRoot)
            ? { allowed: false, path, reason: "delete-denied" } : write;
    }
    const anchors = broadProtectedPaths(policy, broad);
    if (anchors.some((protectedPath) => protectedPath !== path && contains(path, protectedPath))) {
        return { allowed: false, path, reason: "delete-denied" };
    }
    if (path === policy.writableRoot || contains(path, policy.writableRoot)) {
        return { allowed: false, path, reason: "delete-denied" };
    }
    if ([...broad.tempRoots, ...broad.deleteRoots].some((root) => contains(root, path)) ||
        disposableHomePath(path, broad.home)) {
        return write;
    }
    return { allowed: false, path, reason: "delete-denied" };
}

/**
 * Whether an already-canonical path lies where a Write level still allows
 * removal: temp, hidden home entries, worktree folders, a Write & delete
 * workspace and runtime scratch (broad profile), or a worktree folder inside a
 * Project files = Write workspace. The leaf is not re-resolved, so a caller can
 * ask about a symlink's own directory entry.
 */
export function isRemovableUnderWrite(path: string, policy: CompiledSandboxWritePolicy): boolean {
    const broad = policy.broad;
    if (broad) {
        if (broadProtectedPaths(policy, broad).some((guard) => contains(guard, path) || contains(path, guard))) return false;
        return [...broad.tempRoots, ...broad.deleteRoots].some((root) => contains(root, path)) ||
            disposableHomePath(path, broad.home);
    }
    return policy.permissions?.projectFiles === "write" && insideWorktreeFolder(path, policy.writableRoot);
}

/** Outcome of a finished snapshot attempt. */
export type RecoverySnapshotOutcome = { ok: boolean; detail: string };

/** Result of a best-effort recovery snapshot request. */
export type RecoverySnapshotResult =
    | { started: true; done: Promise<RecoverySnapshotOutcome> }
    | { started: false; reason: "not-needed" | "unsupported" | "rate-limited" };

export type RecoverySnapshotSeams = {
    platform?: () => string;
    now?: () => number;
    /** Defaults to an unref'd `/usr/bin/tmutil localsnapshot` child with a 30 s limit. */
    run?: () => Promise<RecoverySnapshotOutcome>;
};

let lastRecoverySnapshot = 0;
const RECOVERY_SNAPSHOT_INTERVAL_MS = 15 * 60 * 1000;

function runLocalSnapshot(): Promise<RecoverySnapshotOutcome> {
    return new Promise((resolveOutcome) => {
        let output = "";
        let settled = false;
        const finish = (outcome: RecoverySnapshotOutcome) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolveOutcome(outcome);
        };
        const child = spawn("/usr/bin/tmutil", ["localsnapshot"], {
            env: { PATH: "/usr/bin:/bin", LANG: "C" }, stdio: ["ignore", "pipe", "pipe"],
        });
        const timer = setTimeout(() => { child.kill("SIGKILL"); finish({ ok: false, detail: "tmutil timed out after 30 s" }); }, 30_000);
        timer.unref();
        child.unref();
        for (const stream of [child.stdout, child.stderr]) {
            stream?.on("data", (chunk: Buffer) => { output = (output + chunk.toString()).slice(-2048); });
            (stream as { unref?: () => void } | null)?.unref?.();
        }
        child.on("error", (error) => finish({ ok: false, detail: error.message }));
        child.on("close", (code) => finish(code === 0
            ? { ok: true, detail: output.trim() }
            : { ok: false, detail: output.trim() || `tmutil exited ${code}` }));
    });
}

/**
 * Start an APFS local snapshot (`tmutil localsnapshot`) before a confined run
 * whose Outside project level lets it change files outside the project: Write
 * & delete can remove them, and Write can still truncate, chmod or chflags
 * them in place. macOS only; it needs no elevated privileges. The snapshot
 * runs in the background and never blocks or fails the run; callers log a
 * failed outcome. Snapshots are volume-wide and purgeable, so one per 15
 * minutes per process is enough. `PI_SANDBOX_RECOVERY_SNAPSHOT=off` disables it
 * (test suites set it so they do not create real snapshots).
 */
export function takeRecoverySnapshot(
    permissions: SandboxPermissions | undefined,
    seams: RecoverySnapshotSeams = {},
): RecoverySnapshotResult {
    if (!canWrite(permissions?.outsideProject) || process.env.PI_SANDBOX_RECOVERY_SNAPSHOT === "off") {
        return { started: false, reason: "not-needed" };
    }
    if ((seams.platform ?? osPlatform)() !== "darwin") return { started: false, reason: "unsupported" };
    const now = (seams.now ?? Date.now)();
    if (lastRecoverySnapshot && now - lastRecoverySnapshot < RECOVERY_SNAPSHOT_INTERVAL_MS) {
        return { started: false, reason: "rate-limited" };
    }
    lastRecoverySnapshot = now;
    let done: Promise<RecoverySnapshotOutcome>;
    try {
        done = (seams.run ?? runLocalSnapshot)().catch((error: unknown) =>
            ({ ok: false, detail: error instanceof Error ? error.message : String(error) }));
    } catch (error) {
        done = Promise.resolve({ ok: false, detail: error instanceof Error ? error.message : String(error) });
    }
    return { started: true, done };
}

/** Test hook: forget the last snapshot time. */
export function resetRecoverySnapshotClock(): void {
    lastRecoverySnapshot = 0;
}

function broadProtectedPaths(policy: CompiledSandboxWritePolicy, broad: CompiledBroadWrite): string[] {
    return [...policy.denyWrite,
        ...(policy.permissions?.storedCredentials === "read-write" ? [] : policy.credentialPaths ?? []), ...broad.codePaths,
        ...(!canWrite(policy.permissions?.projectFiles) ? [policy.writableRoot] : [])];
}

/** Quote a path as an SBPL string literal. */
function sbpl(path: string): string {
    return `"${path.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function validateRuntimeHome(policy: CompiledSandboxWritePolicy, seams: SandboxSeams): void {
    if (policy.permissions?.outsideProject !== "off") return;
    const home = canonicalizePath(policy.home, seams);
    if (RUNTIME_ROOTS.some((root) => contains(canonicalizePath(root, seams), home))) {
        throw new Error("outsideProject=off cannot expose a home under a required system runtime root; move the home or use another permission mode.");
    }
}

function protectedAncestors(paths: readonly string[]): string[] {
    const parents = new Set<string>();
    for (const path of paths) {
        for (let parent = dirname(path); dirname(parent) !== parent; parent = dirname(parent)) parents.add(parent);
    }
    return [...parents].sort((a, b) => a.length - b.length);
}

function buildPermissionProfile(policy: CompiledSandboxWritePolicy, seams: SandboxSeams): string {
    validateRuntimeHome(policy, seams);
    const permissions = policy.permissions!;
    const protectedPaths = [
        ...policy.denyWrite,
        ...(permissions.projectFiles !== "read-write" ? [policy.writableRoot] : []),
        ...(permissions.storedCredentials !== "read-write" ? policy.credentialPaths ?? [] : []),
        ...(policy.compatibilityWrite ?? []),
    ];
    if (permissions.outsideProject === "write") throw new Error("Outside project = Write uses the broad-write profile.");
    const rules = ["(version 1)", "(allow default)", "(deny file-write*)"];
    if (permissions.outsideProject === "off") {
        rules.push("(deny file-read*)", "(allow file-read-metadata)", '(allow file-read* (literal "/"))');
        for (const root of runtimeRoots(seams)) {
            rules.push(`(allow file-read* (subpath ${sbpl(root)}))`);
        }
    }
    if (permissions.outsideProject === "read-write") rules.push("(allow file-write*)");
    // Temporary host paths are not granted for off/read: doing so would expose
    // other users' files in temp. /dev remains necessary for basic shell I/O.
    for (const root of TEMP_ROOTS.filter((path) => permissions.outsideProject === "read-write" || path === "/dev")
        .map((path) => canonicalizePath(path, seams))) {
        rules.push(`(allow file-write* (subpath ${sbpl(root)}))`);
    }
    const scoped = (root: string, mode: SandboxPermissions["projectFiles"]) => {
        if (mode === "off") rules.push(`(deny file-read* (subpath ${sbpl(root)}))`);
        else rules.push(`(allow file-read* (subpath ${sbpl(root)}))`);
        if (canWrite(mode)) rules.push(`(allow file-write* (subpath ${sbpl(root)}))`);
        else rules.push(`(deny file-write* (subpath ${sbpl(root)}))`);
    };
    // Last matching SBPL rule wins. Credential rules override project and outside;
    // explicit denyWrite entries always override every write allowance.
    for (const path of policy.compatibilityWrite ?? []) scoped(path, "read-write");
    scoped(policy.writableRoot, permissions.projectFiles);
    if (permissions.projectFiles === "write" && !TEMP_ROOTS.filter((root) => root !== "/dev")
        .some((root) => contains(canonicalizePath(root, seams), policy.writableRoot))) {
        // Write without delete: only a worktree folder's contents stay removable.
        const project = sbplRegexPath(policy.writableRoot);
        rules.push(`(deny file-write-unlink (subpath ${sbpl(policy.writableRoot)}))`,
            `(allow file-write-unlink (regex #"^${project}/(.+/)?[.]worktrees/."))`,
            `(allow file-write-unlink (regex #"^${project}/(.+/)?[^/]+-worktrees/."))`);
    }
    for (const path of (policy.runtimeWrite ?? []).filter((path) => !policy.compatibilityWrite?.includes(path))) scoped(path, "read-write");
    for (const path of policy.credentialPaths ?? []) scoped(path, permissions.storedCredentials);
    // Explicit unlink denials too: a `file-write-unlink` allowance above would
    // otherwise outrank a `file-write*` denial.
    for (const path of policy.denyWrite) {
        rules.push(`(deny file-write* (subpath ${sbpl(path)}))`);
        if (permissions.projectFiles === "write") rules.push(`(deny file-write-unlink (subpath ${sbpl(path)}))`);
    }
    // Protect the directory entries, not their contents: unrelated children can
    // still be created, while renaming a parent cannot move a denied subtree.
    for (const path of protectedAncestors(protectedPaths)) rules.push(`(deny file-write-unlink (literal ${sbpl(path)}))`);
    for (const path of policy.compatibilityWrite ?? []) rules.push(`(deny file-write-unlink (literal ${sbpl(path)}))`);
    if (!permissions.network) rules.push("(deny network*)");
    return [...rules, ""].join("\n");
}

/** Escape a canonical path for an SBPL regular expression literal. */
function sbplRegexPath(path: string): string {
    return path.replace(/[\\.^$|?*+()[\]{}"]/g, (char) => `\\${char}`);
}

/**
 * The broad-write profile on Seatbelt.
 *
 * Seatbelt has no separate rename operation: `file-write-unlink` guards unlink,
 * rmdir, the source of a rename, and an existing destination a rename replaces.
 * Denying it outside the disposable roots therefore refuses `rm`, `rm -rf` and
 * `mv dir elsewhere`, and also a save that renames a temp file over an existing
 * file there. Writing a file in place (truncate + write) stays allowed.
 */
function buildBroadProfile(policy: CompiledSandboxWritePolicy, seams: SandboxSeams): string {
    const permissions = policy.permissions!;
    const broad = policy.broad!;
    const rules = ["(version 1)", "(allow default)", "(deny file-write*)",
        `(allow file-write* (subpath ${sbpl(broad.home)}))`];
    const project = policy.writableRoot;
    for (const root of [...broad.tempRoots, canonicalizePath("/dev", seams), ...broad.deleteRoots,
        ...(policy.runtimeWrite ?? []), ...(canWrite(permissions.projectFiles) ? [project] : [])]) {
        rules.push(`(allow file-write* (subpath ${sbpl(root)}))`);
    }
    if (permissions.projectFiles === "off") rules.push(`(deny file-read* (subpath ${sbpl(project)}))`);
    rules.push("(deny file-write-unlink)");
    for (const root of [...broad.tempRoots, ...broad.deleteRoots]) {
        rules.push(`(allow file-write-unlink (subpath ${sbpl(root)}))`);
    }
    const home = sbplRegexPath(broad.home);
    rules.push(
        `(allow file-write-unlink (regex #"^${home}/[.][^/]+$"))`,
        `(allow file-write-unlink (regex #"^${home}/[.][^/]+/"))`,
        `(allow file-write-unlink (regex #"^${home}/(.+/)?[.]worktrees/."))`,
        `(allow file-write-unlink (regex #"^${home}/(.+/)?[^/]+-worktrees/."))`,
    );
    // Write-denied controls and credentials override every broad grant above. A rule naming
    // `file-write-unlink` outranks a `file-write*` wildcard whatever their
    // order (verified on the real kernel), so each protected path also gets an
    // explicit unlink denial; otherwise the removal grants above would reopen it.
    const denyWrite = (path: string) => rules.push(
        `(deny file-write* (subpath ${sbpl(path)}))`, `(deny file-write-unlink (subpath ${sbpl(path)}))`);
    if (!canWrite(permissions.projectFiles)) denyWrite(project);
    for (const path of broad.codePaths) denyWrite(path);
    for (const path of policy.credentialPaths ?? []) {
        if (permissions.storedCredentials === "off") rules.push(`(deny file-read* (subpath ${sbpl(path)}))`);
        if (permissions.storedCredentials !== "read-write") denyWrite(path);
    }
    for (const path of policy.denyWrite) denyWrite(path);
    // Renaming an ancestor would move a protected subtree to an unprotected path,
    // and renaming the workspace's ancestors could redirect the next launch.
    const anchors = [...broadProtectedPaths(policy, broad), project];
    for (const path of [...new Set([...protectedAncestors(anchors), project])]) {
        rules.push(`(deny file-write-unlink (literal ${sbpl(path)}))`);
    }
    if (!permissions.network) rules.push("(deny network*)");
    return [...rules, ""].join("\n");
}

/** Build the macOS sandbox-exec wrapper and its SBPL profile. */
function buildMacOSSandboxCommand(args: SandboxCommandArgs, seams: SandboxSeams): SandboxCommand {
    // Match on the real (symlink-resolved) path — sandbox-exec evaluates the
    // canonical path, so /tmp/x must be written as /private/tmp/x.
    const policy = compile(args.policy, seams, false);

    const profile = policy.broad ? buildBroadProfile(policy, seams)
        : policy.permissions ? buildPermissionProfile(policy, seams) : [
        "(version 1)",
        "(allow default)",          // permissive base: reads, exec, network
        "(deny file-write*)",       // ...then deny all writes...
        `(allow file-write* (subpath ${sbpl(policy.writableRoot)}))`,   // ...except here
        `(allow file-write* (subpath ${sbpl(`${policy.home}/.pi`)}))`,  // pi state
        '(allow file-write* (subpath "/private/var/folders"))',         // macOS temp / our runtime
        '(allow file-write* (subpath "/private/tmp"))',
        '(allow file-write* (subpath "/dev"))',                         // /dev/null etc.
        // Deny rules come last: SBPL applies the last matching rule, so these
        // carve holes back out of the allowances above.
        ...policy.denyWrite.map((path) => `(deny file-write* (subpath ${sbpl(path)}))`),
        "",
    ].join("\n");
    (seams.writeProfile ?? writeFileSync)(args.profilePath, profile);

    return {
        file: MACOS_SANDBOX_EXEC,
        fileArgs: ["-f", args.profilePath, args.execPath, ...args.execArgs],
    };
}

const macOSSandboxBackend: SandboxBackend = {
    id: "macos-seatbelt",
    executable: MACOS_SANDBOX_EXEC,
    buildCommand: buildMacOSSandboxCommand,
};

/** Resolve only a root-owned system executable; never inspect task PATH. */
function systemSandboxExecutable(name: string): string | undefined {
    // Never resolve the host-side confinement launcher through task-influenced PATH.
    for (const directory of ["/usr/bin", "/bin"]) {
        const candidate = join(directory, name);
        try {
            const info = statSync(candidate);
            if (!info.isFile() || info.uid !== 0 || (info.mode & 0o022) !== 0) continue;
            accessSync(candidate, constants.X_OK);
            return candidate;
        } catch { /* Try the next system location. */ }
    }
    return undefined;
}

export function executableFromPath(name: string): string | undefined {
    const path = process.env.PATH;
    if (!path) return undefined;

    for (const entry of path.split(delimiter)) {
        const candidate = resolve(entry || ".", name);
        try {
            if (!statSync(candidate).isFile()) continue;
            accessSync(candidate, constants.X_OK);
            return candidate;
        } catch {
            // A PATH entry may disappear or be inaccessible between lookup and use.
        }
    }
    return undefined;
}

/**
 * Give an absent denied path something the kernel can hold out.
 *
 * A mount needs a mount point. `--ro-bind-try` skips a source that does not
 * exist, so before this a denied path that had not been created yet was not
 * denied at all: inside the sandbox `echo secret > .env.local` simply created
 * it. `.env` and `.env.local` are absent in most projects, which made the
 * packaged defaults hold on macOS — SBPL denies by resolved path, existing or
 * not — and not on Linux.
 *
 * Nothing bubblewrap offers closes that without a mount point, and every
 * bubblewrap operation that would create one (`--dir`, `--file`, `--tmpfs`)
 * creates it through the read-write bind of the project, which is to say on the
 * real filesystem anyway. So the placeholder is created here, deliberately and
 * visibly, rather than as a side effect of a mount operation.
 *
 * An empty regular file is the least destructive placeholder: a later
 * `cp .env.example .env` overwrites it, where an empty *directory* at that path
 * would fail. Callers whose denied entry has to be a directory create it before
 * building the command, and an entry that already exists — file or directory —
 * is bound as it is. The file is created with O_EXCL, so anything that appears
 * in the meantime is bound rather than clobbered, and it is left in place
 * afterwards because a resumed task re-runs the launch vector it captured and
 * its `--ro-bind` sources have to still be there.
 *
 * Returns false when the placeholder could not be created. Callers must fail
 * closed for writable regions: a task may replace or chmod the blocking parent.
 */
function materializeDenyPath(path: string): boolean {
    if (existsSync(path)) return true;
    try {
        mkdirSync(dirname(path), { recursive: true });
        closeSync(openSync(path, "wx"));
        return true;
    } catch {
        // Re-check rather than trust the errno. EEXIST from the O_EXCL create
        // means the path appeared in between, which is the outcome we wanted and
        // not ours to overwrite; EEXIST from the mkdir means a parent is a
        // regular file, and nothing can exist under it. Only the first leaves a
        // source a bind can use.
        return existsSync(path);
    }
}

/**
 * Whether a denied path lies in a region this backend binds read-write.
 *
 * Everywhere else is already covered by the read-only bind of `/`, so a
 * placeholder there would deny nothing that is not denied already — and would
 * scatter empty files across the host for the sake of it. Materializing is
 * confined to the two regions that are genuinely writable inside the sandbox:
 * the writable root, and the `/tmp` rebind that pi's own tooling needs.
 */
function writableInsideLinuxSandbox(path: string, writableRoot: string): boolean {
    return contains(writableRoot, path) || contains("/tmp", path);
}

function buildLinuxSandboxCommand(
    bwrap: string,
    args: SandboxCommandArgs,
    seams: SandboxSeams,
): SandboxCommand {
    // The caller creates the selected work directory before it reaches this
    // boundary. Canonicalizing it before bind-mounting keeps symlink aliases from
    // widening the writable root.
    const policy = compile(args.policy, seams, true);
    if (policy.broad) return buildLinuxBroadCommand(bwrap, args, policy, seams);
    if (policy.permissions) return buildLinuxPermissionCommand(bwrap, args, policy, seams);
    const materialize = seams.materializeDenyPath ?? materializeDenyPath;
    const denyBinds = policy.denyWrite.flatMap((path) => {
        const writable = writableInsideLinuxSandbox(path, policy.writableRoot);
        if (writable && !materialize(path)) throw new Error(`Cannot protect denied path: ${path}`);
        return [writable ? "--ro-bind" : "--ro-bind-try", path, path];
    });
    return {
        file: bwrap,
        fileArgs: [
            "--ro-bind", "/", "/",
            "--bind", policy.writableRoot, policy.writableRoot,
            "--bind", "/tmp", "/tmp",
            "--dev", "/dev",
            // Layered last so a denied path wins over every writable bind above.
            // A denied path need not exist yet, so one inside a writable region
            // is materialized first; `-try` remains for the paths that are
            // read-only regardless. A writable region whose guard cannot be
            // materialized must fail before launching the task.
            ...denyBinds,
            "--",
            args.execPath, ...args.execArgs,
        ],
    };
}

// ---------------------------------------------------------------------------
// Confined-launch hardening
// ---------------------------------------------------------------------------
//
// Every confined launch (Linux, a read-confinement plan, Outside project = Off)
// additionally gets, each behind its own policy switch (`hardening` in the
// read-confinement policy, all default on):
//
//   ipc      private SysV/POSIX IPC namespace             bwrap --unshare-ipc
//   uts      private hostname                              bwrap --unshare-uts --hostname
//   userns   no nested user namespaces                     bwrap --unshare-user --uid --gid --disable-userns
//   keyring  keyctl/add_key/request_key denied (EPERM)     bwrap --seccomp FD, a classic-BPF program built below
//   fds      only descriptors 0-2 (and the filter's own)   a launcher that closes every other inherited descriptor
//
// A measure that is on but cannot be applied (an older bubblewrap, an
// architecture without a syscall table, no way to place the launcher) fails the
// launch closed with the reason. It is never silently dropped.

const HARDENING_FLAGS: Readonly<Record<HardeningMeasure, readonly string[]>> = {
    ipc: ["--unshare-ipc"],
    uts: ["--unshare-uts", "--hostname"],
    userns: ["--unshare-user", "--uid", "--gid", "--disable-userns"],
    keyring: ["--seccomp"],
    fds: [],
};

/** Descriptor the launcher hands the seccomp program to bubblewrap on. Everything else above 2 is closed. */
const SECCOMP_FD = 9;

const bwrapHelpCache = new Map<string, string>();

function bwrapHelpText(bwrap: string, seams: SandboxSeams): string | undefined {
    if (seams.bwrapHelp) return seams.bwrapHelp(bwrap);
    const cached = bwrapHelpCache.get(bwrap);
    if (cached !== undefined) return cached;
    const result = spawnSync(bwrap, ["--help"], { encoding: "utf8", env: {}, timeout: 10_000 });
    if (result.error) return undefined;
    const text = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    if (!text.includes("--unshare-pid")) return undefined;
    bwrapHelpCache.set(bwrap, text);
    return text;
}

/**
 * Architectures the keyring filter has a syscall table for. A filter for any other architecture would deny
 * nothing (or everything), so the measure is unavailable there instead.
 */
const KEYRING_FILTER_ARCHITECTURES: readonly string[] = ["x64", "arm64"];

/** Why the keyring filter cannot be applied on this CPU, or undefined when it can. */
function keyringFilterGap(seams: SandboxSeams): string | undefined {
    const arch = seams.arch ?? process.arch;
    if (!KEYRING_FILTER_ARCHITECTURES.includes(arch)) return `no keyring syscall table for CPU architecture ${arch} (supported: x86_64, aarch64)`;
    if (endianness() !== "LE") return "the seccomp program is only generated for little-endian CPUs";
    return undefined;
}

/**
 * The state of each measure for one bubblewrap executable. `bwrap` is undefined when none is available.
 * Pure of side effects except the one cached `bwrap --help` read.
 */
export function hardeningStates(
    hardening: ResolvedHardening,
    bwrap: string | undefined,
    seams: SandboxSeams = {},
): Record<HardeningMeasure, HardeningState> {
    const help = bwrap ? bwrapHelpText(bwrap, seams) : undefined;
    const states = {} as Record<HardeningMeasure, HardeningState>;
    for (const measure of HARDENING_MEASURES) {
        if (!hardening[measure]) { states[measure] = { state: "off" }; continue; }
        const unavailable = (reason: string): HardeningState => ({ state: "unavailable", reason });
        if (!bwrap) { states[measure] = unavailable("bubblewrap was not found"); continue; }
        const missing = HARDENING_FLAGS[measure].find((flag) => help === undefined || !new RegExp(`(^|\\s)${flag}(\\s|$)`, "m").test(help));
        if (missing !== undefined) {
            states[measure] = unavailable(help === undefined
                ? `cannot read the option list of ${bwrap} (--help)`
                : `bubblewrap ${missing} is not supported by ${bwrap}; use a newer bubblewrap`);
            continue;
        }
        if (measure === "userns" && (process.getuid === undefined || process.getgid === undefined)) {
            states[measure] = unavailable("the current user and group ids are not available to map");
            continue;
        }
        if (measure === "keyring") {
            const gap = keyringFilterGap(seams);
            if (gap) { states[measure] = unavailable(gap); continue; }
        }
        if (measure === "fds" && (!existsSync("/proc/self/fd") || !systemSandboxExecutable("sh"))) {
            states[measure] = unavailable("closing inherited descriptors needs /proc/self/fd and a system sh");
            continue;
        }
        states[measure] = { state: "on" };
    }
    return states;
}

function endianness(): "LE" | "BE" {
    return new Uint8Array(new Uint16Array([1]).buffer)[0] === 1 ? "LE" : "BE";
}

// ---- the keyring seccomp program -------------------------------------------

// Classic BPF (struct sock_filter { u16 code; u8 jt; u8 jf; u32 k }), little-endian.
const BPF_LD_W_ABS = 0x20;
const BPF_JEQ_K = 0x15;
const BPF_JSET_K = 0x45;
const BPF_RET_K = 0x06;
const SECCOMP_DATA_NR = 0;
const SECCOMP_DATA_ARCH = 4;
const AUDIT_ARCH_X86_64 = 0xc000003e;
const AUDIT_ARCH_AARCH64 = 0xc00000b7;
const X32_SYSCALL_BIT = 0x40000000;
const SECCOMP_RET_ALLOW = 0x7fff0000;
const SECCOMP_RET_KILL_PROCESS = 0x80000000;
const SECCOMP_RET_ERRNO = 0x00050000;
const EPERM = 1;

/** The kernel-keyring system calls: add_key, request_key, keyctl. */
export const KEYRING_SYSCALLS: Readonly<Record<"x86_64" | "aarch64", Readonly<Record<"add_key" | "request_key" | "keyctl", number>>>> = Object.freeze({
    x86_64: Object.freeze({ add_key: 248, request_key: 249, keyctl: 250 }),
    aarch64: Object.freeze({ add_key: 217, request_key: 218, keyctl: 219 }),
});

type BpfInstruction = { code: number; k: number; jt?: string; jf?: string; label?: string };

/**
 * The seccomp filter that denies the keyring system calls with EPERM and allows everything else.
 *
 * Both supported ABIs are in one program so it does not depend on the building host: x86_64 (its x32 ABI
 * and any other architecture, including 32-bit compat, are killed rather than left a way around the
 * filter) and aarch64. Generated here, with no library, because the filter has three syscall numbers and
 * a fixed shape; `KEYRING_SYSCALLS` is the table a reader checks it against.
 */
export function keyringSeccompProgram(): Buffer {
    const x86 = Object.values(KEYRING_SYSCALLS.x86_64);
    const a64 = Object.values(KEYRING_SYSCALLS.aarch64);
    const program: BpfInstruction[] = [
        { code: BPF_LD_W_ABS, k: SECCOMP_DATA_ARCH },
        { code: BPF_JEQ_K, k: AUDIT_ARCH_X86_64, jt: "x86", jf: "next" },
        { code: BPF_JEQ_K, k: AUDIT_ARCH_AARCH64, jt: "a64", jf: "kill" },
        // Classic BPF only jumps forward, so the two failure outcomes sit at the end.
        { code: BPF_LD_W_ABS, k: SECCOMP_DATA_NR, label: "x86" },
        { code: BPF_JSET_K, k: X32_SYSCALL_BIT, jt: "kill", jf: "next" },
        ...x86.map((nr): BpfInstruction => ({ code: BPF_JEQ_K, k: nr, jt: "deny", jf: "next" })),
        { code: BPF_RET_K, k: SECCOMP_RET_ALLOW },
        { code: BPF_LD_W_ABS, k: SECCOMP_DATA_NR, label: "a64" },
        ...a64.map((nr): BpfInstruction => ({ code: BPF_JEQ_K, k: nr, jt: "deny", jf: "next" })),
        { code: BPF_RET_K, k: SECCOMP_RET_ALLOW },
        { code: BPF_RET_K, k: SECCOMP_RET_ERRNO | EPERM, label: "deny" },
        { code: BPF_RET_K, k: SECCOMP_RET_KILL_PROCESS, label: "kill" },
    ];
    const labels = new Map<string, number>();
    program.forEach((instruction, index) => { if (instruction.label) labels.set(instruction.label, index); });
    const out = Buffer.alloc(program.length * 8);
    program.forEach((instruction, index) => {
        const target = (name: string | undefined): number => {
            if (name === undefined) return 0;
            const to = name === "next" ? index + 1 : labels.get(name);
            if (to === undefined || to <= index || to - index - 1 > 255) throw new Error(`Invalid seccomp jump ${name} at ${index}`);
            return to - index - 1;
        };
        out.writeUInt16LE(instruction.code, index * 8);
        out.writeUInt8(target(instruction.jt), index * 8 + 2);
        out.writeUInt8(target(instruction.jf), index * 8 + 3);
        out.writeUInt32LE(instruction.k >>> 0, index * 8 + 4);
    });
    return out;
}

// ---- resource limits ---------------------------------------------------------
//
// `resources` in the read-confinement policy bounds what a confined launch can consume:
//
//   resources.command   one transient systemd user scope per launch   systemd-run --user --scope -p ...
//   resources.tmpSize   size of the private /tmp tmpfs                 bwrap --size BYTES before --tmpfs /tmp
//
// Both are optional, and an unset limit changes nothing (no scope, the argument vector is the historical
// one). A limit that is set but cannot be applied (no reachable user manager, a controller the manager does
// not delegate, a bubblewrap without `--size`) fails the launch closed with the reason.
//
// The parser, the property mapping and the scope arguments are exported so that other launchers (the remote
// subagent launch script) apply the same keys the same way.

/** The keys of `resources.command` (and of a remote target's `resources.session`). */
export const COMMAND_LIMIT_KEYS = ["memoryMax", "memorySwapMax", "tasksMax", "cpuQuota", "runtimeMaxSec"] as const;
export type CommandLimitKey = (typeof COMMAND_LIMIT_KEYS)[number];

/**
 * Command limits as written. Sizes are strings (a decimal integer with an optional K, M, G or T suffix,
 * powers of 1024); `tasksMax`, `cpuQuota` (percent of one CPU) and `runtimeMaxSec` are positive integers.
 */
export type CommandLimits = {
    memoryMax?: string;
    memorySwapMax?: string;
    tasksMax?: number;
    cpuQuota?: number;
    runtimeMaxSec?: number;
};

/** The policy's `resources` object as written. */
export type ResourcesPolicy = { command?: CommandLimits; tmpSize?: string };

/** Whether one resource limit is applied, or could not be applied (the launch then fails closed). */
export type ResourceState =
    | { readonly state: "on" }
    | { readonly state: "unavailable"; readonly reason: string };

/** What the policy's `resources` object resolved to for the checks and the launch builder. */
export type ResolvedResources = { readonly command?: CommandLimits; readonly tmpSize?: string };

const SIZE_PATTERN = /^(0|[1-9][0-9]*)([KMGT])?$/;
const SIZE_UNITS: Readonly<Record<string, bigint>> = { "": 1n, K: 1024n, M: 1024n ** 2n, G: 1024n ** 3n, T: 1024n ** 4n };
const MAX_LIMIT_INTEGER = 1_000_000_000_000;

/** Bytes in a size string, or undefined when it is malformed or does not fit a safe integer. */
export function sizeToBytes(text: unknown): number | undefined {
    if (typeof text !== "string") return undefined;
    const match = SIZE_PATTERN.exec(text);
    if (!match) return undefined;
    const bytes = BigInt(match[1]!) * SIZE_UNITS[match[2] ?? ""]!;
    return bytes <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(bytes) : undefined;
}

/** Reports a malformed policy value; must throw. */
export type ResourceFail = (path: string, message: string) => never;

function resourceObject(value: unknown, path: string, allowed: readonly string[], fail: ResourceFail): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(path, "expected an object");
    for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${path}.${key}`, "unknown key");
    return value as Record<string, unknown>;
}

function resourceSize(value: unknown, path: string, fail: ResourceFail, zero: boolean): string {
    const bytes = sizeToBytes(value);
    if (bytes === undefined) fail(path, 'expected a size string: a decimal integer with an optional K, M, G or T suffix (powers of 1024), for example "512M"');
    if (bytes === 0 && !zero) fail(path, "must be greater than zero");
    return value as string;
}

function resourceCount(value: unknown, path: string, fail: ResourceFail, unit: string): number {
    if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > MAX_LIMIT_INTEGER) {
        fail(path, `expected a positive integer (${unit})`);
    }
    return value;
}

/**
 * Strictly validate a set of command limits (`resources.command`, a remote target's `resources.session`).
 * Unknown keys and every value that is not exactly the documented form are refused.
 */
export function parseCommandLimits(value: unknown, path: string, fail: ResourceFail): CommandLimits {
    const raw = resourceObject(value, path, COMMAND_LIMIT_KEYS, fail);
    const limits: CommandLimits = {};
    if (raw.memoryMax !== undefined) limits.memoryMax = resourceSize(raw.memoryMax, `${path}.memoryMax`, fail, false);
    if (raw.memorySwapMax !== undefined) limits.memorySwapMax = resourceSize(raw.memorySwapMax, `${path}.memorySwapMax`, fail, true);
    if (raw.tasksMax !== undefined) limits.tasksMax = resourceCount(raw.tasksMax, `${path}.tasksMax`, fail, "processes and threads");
    if (raw.cpuQuota !== undefined) limits.cpuQuota = resourceCount(raw.cpuQuota, `${path}.cpuQuota`, fail, "percent of one CPU; 200 is two CPUs");
    if (raw.runtimeMaxSec !== undefined) limits.runtimeMaxSec = resourceCount(raw.runtimeMaxSec, `${path}.runtimeMaxSec`, fail, "seconds");
    return limits;
}

/** Strictly validate the read-confinement policy's `resources` object. */
export function parseResourcesPolicy(value: unknown, path: string, fail: ResourceFail): ResourcesPolicy {
    const raw = resourceObject(value, path, ["command", "tmpSize"], fail);
    const resources: ResourcesPolicy = {};
    if (raw.command !== undefined) resources.command = parseCommandLimits(raw.command, `${path}.command`, fail);
    if (raw.tmpSize !== undefined) resources.tmpSize = resourceSize(raw.tmpSize, `${path}.tmpSize`, fail, false);
    return resources;
}

/** Whether any command limit is set (an empty object is the same as none). */
export function hasCommandLimits(limits: CommandLimits | undefined): limits is CommandLimits {
    return limits !== undefined && COMMAND_LIMIT_KEYS.some((key) => limits[key] !== undefined);
}

/** The systemd unit properties (`NAME=value`) for a set of command limits, in a fixed order. Sizes become bytes. */
export function commandLimitProperties(limits: CommandLimits): string[] {
    const properties: string[] = [];
    const bytes = (key: "memoryMax" | "memorySwapMax"): string => String(sizeToBytes(limits[key]));
    if (limits.memoryMax !== undefined) properties.push(`MemoryMax=${bytes("memoryMax")}`);
    if (limits.memorySwapMax !== undefined) properties.push(`MemorySwapMax=${bytes("memorySwapMax")}`);
    if (limits.tasksMax !== undefined) properties.push(`TasksMax=${limits.tasksMax}`);
    if (limits.cpuQuota !== undefined) properties.push(`CPUQuota=${limits.cpuQuota}%`);
    if (limits.runtimeMaxSec !== undefined) properties.push(`RuntimeMaxSec=${limits.runtimeMaxSec}`);
    return properties;
}

/**
 * The cgroup control file each limit needs, and the controller that provides it. A scope only has the file
 * when the user manager delegates the controller, so its absence is the proof that the limit is not applied.
 * `runtimeMaxSec` is enforced by the manager's own timer and needs no controller.
 */
export const COMMAND_LIMIT_CONTROLLERS: Readonly<Partial<Record<CommandLimitKey, { controller: string; file: string }>>> = Object.freeze({
    memoryMax: { controller: "memory", file: "memory.max" },
    memorySwapMax: { controller: "memory", file: "memory.swap.max" },
    tasksMax: { controller: "pids", file: "pids.max" },
    cpuQuota: { controller: "cpu", file: "cpu.max" },
});

/** Seconds a scope gets between SIGTERM and SIGKILL when its time limit ends it, so a command that ignores SIGTERM cannot outlive the bound. */
const SCOPE_STOP_TIMEOUT_SEC = 5;

/**
 * The `systemd-run` arguments (everything after the executable, up to and excluding `--`) that start a
 * transient user scope with `limits`. `--quiet` keeps the scope notice off stderr and `--collect` unloads
 * the scope even when the kernel killed it.
 */
export function resourceScopeArguments(limits: CommandLimits, options: { stopGrace?: boolean } = {}): string[] {
    const args = ["--user", "--scope", "--quiet", "--collect", "--no-ask-password"];
    for (const property of commandLimitProperties(limits)) args.push("-p", property);
    // Only a time limit ends a scope by itself; the grace period bounds how long the end takes. A caller that
    // wants the scope to carry exactly the configured properties (a remote session) passes `stopGrace: false`.
    if (limits.runtimeMaxSec !== undefined && options.stopGrace !== false) args.push("-p", `TimeoutStopSec=${SCOPE_STOP_TIMEOUT_SEC}`);
    return args;
}

/**
 * POSIX sh text that runs inside a scope and exits 126 unless the scope really carries the controllers its
 * limits need (the cgroup control files exist). It ends with `exec "$@"`, so the scoped command follows as
 * the script's arguments. Used for the launch itself and for the availability probe.
 */
export function resourceScopeCheckScript(limits: CommandLimits, finalStep: 'exec "$@"' | "exit 0" = 'exec "$@"', subject = "confined launch"): string {
    const lines = [
        "cg=",
        'while IFS= read -r line; do case $line in 0::*) cg=${line#0::} ;; esac; done < /proc/self/cgroup',
        `[ -n "$cg" ] || { echo "${subject} refused: the scope's cgroup is unknown, so the resource limits cannot be confirmed" >&2; exit 126; }`,
    ];
    const seen = new Set<string>();
    for (const key of COMMAND_LIMIT_KEYS) {
        const needs = COMMAND_LIMIT_CONTROLLERS[key];
        if (limits[key] === undefined || !needs || seen.has(needs.file)) continue;
        seen.add(needs.file);
        lines.push(`[ -e "/sys/fs/cgroup$cg/${needs.file}" ] || { echo "${subject} refused: the ${needs.controller} controller is not delegated to the scope, so ${key} cannot be applied" >&2; exit 126; }`);
    }
    lines.push(finalStep);
    return lines.join("\n");
}

/**
 * How to reach the current user's systemd user manager from a process that may have lost its environment:
 * `XDG_RUNTIME_DIR` (default `/run/user/<uid>`) and, when set, `DBUS_SESSION_BUS_ADDRESS`. A reason when the
 * manager cannot be reached.
 */
export function userManagerEnvironment(
    env: NodeJS.ProcessEnv,
    seams: { uid?: number; userManagerPathExists?: (path: string) => boolean } = {},
): { env: Record<string, string> } | { reason: string } {
    const uid = seams.uid ?? process.getuid?.();
    const exists = seams.userManagerPathExists ?? existsSync;
    const clean = (value: string | undefined): string | undefined =>
        value && !value.includes("\0") && !value.includes("\n") ? value : undefined;
    const configured = clean(env.XDG_RUNTIME_DIR);
    const runtime = configured && isAbsolute(configured) ? configured : uid !== undefined ? `/run/user/${uid}` : undefined;
    if (!runtime) return { reason: "XDG_RUNTIME_DIR is not set and the user id is unknown: no systemd user manager is reachable" };
    const bus = clean(env.DBUS_SESSION_BUS_ADDRESS);
    if (!bus && !exists(join(runtime, "bus")) && !exists(join(runtime, "systemd", "private"))) {
        return { reason: `no systemd user manager is reachable: neither ${join(runtime, "bus")} nor ${join(runtime, "systemd", "private")} exists and DBUS_SESSION_BUS_ADDRESS is not set (no active login session or lingering user)` };
    }
    return { env: { XDG_RUNTIME_DIR: runtime, ...(bus && { DBUS_SESSION_BUS_ADDRESS: bus }) } };
}

type ScopeEnvironment = { env: Record<string, string>; systemdRun: string; envTool: string; sh: string };

const scopeProbeCache = new Map<string, number>();
const SCOPE_PROBE_TTL_MS = 30_000;

/**
 * Whether a resource scope with `limits` can be started from here: the user manager is reachable and every
 * controller the limits need is delegated. It starts one real scope with the configured properties and
 * inspects its cgroup, so a configured limit that the host cannot enforce is found before any command runs.
 * A positive answer is cached for a short while per limits and user manager.
 */
export function commandScopeAvailability(limits: CommandLimits, seams: SandboxSeams = {}): { scope: ScopeEnvironment } | { reason: string } {
    const systemdRun = systemSandboxExecutable("systemd-run");
    if (!systemdRun) return { reason: "systemd-run was not found in /usr/bin or /bin" };
    const envTool = systemSandboxExecutable("env");
    const sh = systemSandboxExecutable("sh");
    if (!envTool || !sh) return { reason: "env and sh were not found in /usr/bin or /bin" };
    // The user manager is the launching process's: a seam environment that names none (a plan computed with
    // an allowlist-only environment) must not hide the one the launches will really see.
    const reach = userManagerEnvironment({
        XDG_RUNTIME_DIR: seams.env?.XDG_RUNTIME_DIR ?? process.env.XDG_RUNTIME_DIR,
        DBUS_SESSION_BUS_ADDRESS: seams.env?.DBUS_SESSION_BUS_ADDRESS ?? process.env.DBUS_SESSION_BUS_ADDRESS,
    }, seams);
    if (seams.commandScopeProbe) {
        // A test seam decides availability; the scope arguments are still built from what the host offers.
        const reason = seams.commandScopeProbe(limits);
        return reason !== undefined ? { reason } : { scope: { env: "env" in reach ? reach.env : {}, systemdRun, envTool, sh } };
    }
    if ("reason" in reach) return reach;
    const scope: ScopeEnvironment = { env: reach.env, systemdRun, envTool, sh };
    const key = JSON.stringify([limits, reach.env]);
    const checked = scopeProbeCache.get(key);
    if (checked !== undefined && Date.now() - checked < SCOPE_PROBE_TTL_MS) return { scope };
    const probe = spawnSync(envTool, [...Object.entries(reach.env).map(([name, value]) => `${name}=${value}`),
        systemdRun, ...resourceScopeArguments(limits), "--", sh, "-c", resourceScopeCheckScript(limits, "exit 0"), "pi-resource-scope-probe"], {
        encoding: "utf8", env: {}, timeout: 15_000, stdio: ["ignore", "pipe", "pipe"],
    });
    if (probe.status === 0) {
        scopeProbeCache.set(key, Date.now());
        return { scope };
    }
    const detail = `${probe.stderr ?? ""}`.trim().split("\n").filter(Boolean).slice(-1)[0];
    return { reason: probe.error
        ? `cannot start systemd-run: ${probe.error.message}`
        : `a systemd user scope with the configured limits cannot be started${detail ? `: ${detail}` : ` (exit ${probe.status ?? probe.signal})`}` };
}

/** The state of the configured resource limits for one bubblewrap executable. Only configured limits appear. */
export function resourceStates(
    resources: ResolvedResources | undefined,
    bwrap: string | undefined,
    seams: SandboxSeams = {},
): { command?: ResourceState; tmpSize?: ResourceState } {
    const states: { command?: ResourceState; tmpSize?: ResourceState } = {};
    if (hasCommandLimits(resources?.command)) {
        const availability = commandScopeAvailability(resources.command, seams);
        states.command = "reason" in availability ? { state: "unavailable", reason: availability.reason } : { state: "on" };
    }
    if (resources?.tmpSize !== undefined) {
        const help = bwrap ? bwrapHelpText(bwrap, seams) : undefined;
        states.tmpSize = !bwrap ? { state: "unavailable", reason: "bubblewrap was not found" }
            : help === undefined ? { state: "unavailable", reason: `cannot read the option list of ${bwrap} (--help)` }
            : !/(^|\s)--size(\s|$)/m.test(help) ? { state: "unavailable", reason: `bubblewrap --size is not supported by ${bwrap}; use a newer bubblewrap` }
            : { state: "on" };
    }
    return states;
}

/** Why a configured resource limit is unavailable, one entry per limit, empty when all hold. */
export function resourceUnavailability(states: { command?: ResourceState; tmpSize?: ResourceState }): string[] {
    const out: string[] = [];
    for (const [name, state] of Object.entries(states) as [string, ResourceState][]) {
        if (state.state === "unavailable") out.push(`resources.${name} unavailable: ${state.reason}`);
    }
    return out;
}

// ---- the launcher ----------------------------------------------------------

function shellQuote(value: string): string {
    return `'${value.replaceAll("'", `'\\''`)}'`;
}

/** What the launcher does before it becomes bubblewrap. */
export type ConfinedLauncherSpec = {
    /** The bubblewrap executable it finally execs. */
    bwrap: string;
    /** Close every descriptor above 2 it inherited. */
    closeDescriptors: boolean;
    /** Seccomp program file to open read-only on `SECCOMP_FD` for `--seccomp`. */
    seccompProgram?: Buffer;
    /**
     * Wrapper argv placed in front of bubblewrap (for example a transient resource scope). It runs after
     * the descriptors are closed and the program is open, and `bwrap` and its arguments follow it.
     */
    prefix?: readonly string[];
};

/**
 * The launcher script. `fileArgs` of the confined command stay bubblewrap's own, so a launcher is a drop-in
 * for the `bwrap` executable: it closes inherited descriptors, opens the seccomp program on `SECCOMP_FD`,
 * and execs `[prefix...] bwrap "$@"`.
 *
 * The work happens in a `-c` shell so that no script descriptor is open while descriptors are closed. When
 * bash is available it closes any descriptor; a plain POSIX shell can only name descriptors 0-9, so a leaked
 * higher one makes the launch fail closed instead.
 */
function confinedLauncherScript(spec: ConfinedLauncherSpec, programPath: string | undefined, bash: string | undefined, sh: string): string {
    const body: string[] = [];
    if (spec.closeDescriptors) {
        body.push(
            '[ -d /proc/self/fd ] || { echo "confined launch refused: /proc/self/fd is not readable, so inherited descriptors cannot be closed" >&2; exit 126; }',
            "for f in /proc/self/fd/*; do",
            "  n=${f##*/}",
            "  case $n in",
            "    0|1|2) ;;",
            '    [0-9]) eval "exec $n>&-" ;;',
            bash
                ? '    *) eval "exec $n>&-" ;;'
                : '    *) echo "confined launch refused: inherited descriptor $n cannot be closed without bash" >&2; exit 126 ;;',
            "  esac",
            "done",
        );
    }
    if (programPath) body.push(`exec ${SECCOMP_FD}<${shellQuote(programPath)} || exit 126`);
    body.push(`exec ${[...(spec.prefix ?? []), spec.bwrap].map(shellQuote).join(" ")} "$@"`);
    const shell = bash ? `${shellQuote(bash)} -p` : shellQuote(sh);
    return [
        `#!${sh}`,
        "case $1 in --pi-confined-launcher-selftest) exit 0 ;; esac",
        `exec ${shell} -c ${shellQuote(body.join("\n"))} pi-confined-launcher "$@"`,
        "",
    ].join("\n");
}

const launcherCache = new Map<string, string>();

function isInside(root: string, path: string): boolean {
    return path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);
}

function writeAtomically(path: string, content: string | Buffer, mode: number): void {
    try {
        if (readFileSync(path).equals(Buffer.from(content))) return;
    } catch { /* absent or unreadable: write it */ }
    const temporary = `${path}.${process.pid}.${Math.random().toString(36).slice(2)}`;
    try {
        writeFileSync(temporary, content, { mode, flag: "wx" });
        renameSync(temporary, path);
    } catch (error) {
        try { unlinkSync(temporary); } catch { /* nothing to remove */ }
        throw error;
    }
}

/**
 * Create (or reuse) the executable launcher for `spec` and return its path.
 *
 * The files live in a per-user directory only the launching user can write, outside every root a confined
 * command can write (`avoid`: the project, runtime and writable plan roots), so a confined command can
 * never alter the launcher the next command starts under. They are content-addressed and never deleted: a
 * resumed task re-runs the launch vector it captured. Each candidate directory is proven by running the
 * launcher, which rejects one on a no-exec mount. Throws when none works; the launch then fails closed.
 */
export function ensureConfinedLauncher(spec: ConfinedLauncherSpec, avoid: readonly string[], seams: SandboxSeams = {}): string {
    const env = seams.env ?? process.env;
    const uid = process.getuid?.() ?? 0;
    const candidates = [...new Set([env.XDG_RUNTIME_DIR, tmpdir(), "/tmp"]
        .filter((entry): entry is string => typeof entry === "string" && isAbsolute(entry)))];
    const key = JSON.stringify([spec.bwrap, spec.closeDescriptors, spec.seccompProgram?.toString("hex"), spec.prefix, candidates, avoid]);
    const cached = launcherCache.get(key);
    if (cached !== undefined && existsSync(cached)) return cached;
    const bash = systemSandboxExecutable("bash");
    const sh = systemSandboxExecutable("sh");
    if (!sh) throw new Error("no system sh to start the confined launcher");
    const problems: string[] = [];
    for (const base of candidates) {
        try {
            const root = realpathSync(base);
            const directory = join(root, `pi-confined-launch-${uid}`);
            if (avoid.some((entry) => isInside(entry, directory))) throw new Error("inside a path a confined command can write");
            try { mkdirSync(directory, { mode: 0o700 }); } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
            }
            const info = lstatSync(directory);
            if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== uid || (info.mode & 0o077) !== 0) {
                throw new Error("exists but is not a private directory owned by this user");
            }
            let programPath: string | undefined;
            if (spec.seccompProgram) {
                programPath = join(directory, `keyring-${createHash("sha256").update(spec.seccompProgram).digest("hex").slice(0, 24)}.bpf`);
                writeAtomically(programPath, spec.seccompProgram, 0o400);
            }
            const script = confinedLauncherScript(spec, programPath, bash, sh);
            const path = join(directory, `launch-${createHash("sha256").update(script).digest("hex").slice(0, 24)}.sh`);
            writeAtomically(path, script, 0o500);
            const proof = spawnSync(path, ["--pi-confined-launcher-selftest"], { env: {}, timeout: 10_000 });
            if (proof.status !== 0) throw new Error(`cannot run it${proof.error ? `: ${proof.error.message}` : " (no-exec mount?)"}`);
            launcherCache.set(key, path);
            return path;
        } catch (error) {
            problems.push(`${base}: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    throw new Error(`no usable directory for the confined launcher (${problems.join("; ")})`);
}

/**
 * The launch flags and executable that apply `hardening` and the command limits of `resources`; `file` is
 * bubblewrap itself when nothing needs the launcher. A configured limit that cannot be applied throws.
 */
function hardenLaunch(
    bwrap: string,
    hardening: ResolvedHardening,
    resources: ResolvedResources | undefined,
    avoid: readonly string[],
    seams: SandboxSeams,
): { file: string; flags: string[] } {
    const states = hardeningStates(hardening, bwrap, seams);
    for (const measure of HARDENING_MEASURES) {
        const state = states[measure];
        if (state.state === "unavailable") {
            throw new Error(`Confined launch refused (fails closed): hardening.${measure} is on but unavailable: ${state.reason}. ` +
                `Fix the cause, or switch it off with "hardening": { "${measure}": false } in the read-confinement policy.`);
        }
    }
    const flags: string[] = [];
    if (hardening.ipc) flags.push("--unshare-ipc");
    if (hardening.uts) flags.push("--unshare-uts", "--hostname", hardening.hostname);
    if (hardening.userns) flags.push("--unshare-user", "--uid", String(process.getuid!()), "--gid", String(process.getgid!()), "--disable-userns");
    if (hardening.keyring) flags.push("--seccomp", String(SECCOMP_FD));
    let prefix: string[] | undefined;
    if (hasCommandLimits(resources?.command)) {
        const availability = commandScopeAvailability(resources.command, seams);
        if ("reason" in availability) {
            throw new Error(`Confined launch refused (fails closed): resources.command is set but unavailable: ${availability.reason}. ` +
                'Fix the cause, or remove "resources.command" from the read-confinement policy.');
        }
        const { scope } = availability;
        // The scope is started by the launcher, outside bubblewrap, so the bus location comes from here and
        // not from the (often minimal) environment the launch is spawned with. The check inside the scope
        // re-confirms the controllers for this very launch before bubblewrap starts.
        prefix = [scope.envTool, ...Object.entries(scope.env).map(([name, value]) => `${name}=${value}`),
            scope.systemdRun, ...resourceScopeArguments(resources.command), "--",
            scope.sh, "-c", resourceScopeCheckScript(resources.command), "pi-resource-scope"];
    }
    if (!hardening.fds && !hardening.keyring && !prefix) return { file: bwrap, flags };
    try {
        const file = ensureConfinedLauncher({
            bwrap, closeDescriptors: hardening.fds,
            ...(hardening.keyring && { seccompProgram: keyringSeccompProgram() }),
            ...(prefix && { prefix }),
        }, avoid, seams);
        return { file, flags };
    } catch (error) {
        throw new Error(`Confined launch refused (fails closed): the launcher that applies ${prefix ? "resources.command" : `hardening.${hardening.keyring ? "keyring" : "fds"}`} ` +
            `could not be prepared: ${error instanceof Error ? error.message : String(error)}.`);
    }
}

/** `--size BYTES` for the private /tmp, or nothing when the policy sets no `tmpSize`. Throws when bubblewrap cannot apply it. */
function tmpSizeFlags(bwrap: string, resources: ResolvedResources | undefined, seams: SandboxSeams): string[] {
    if (resources?.tmpSize === undefined) return [];
    const state = resourceStates({ tmpSize: resources.tmpSize }, bwrap, seams).tmpSize;
    if (state?.state === "unavailable") {
        throw new Error(`Confined launch refused (fails closed): resources.tmpSize is set but unavailable: ${state.reason}. ` +
            'Fix the cause, or remove "resources.tmpSize" from the read-confinement policy.');
    }
    return ["--size", String(sizeToBytes(resources.tmpSize))];
}

function buildLinuxPermissionCommand(
    bwrap: string,
    args: SandboxCommandArgs,
    policy: CompiledSandboxWritePolicy,
    seams: SandboxSeams,
): SandboxCommand {
    const permissions = policy.permissions!;
    validateRuntimeHome(policy, seams);
    if (permissions.projectFiles === "write" || permissions.outsideProject === "write") {
        throw new Error("Linux bubblewrap cannot separate removal from writing for Project files; use Write & delete or Read.");
    }
    const project = policy.writableRoot;
    const credentials = policy.credentialPaths ?? [];
    const writableProject = permissions.projectFiles === "read-write";
    const overlappingCredentials = credentials.filter((path) => contains(project, path));
    if (credentials.some((path) => contains(path, project)) &&
        permissions.projectFiles !== permissions.storedCredentials) {
        throw new Error("Linux bubblewrap cannot apply differing project and credential permissions when a credential directory contains the project.");
    }
    if (writableProject && policy.denyWrite.some((path) => contains(path, project))) {
        throw new Error("Linux bubblewrap cannot make a project writable inside a write-denied directory.");
    }
    // Protected leaves and their writable ancestors become mount points below.
    // Linux refuses renaming mount points, preventing ancestor replacement.
    if (permissions.outsideProject === "read-write" && (
        permissions.projectFiles !== "read-write" || permissions.storedCredentials !== "read-write" ||
        policy.denyWrite.length > 0
    )) {
        throw new Error("Linux bubblewrap cannot enforce restricted project/credential/denyWrite paths under a writable outsideProject mount.");
    }
    if (permissions.outsideProject === "read" && permissions.storedCredentials === "read-write" &&
        credentials.some((path) => !contains(project, path))) {
        throw new Error("Linux bubblewrap cannot write credential stores under a read-only outsideProject root.");
    }
    if (permissions.projectFiles === "read" && permissions.storedCredentials === "read-write" &&
        overlappingCredentials.length > 0) {
        throw new Error("Linux bubblewrap cannot write credential stores under a read-only project mount.");
    }
    if (permissions.outsideProject === "read" && permissions.storedCredentials === "off") {
        throw new Error("Linux bubblewrap cannot hide stored credentials in a read-only whole-root bind.");
    }
    if (permissions.outsideProject === "off" && permissions.storedCredentials === "off" &&
        credentials.some((path) => contains(project, path) && permissions.projectFiles !== "off")) {
        throw new Error("Linux bubblewrap cannot hide credentials inside a visible read-only project.");
    }
    if (permissions.outsideProject === "off" && permissions.projectFiles === "off" &&
        RUNTIME_ROOTS.some((root) => contains(canonicalizePath(root, seams), project))) {
        throw new Error("Linux bubblewrap cannot hide a project nested under a required system runtime bind.");
    }
    if (permissions.outsideProject === "off" && credentials.some((path) =>
        !contains(project, path) &&
        RUNTIME_ROOTS.some((root) => contains(canonicalizePath(root, seams), path)) &&
        permissions.storedCredentials === "off")) {
        throw new Error("Linux bubblewrap cannot hide credentials under a required system runtime bind.");
    }
    if (permissions.outsideProject === "off" && permissions.storedCredentials === "read-write" &&
        credentials.some((path) => !contains(project, path))) {
        throw new Error("Linux bubblewrap cannot create or safely bind writable credential stores outside a hidden root.");
    }
    if (permissions.outsideProject === "off" && permissions.projectFiles === "off" &&
        permissions.storedCredentials !== "off" && credentials.some((path) => contains(project, path))) {
        throw new Error("Linux bubblewrap cannot expose credentials inside a hidden project without exposing the project.");
    }
    if (permissions.outsideProject !== "off" && permissions.projectFiles === "off") {
        throw new Error("Linux bubblewrap cannot hide a project inside a visible outsideProject root.");
    }
    const confined = policy.readConfinement !== undefined && permissions.outsideProject === "off";
    // Read confinement: no inherited environment (keys and tokens), a private PID
    // namespace so same-uid host processes cannot be signalled, and a new session
    // so the child cannot inject input into the controlling terminal. /proc is not
    // mounted, so nothing needs it and none is exposed.
    const mounts: string[] = confined ? ["--clearenv", "--unshare-pid", "--new-session"] : [];
    mounts.push(...(permissions.outsideProject === "off" ? ["--tmpfs", "/"]
        : [permissions.outsideProject === "read" ? "--ro-bind" : "--bind", "/", "/"]));
    if (permissions.outsideProject === "off") {
        // Bounded system executable/library roots only. /tmp is private, not a
        // host bind: otherwise outsideProject=off would expose user temp data.
        for (const root of RUNTIME_ROOTS) {
            if (existsSync(root)) mounts.push("--ro-bind", root, root);
        }
        // --size applies to the next tmpfs only, so it sits directly in front of the private /tmp.
        if (confined) mounts.push(...tmpSizeFlags(bwrap, policy.readConfinement?.resources, seams));
        mounts.push("--tmpfs", "/tmp");
        if (args.internalHelperExecutable) {
            const executable = canonicalizePath(args.execPath, seams);
            if (!RUNTIME_ROOTS.some((root) => contains(canonicalizePath(root, seams), executable))) {
                mounts.push("--ro-bind", executable, executable);
            }
        }
    } else {
        mounts.push(permissions.outsideProject === "read" && !policy.compatibilityWrite?.includes(canonicalizePath("/tmp", seams)) ? "--ro-bind" : "--bind", "/tmp", "/tmp");
    }
    mounts.push("--dev", "/dev");
    if (policy.readConfinement && permissions.outsideProject === "off") {
        mounts.push(...policy.readConfinement.args);
        // Only allowlisted names are copied into the cleared environment; PATH is the plan's.
        const env = confinedEnvironment(policy.readConfinement, seams.env ?? process.env);
        for (const [name, value] of Object.entries(env)) {
            if (name !== "PATH" && value !== undefined && !value.includes("\0")) mounts.push("--setenv", name, value);
        }
    }
    const scopedMounts: { option: "--bind" | "--ro-bind"; path: string }[] = [];
    const writableAncestors = new Set<string>();
    const readOnlyGuards = new Set<string>();
    if (permissions.outsideProject === "off" && permissions.storedCredentials === "read") {
        for (const path of credentials) {
            if (existsSync(path) && !contains(project, path)) readOnlyGuards.add(path);
        }
    }
    // A broad /tmp bind is already present for visible outside roots. Cover
    // existing leaves and absent leaves via a read-only existing ancestor; do
    // not create credential or control files in host runtime directories.
    const compatibility = policy.compatibilityWrite ?? [];
    if (compatibility.length) {
        const tmp = canonicalizePath("/tmp", seams);
        const protectedInTmp = [...policy.denyWrite, ...(permissions.storedCredentials !== "read-write" ? credentials : [])]
            .filter((path) => contains(tmp, path) && !contains(project, path));
        if (permissions.storedCredentials === "off" && protectedInTmp.some((path) =>
            credentials.some((credential) => credential === path))) {
            throw new Error("Linux bubblewrap cannot hide credentials under a writable runtime directory.");
        }
        if (policy.denyWrite.some((path) => contains(path, tmp))) {
            throw new Error("Runtime directory overlaps a write-denied control path.");
        }
        const guards = new Set<string>();
        for (const path of protectedInTmp) {
            let guard = path;
            while (!existsSync(guard) && contains(tmp, guard) && guard !== tmp) guard = dirname(guard);
            if (guard === tmp || !contains(tmp, guard)) {
                throw new Error("Cannot protect an absent path directly under writable runtime directory.");
            }
            guards.add(guard);
        }
        for (const guard of [...guards].sort((a, b) => a.length - b.length)) {
            if ([...guards].some((parent) => parent !== guard && contains(parent, guard))) continue;
            for (const parent of protectedAncestors([guard]).filter((parent) => contains(tmp, parent) && parent !== tmp)) {
                writableAncestors.add(parent);
            }
            readOnlyGuards.add(guard);
        }
        // A writable /tmp can rename any directory above the captured project
        // root, then substitute a symlink before the next launch. Anchor each
        // ancestor even when there are no explicit control or credential guards.
        if (permissions.projectFiles !== "off" && contains(tmp, project)) {
            for (const parent of protectedAncestors([project]).filter((path) => contains(tmp, path) && path !== tmp)) {
                writableAncestors.add(parent);
            }
        }
    }
    if (permissions.projectFiles !== "off") {
        scopedMounts.push({ option: writableProject ? "--bind" : "--ro-bind", path: project });
    }
    for (const path of policy.runtimeWrite ?? []) {
        if (compatibility.includes(path)) continue;
        if (credentials.some((protectedPath) => contains(path, protectedPath) || contains(protectedPath, path)) ||
            policy.denyWrite.some((protectedPath) => contains(protectedPath, path))) {
            throw new Error("Runtime directory overlaps protected credentials or control paths.");
        }
        scopedMounts.push({ option: "--bind", path });
    }
    const protectedPaths = [...policy.denyWrite,
        ...(permissions.storedCredentials !== "read-write" ? overlappingCredentials : [])];
    // Deny entries mapped into a redirected git dir are enforced there, in the plan's writable git dirs.
    const redirectedRoots = (policy.readConfinement?.writeRoots ?? []).filter((root) => root !== project &&
        policy.redirectedDeny?.some((path) => contains(root, path)));
    for (const writableRoot of [...(writableProject ? [project] : []),
        ...(policy.runtimeWrite ?? []).filter((path) => !compatibility.includes(path)), ...redirectedRoots]) {
        const materialize = seams.materializeDenyPath ?? materializeDenyPath;
        const mappedOnly = redirectedRoots.includes(writableRoot);
        const leaves = protectedPaths.filter((path) => contains(writableRoot, path) && (!mappedOnly || policy.redirectedDeny?.includes(path)));
        for (const path of leaves) {
            if (!materialize(path)) throw new Error(`Cannot protect denied path: ${path}`);
        }
        // A redirected root is bound inside read-only overlays of the plan; re-binding its ancestors writable
        // would sit after those overlays and hide them. Its leaves are anchored by their own read-only mounts.
        if (!mappedOnly) for (const parent of protectedAncestors(leaves).filter((path) => contains(writableRoot, path) && path !== writableRoot)) {
            writableAncestors.add(parent);
        }
        for (const path of leaves) readOnlyGuards.add(path);
    }
    // A nearest-existing guard can be an ancestor of an unrelated writable
    // project (e.g. absent ~/.npmrc with a project under ~/work). Mount that
    // broad guard in path order, keeping its intervening anchors read-only;
    // only the disjoint project subtree may be rebound writable afterwards.
    const ancestorGuards = [...readOnlyGuards].filter((guard) =>
        scopedMounts.some(({ option, path }) => option === "--bind" && guard !== path && contains(guard, path)));
    for (const guard of ancestorGuards) {
        scopedMounts.push({ option: "--ro-bind", path: guard });
        readOnlyGuards.delete(guard);
    }
    for (const path of writableAncestors) scopedMounts.push({
        option: ancestorGuards.some((guard) => contains(guard, path)) ? "--ro-bind" : "--bind", path,
    });
    scopedMounts.sort((a, b) => a.path.length - b.path.length);
    for (const { option, path } of scopedMounts) mounts.push(option, path, path);
    for (const path of [...readOnlyGuards].sort((a, b) => a.length - b.length)) {
        mounts.push("--ro-bind", path, path);
    }
    if (policy.readConfinement?.overlayArgs && permissions.outsideProject === "off") mounts.push(...policy.readConfinement.overlayArgs);
    // Last, so every mount point above could still be created: the synthetic
    // root and the parents of bound paths become read-only; only the explicit
    // writable binds and the private /tmp stay writable.
    if (policy.readConfinement && permissions.outsideProject === "off") mounts.push("--remount-ro", "/");
    // Hardening goes last so the flags above keep their historical order. It cannot sit under a root the
    // confined command can write, which is where the launcher is kept.
    const hardened = confined
        ? hardenLaunch(bwrap, resolveHardening(policy.readConfinement?.hardening), policy.readConfinement?.resources, [project, ...(policy.runtimeWrite ?? []), ...(policy.readConfinement?.writeRoots ?? [])], seams)
        : undefined;
    return {
        file: hardened?.file ?? bwrap,
        fileArgs: [...mounts, ...(hardened?.flags ?? []), ...(!permissions.network ? ["--unshare-net"] : []),
            "--", args.execPath, ...args.execArgs],
    };
}

type DirectoryEntry = { name: string; directory: boolean; symlink: boolean };

function systemListDirectory(path: string): DirectoryEntry[] {
    try {
        return readdirSync(path, { withFileTypes: true }).map((entry) => ({
            name: entry.name, directory: entry.isDirectory(), symlink: entry.isSymbolicLink(),
        }));
    } catch {
        return [];
    }
}

/**
 * Worktree folders (`.worktrees`, `*-worktrees`) within three levels of home.
 * Bounded so a large home cannot stall a launch; a folder created after launch
 * or deeper than that stays read-only on Linux.
 */
function discoverWorktreeFolders(home: string, list: (path: string) => DirectoryEntry[]): string[] {
    const found: string[] = [];
    let budget = 4000;
    const walk = (directory: string, depth: number) => {
        for (const entry of list(directory)) {
            if (--budget < 0 || !entry.directory || entry.symlink) continue;
            const path = join(directory, entry.name);
            if (entry.name === ".worktrees" || entry.name.endsWith("-worktrees")) found.push(path);
            else if (!entry.name.startsWith(".") && depth < 3) walk(path, depth + 1);
        }
    };
    walk(home, 1);
    return found;
}

/** Empty, mode-000 mask sources a hidden credential is bound over. */
function maskSources(profilePath: string): { directory: string; file: string } {
    const base = join(dirname(profilePath), ".pi-sandbox-mask");
    mkdirSync(base, { recursive: true, mode: 0o700 });
    const directory = join(base, "directory");
    const file = join(base, "file");
    if (!existsSync(directory)) mkdirSync(directory, { mode: 0o000 });
    if (!existsSync(file)) closeSync(openSync(file, "wx", 0o000));
    for (const [path, isDirectory] of [[directory, true], [file, false]] as const) {
        const info = lstatSync(path);
        if (info.isDirectory() !== isDirectory || (info.mode & 0o777) !== 0 || (!isDirectory && info.size !== 0)) {
            throw new Error(`Unsafe sandbox mask source: ${path}`);
        }
    }
    return { directory, file };
}

/**
 * The broad-write profile on Bubblewrap.
 *
 * Mount namespaces cannot separate removal from writing, and Landlock is not
 * reachable from Node or bwrap here, so Linux uses the documented fallback:
 * the root is read-only; temp, the workspace, hidden home entries and worktree
 * folders are writable (removal included); ordinary top-level home folders and
 * home itself stay read-only, so sibling repositories cannot even be edited in
 * place there. Off credentials are masked by empty mode-000 mounts, Read
 * credentials are read-only binds, and Read / write credentials follow the
 * surrounding broad-write rules. Code that runs later and caller-denied paths
 * are read-only binds. Every writable bind and protected leaf is a mount point,
 * which Linux refuses to rename. A protected
 * symlink inside a writable directory (a stow link in `~/.config`) makes that
 * directory read-only with each existing entry bound writable again, so only
 * new top-level entries there are refused.
 */
function buildLinuxBroadCommand(
    bwrap: string,
    args: SandboxCommandArgs,
    policy: CompiledSandboxWritePolicy,
    seams: SandboxSeams,
): SandboxCommand {
    const permissions = policy.permissions!;
    const broad = policy.broad!;
    const project = policy.writableRoot;
    if (permissions.projectFiles === "off") {
        throw new Error("Linux bubblewrap cannot hide a project inside the broad-write profile's visible root.");
    }
    if (permissions.projectFiles === "write") {
        throw new Error("Linux bubblewrap cannot separate removal from writing for Project files; use Write & delete or Read.");
    }
    const credentials = policy.credentialPaths ?? [];
    const protectedCredentials = permissions.storedCredentials === "read-write" ? [] : credentials;
    const writeDenied = [...broad.codePaths, ...policy.denyWrite];
    if (permissions.projectFiles === "read-write" &&
        [...protectedCredentials, ...writeDenied].some((path) => path !== project && contains(path, project))) {
        throw new Error("Linux bubblewrap cannot make a project writable inside a protected directory.");
    }
    const list = seams.listDirectory ?? systemListDirectory;
    const exists = (path: string) => (seams.pathExists ?? existsSync)(path);
    const protectedPaths = [...protectedCredentials, ...writeDenied];
    const insideProtected = (path: string) => protectedPaths.some((guard) => contains(guard, path));

    const writable = new Set<string>();
    for (const root of broad.tempRoots) if (exists(root)) writable.add(root);
    for (const entry of list(broad.home)) {
        if (entry.symlink) continue;
        const path = join(broad.home, entry.name);
        if (entry.name.startsWith(".") && !insideProtected(path)) writable.add(path);
    }
    for (const path of discoverWorktreeFolders(broad.home, list)) if (!insideProtected(path)) writable.add(path);
    for (const path of [...broad.deleteRoots, ...(policy.runtimeWrite ?? [])]) {
        if (path === project || !exists(path)) continue;
        if (insideProtected(path)) throw new Error(`Writable sandbox root overlaps a protected path: ${path}`);
        writable.add(path);
    }
    if (permissions.projectFiles === "read-write") writable.add(project);
    const writableRoots = [...writable];
    const writableAt = (path: string) => writableRoots.some((root) => contains(root, path));

    const mask = (seams.maskSources ?? maskSources)(args.profilePath);
    const materialize = seams.materializeDenyPath ?? materializeDenyPath;
    const hidden: { path: string; source: string }[] = [];
    const readOnly = new Set<string>();
    const directoryLocation = (path: string) => [...DIRECTORY_LOCATIONS]
        .some((name) => canonicalizePath(join(broad.home, name), seams) === path);
    // The literal fixed-list entry (a dangling `~/.ssh` link) or its canonical path.
    const directoryEntry = (path: string) => directoryLocation(path) ||
        [...DIRECTORY_LOCATIONS].some((name) => join(broad.home, name) === path);
    // Directories holding a protected symlink: read-only, so the link cannot be
    // replaced, with their existing entries bound writable again below.
    const linkParents = new Set<string>();
    // Where dangling links would land. Only the first missing component of each
    // needs a guard: nothing can be created below a read-only mount or a locked
    // parent. It is a directory when more of the path lies below it, or when the
    // link is a directory-type entry (`~/.ssh -> ~/work/ssh`).
    const firstMissing = new Map<string, boolean>();
    const belowFirstMissing = new Set<string>();
    for (const path of protectedPaths) {
        const unresolved = walkSymlinks(path).unresolved;
        if (!unresolved.length) continue;
        const first = unresolved[0]!;
        const full = unresolved.at(-1)!;
        firstMissing.set(first, firstMissing.get(first) === true || first !== full || directoryEntry(path));
        if (full !== first) belowFirstMissing.add(full);
    }
    const created: string[] = [];
    const makeDirectory = seams.makeDirectory ?? ((target: string) => mkdirSync(target, { recursive: true, mode: 0o700 }));
    const guard = (path: string, hide: boolean) => {
        let directory: boolean | undefined;
        let link = false;
        try { link = lstatSync(path).isSymbolicLink(); } catch { /* absent or intermediate link */ }
        if (canonicalizePath(path, seams) !== path || (link && unresolvable(path))) {
            // A literal twin of a canonical deny entry: its target is guarded on
            // its own. A looping link resolves to nothing (ELOOP), and a dangling
            // one's missing target is guarded below, so only the link itself
            // needs guarding here. A symlink leaf inside a writable root could be
            // replaced, so its directory is protected; home already is.
            if (link && dirname(path) !== broad.home && writableAt(dirname(path))) linkParents.add(dirname(path));
            return;
        }
        if (belowFirstMissing.has(path) && !firstMissing.has(path)) return; // Its first missing component is guarded.
        if (firstMissing.has(path)) {
            // Where a dangling link would land: nothing may be created there.
            // A missing directory gets an empty read-only placeholder directory,
            // so only that one name is taken, not every new entry beside it
            // (`~/.cache/<tool>/…` would otherwise lock all of `~/.cache`). A
            // missing file is not planted in the user's files: its parent is
            // locked instead (entries stay writable, see below), except in the
            // workspace root and temp, which must keep accepting new entries,
            // so the file placeholder is bound there. Each placeholder made is
            // reported, and the workspace and temp fail closed without one.
            if (!writableAt(path)) return;
            const ancestor = dirname(path);
            if (ancestor === broad.home) return; // Home is read-only already.
            const failClosed = ancestor === project || broad.tempRoots.includes(ancestor);
            const directory = firstMissing.get(path)!;
            if (directory || failClosed) {
                const existed = exists(path);
                let made: boolean;
                if (directory) {
                    try { makeDirectory(path); } catch { /* Re-checked below. */ }
                    made = exists(path);
                } else {
                    made = materialize(path);
                }
                if (made) {
                    if (!existed) created.push(`${path}${directory ? "/" : ""}`);
                    readOnly.add(path);
                    return;
                }
                if (failClosed) throw new Error(`Cannot protect denied path: ${path}`);
            }
            linkParents.add(ancestor);
            return;
        }
        if (!exists(path)) {
            if (!writableAt(path)) return; // Nothing inside the sandbox can create it.
            let ancestor = dirname(path);
            while (!exists(ancestor) && dirname(ancestor) !== ancestor) ancestor = dirname(ancestor);
            if (directoryLocation(path)) {
                (seams.makeDirectory ?? ((target: string) => mkdirSync(target, { recursive: true, mode: 0o700 })))(path);
                directory = true;
            } else if (writableRoots.includes(ancestor) || contains(project, ancestor) ||
                broad.tempRoots.some((root) => contains(root, ancestor))) {
                if (!materialize(path)) throw new Error(`Cannot protect denied path: ${path}`);
            } else {
                readOnly.add(ancestor);
                return;
            }
        }
        if (hide) {
            directory ??= seams.isDirectory ? seams.isDirectory(path) : statSync(path).isDirectory();
            hidden.push({ path, source: directory ? mask.directory : mask.file });
        } else {
            readOnly.add(path);
        }
    };
    for (const path of credentials) {
        if (permissions.storedCredentials === "off") guard(path, true);
        else if (permissions.storedCredentials === "read") guard(path, false);
    }
    for (const path of writeDenied) guard(path, false);
    if (permissions.projectFiles === "read") readOnly.add(project);

    // A read-only link parent keeps its existing entries writable: each one is
    // bound back read-write (a mount point, so it cannot be renamed away either).
    // Only new top-level entries in that directory are lost. Protected entries
    // keep their own mounts, and a symlink entry is never bound: a bind follows
    // it, and writes through it already meet its target's own mounts.
    const rebound = new Set<string>();
    for (const parent of linkParents) readOnly.add(parent);
    for (const parent of linkParents) {
        for (const entry of list(parent)) {
            if (entry.symlink) continue;
            const path = join(parent, entry.name);
            if (insideProtected(path) || readOnly.has(path) || writable.has(path)) continue;
            rebound.add(path);
        }
    }

    // Intermediate directories between a writable root and anything bound
    // inside it become mount points too, so none of them can be renamed away.
    const anchors = new Set<string>();
    for (const target of [...writableRoots, ...readOnly, ...hidden.map((entry) => entry.path)]) {
        for (const parent of protectedAncestors([target])) {
            if (writableRoots.some((root) => root !== parent && contains(root, parent)) &&
                !readOnly.has(parent) && !writable.has(parent) && !rebound.has(parent)) anchors.add(parent);
        }
    }
    type Mount = { option: "--bind" | "--bind-try" | "--ro-bind"; source: string; path: string; rank: number };
    const mounts: Mount[] = [
        ...[...anchors].map((path) => ({ option: "--bind" as const, source: path, path, rank: 0 })),
        ...writableRoots.map((path) => ({ option: "--bind" as const, source: path, path, rank: 1 })),
        // `-try`: an entry removed before a resumed launch stays read-only instead of failing it.
        ...[...rebound].map((path) => ({ option: "--bind-try" as const, source: path, path, rank: 1 })),
        ...[...readOnly].map((path) => ({ option: "--ro-bind" as const, source: path, path, rank: 2 })),
        ...hidden.map(({ path, source }) => ({ option: "--ro-bind" as const, source, path, rank: 3 })),
    ].sort((a, b) => a.path.length - b.path.length || a.rank - b.rank);
    const seen = new Set<string>();
    const fileArgs = ["--ro-bind", "/", "/", "--dev", "/dev"];
    for (const mount of mounts) {
        const key = `${mount.option}\0${mount.source}\0${mount.path}`;
        if (seen.has(key)) continue;
        seen.add(key);
        fileArgs.push(mount.option, mount.source, mount.path);
    }
    return {
        file: bwrap,
        fileArgs: [...fileArgs, ...(!permissions.network ? ["--unshare-net"] : []),
            "--", args.execPath, ...args.execArgs],
        ...(created.length && { notices: [
            `Sandbox: created an empty read-only placeholder where a protected symlink points at nothing, and left it in place (remove it before creating the real target): ${created.join(", ")}`,
        ] }),
    };
}

/** The bubblewrap executable a Linux launch would use, if any. */
export function bubblewrapExecutable(seams: SandboxSeams = {}): string | undefined {
    return (seams.lookupExecutable ?? systemSandboxExecutable)("bwrap");
}

function linuxSandboxBackend(seams: SandboxSeams): SandboxBackend | undefined {
    const bwrap = (seams.lookupExecutable ?? systemSandboxExecutable)("bwrap");
    if (!bwrap) return undefined;
    return {
        id: "linux-bubblewrap",
        executable: bwrap,
        buildCommand: (args, buildSeams) => buildLinuxSandboxCommand(bwrap, args, buildSeams),
    };
}

function selectedSandboxBackend(seams: SandboxSeams): SandboxBackend | undefined {
    const platform = currentPlatform(seams);
    if (platform === "darwin") return macOSSandboxBackend;
    if (platform === "linux") return linuxSandboxBackend(seams);
    return undefined;
}

/**
 * Why no backend applies here. The requirement only: what a caller can do
 * instead is a property of that caller's surface, not of the platform, and is
 * supplied through `SandboxRequest.remedy`.
 */
function unavailableMessage(platform: string): string {
    if (platform === "linux") {
        return "Linux sandbox requires executable bubblewrap (bwrap) in /usr/bin or /bin. Install bubblewrap to enable it.";
    }
    if (platform === "darwin") {
        return "macOS sandbox requires /usr/bin/sandbox-exec, which is missing here.";
    }
    return `sandbox is unsupported on ${platform}.`;
}

/** Report which backend this platform would select, and why it would not. */
export function describeSandboxSupport(seams: SandboxSeams = {}): SandboxSupport {
    const platform = currentPlatform(seams);
    const backend = selectedSandboxBackend(seams);
    if (!backend) {
        return {
            supported: false,
            platform,
            backend: undefined,
            executable: undefined,
            reason: unavailableMessage(platform),
        };
    }
    return { supported: true, platform, backend: backend.id, executable: backend.executable };
}

/** The message explaining why no backend is available on this platform. */
export function sandboxUnavailableMessage(seams: SandboxSeams = {}): string {
    return unavailableMessage(currentPlatform(seams));
}

/** True when an OS write-sandbox backend can be applied on this platform. */
export function sandboxSupported(seams: SandboxSeams = {}): boolean {
    return selectedSandboxBackend(seams) !== undefined;
}

/**
 * Resolve the caller's default-on, explicit-request, and opt-out policy before
 * spawning. A selected backend always returns its wrapper; callers never retry
 * the child directly when that wrapper exits or cannot initialize.
 */
export function maybeBuildSandboxCommand(
    args: SandboxCommandArgs,
    request: SandboxRequest,
    seams: SandboxSeams = {},
): SandboxCommand | undefined {
    if (args.policy.permissions?.commands === false) {
        throw new Error("Sandbox commands permission is off; enable commands before launching a sandboxed process (including bootstrap).");
    }
    if (!request.sandboxEnabled) return undefined;

    const backend = selectedSandboxBackend(seams);
    if (!backend) {
        if (args.policy.permissions) {
            throw new Error(`Cannot enforce sandbox permissions: ${sandboxUnavailableMessage(seams)}`);
        }
        if (request.explicitSandbox) {
            const reason = sandboxUnavailableMessage(seams);
            throw new Error(request.remedy ? `${reason} ${request.remedy}` : reason);
        }
        return undefined;
    }
    return backend.buildCommand(args, seams);
}

/**
 * Return the selected backend's executable and ordered argv wrapper around the
 * target. The fallback preserves the pre-existing direct-call result for callers
 * that bypass the request-policy helper above.
 */
export function buildSandboxCommand(
    args: SandboxCommandArgs,
    seams: SandboxSeams = {},
): SandboxCommand {
    if (args.policy.permissions?.commands === false) {
        throw new Error("Sandbox commands permission is off; enable commands before launching a sandboxed process (including bootstrap).");
    }
    const backend = selectedSandboxBackend(seams);
    if (!backend && args.policy.permissions) {
        throw new Error(`Cannot enforce sandbox permissions: ${sandboxUnavailableMessage(seams)}`);
    }
    return (backend ?? macOSSandboxBackend).buildCommand(args, seams);
}
