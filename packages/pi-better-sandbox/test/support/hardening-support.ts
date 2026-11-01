/**
 * Shared helpers for the confined-launch hardening tests (private IPC and UTS namespaces, no nested user
 * namespaces, no kernel keyring, no inherited descriptors, and the `hardening` switches of the
 * read-confinement policy).
 *
 * Skip convention for real-kernel suites: a missing or unusable bubblewrap skips the suite, except when
 * `PI_SANDBOX_REQUIRE_BACKEND` is set (see "Sandbox confinement lanes" in docs/development-and-release.md),
 * where it throws instead. `environmentSkip` and `requireOrSkip` below apply that rule.
 *
 * Everything here launches through the package's own controller, plan and argument builder (the foreground
 * shell operations); nothing hand-writes bubblewrap arguments. Expected results are derived from kernel and
 * bubblewrap semantics, never from product output. Fixtures live under a non-scratch base
 * (override: PI_SANDBOX_TEST_NON_TEMP_BASE).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { defaultSandboxPermissions } from "../../permissions.ts";
import { hashPolicy, parseReadConfinementPolicy } from "../../shared-read-confinement.ts";
import { buildSandboxCommand, describeSandboxSupport, executableFromPath, type SandboxSeams } from "../../shared-sandbox-core.ts";
import { createSandboxedBashOperations, type ForegroundShellSeams } from "../../shell.ts";
import { ForegroundSandboxController, type ForegroundSandboxSeams } from "../../state.ts";
import { nonTempBase } from "./fixture-base.ts";
import { realBackendSkip } from "./resolvable-backend.ts";

export const PYTHON = "/usr/bin/python3";
export const GIT = "/usr/bin/git";

/** Single-quote a value for a POSIX shell. */
export const q = (value: string): string => `'${value.replaceAll("'", `'\\''`)}'`;

/** Linux syscall numbers per architecture; other architectures skip the syscall-based probes. */
export const SYSCALLS: Record<string, { add_key: number; request_key: number; keyctl: number }> = {
    x64: { add_key: 248, request_key: 249, keyctl: 250 },
    arm64: { add_key: 217, request_key: 218, keyctl: 219 },
};
export const syscalls = SYSCALLS[process.arch];

export const hostLibc = (code: string, args: string[] = []) => spawnSync(PYTHON, ["-c", code, ...args], { encoding: "utf8" });

/**
 * A skip reason for a missing or unusable bubblewrap. When `PI_SANDBOX_REQUIRE_BACKEND` is set the lane must
 * prove its backend, so the reason becomes a thrown error (the same rule `realBackendSkip` applies).
 */
export function requireOrSkip(reason: string): string {
    const required = process.env.PI_SANDBOX_REQUIRE_BACKEND;
    if (required) throw new Error(`PI_SANDBOX_REQUIRE_BACKEND=${required} but ${reason}`);
    return reason;
}

/** Why the real-bubblewrap tests cannot run here, or false. Throws instead of skipping when a backend is required. */
export function environmentSkip(): string | false {
    // Checked first: a required Linux backend on a platform without it must fail, not skip as "not Linux".
    const backend = realBackendSkip();
    if (backend) return backend;
    if (process.platform !== "linux") return "Linux bubblewrap only";
    if (!existsSync(PYTHON)) return `${PYTHON} is required for the in-sandbox probes`;
    // The probe runs the executable the product itself selected (never a PATH lookup: the product ignores PATH).
    const support = describeSandboxSupport();
    const probe = spawnSync(support.supported ? support.executable : "bwrap", ["--unshare-pid", "--unshare-net", "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib64", "/lib64", "--", PYTHON, "-c", "print(1)"], { encoding: "utf8" });
    if (probe.status !== 0) return requireOrSkip(`bubblewrap with --unshare-pid/--unshare-net and ${PYTHON} unavailable: ${(probe.stderr || probe.error?.message || "").trim()}`);
    return false;
}

export const base = nonTempBase();
export function baseSkip(): string | false {
    return environmentSkip() || (base ? false : "no writable non-scratch fixture base (set PI_SANDBOX_TEST_NON_TEMP_BASE)");
}

export type Fixture = { root: string; project: string; home: string; profiles: string; probeDir: string; outside: string; agentDir: string };

/** A fresh fixture tree under the non-scratch base. The caller removes `root`. */
export function makeFixture(prefix: string): Fixture {
    const root = realpathSync(mkdtempSync(join(base!, prefix)));
    const dirs = Object.fromEntries(["project", "home", "profiles", "probe", "outside", "agent"].map((name) => [name, join(root, name)]));
    for (const dir of Object.values(dirs)) mkdirSync(dir, { recursive: true });
    return { root, project: dirs.project!, home: dirs.home!, profiles: dirs.profiles!, probeDir: dirs.probe!, outside: dirs.outside!, agentDir: dirs.agent! };
}

export type RawPolicy = { version: 1; [key: string]: unknown };

/** A minimal read-confinement policy: the probe directory is mounted read-only, plus optional extras and `hardening`. */
export function rawPolicy(fx: Fixture, hardening?: Record<string, unknown>, extra: Record<string, unknown> = {}): RawPolicy {
    return { version: 1, readOnly: [fx.probeDir], tools: { approved: ["sh", "cat"], builtinDefaults: false }, ...extra, ...(hardening ? { hardening } : {}) };
}

/** Policy hash of a raw policy, computed by the policy parser's own `hashPolicy`. */
export const policyHashOf = (raw: RawPolicy): string => hashPolicy(parseReadConfinementPolicy(raw));

/** A controller with read confinement in force (Main profile, Outside project = Off, commands On, Network Off). */
export function controllerFor(fx: Fixture, raw: RawPolicy, overrides: Partial<ForegroundSandboxSeams> = {}): ForegroundSandboxController {
    const controller = new ForegroundSandboxController({
        platform: () => "linux", home: () => fx.home, createProfileDir: () => fx.profiles,
        readConfinement: {
            loadPolicy: () => ({ policy: parseReadConfinementPolicy(raw), source: "fixture-policy", sha256: policyHashOf(raw) }),
            plan: { passwdHomes: () => [], env: { PATH: "/usr/bin:/bin" } },
        },
        ...overrides,
    });
    controller.beginSession(fx.project);
    const settings = defaultSandboxPermissions();
    settings.main = { ...settings.main, enabled: true, projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false };
    controller.setPermissionSettings(settings);
    return controller;
}

/** Run a shell command through the package's own foreground operations (plan, argument builder, local shell). */
export async function confinedExec(controller: ForegroundSandboxController, fx: Fixture, command: string,
    options: { env?: Record<string, string>; timeoutSeconds?: number; seams?: ForegroundShellSeams } = {}): Promise<{ exitCode: number | null; output: string }> {
    const operations = createSandboxedBashOperations(controller, options.seams ?? {});
    let output = "";
    const { exitCode } = await operations.exec(command, fx.project, {
        onData: (chunk) => { output += chunk.toString(); },
        env: { HOME: fx.home, ...(options.env ?? {}) },
        ...(options.timeoutSeconds ? { timeout: options.timeoutSeconds } : {}),
    });
    return { exitCode, output };
}

/** The last JSON object line of a command's output. */
export function lastJson<T = Record<string, string>>(output: string): T {
    const line = output.trim().split("\n").reverse().find((entry) => entry.startsWith("{"));
    if (!line) throw new Error(`no JSON line in output: ${output}`);
    return JSON.parse(line) as T;
}

/** Fake bubblewrap wrappers that behave like an older build: they pass everything through except the named flags. */
export function writeFakeBwrap(dir: string, name: string, missingFlags: string[], version?: string): string {
    const support = describeSandboxSupport();
    if (!support.supported) throw new Error("no bubblewrap to wrap");
    const path = join(dir, name);
    const pattern = missingFlags.map((flag) => `${flag}`).join("|");
    const grep = missingFlags.map((flag) => `-e ${q(flag.replace(/^--/, ""))}`).join(" ");
    writeFileSync(path, [
        "#!/bin/sh",
        `REAL=${q(support.executable)}`,
        ...(version ? [`if [ "$1" = "--version" ]; then echo ${q(`bubblewrap ${version}`)}; exit 0; fi`] : []),
        `if [ "$1" = "--help" ]; then "$REAL" --help 2>&1 | grep -v ${grep}; exit 0; fi`,
        "for a in \"$@\"; do",
        "  case \"$a\" in",
        `    ${pattern}) echo "bwrap: Unknown option $a" >&2; exit 1 ;;`,
        "  esac",
        "done",
        "exec \"$REAL\" \"$@\"",
        "",
    ].join("\n"));
    chmodSync(path, 0o755);
    return path;
}

/** Seams that look up the named fake as `bwrap`, everything else on the real PATH. */
export const lookupWith = (fake: string): Required<Pick<SandboxSeams, "lookupExecutable">> => ({
    lookupExecutable: (name: string) => name === "bwrap" ? fake : executableFromPath(name),
});

// ---- the in-sandbox probe -------------------------------------------------------
// One script, one JSON object: probe name -> "ok:<value>" | "err:<ERRNO NAME>".
export const HARDENING_PROBE = String.raw`
import os, sys, json, errno, ctypes, subprocess
P = json.loads(sys.argv[1])
R = {}
libc = ctypes.CDLL(None, use_errno=True)
def probe(name, fn):
    try: R[name] = "ok:" + str(fn())
    except OSError as e: R[name] = "err:" + errno.errorcode.get(e.errno, str(e.errno))
    except Exception as e: R[name] = "err:" + type(e).__name__
def call(fn):
    ctypes.set_errno(0); r = fn()
    if r == -1 or r is None: raise OSError(ctypes.get_errno(), "x")
    return r

probe("hostname", lambda: os.uname().nodename)

def shm():
    libc.shmat.restype = ctypes.c_void_p
    ctypes.set_errno(0); r = libc.shmat(P["shmId"], None, 0)
    if r is None or r == ctypes.c_void_p(-1).value: raise OSError(ctypes.get_errno() or errno.EINVAL, "x")
    return "attached"
probe("shm_attach", shm)
probe("mq_open", lambda: call(lambda: libc.mq_open(P["mqName"].encode(), os.O_RDWR)) >= 0 and "opened")

def userns():
    pid = os.fork()
    if pid == 0:
        os._exit(0 if libc.unshare(0x10000000) == 0 else (ctypes.get_errno() or 255))
    code = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    if code == 0: return "created"
    raise OSError(code, "x")
probe("userns_syscall", userns)
def unshare_cmd():
    if not os.path.exists("/usr/bin/unshare"): return "n/a"
    r = subprocess.run(["/usr/bin/unshare", "-U", "/usr/bin/true"], capture_output=True, text=True)
    return "rc=%d" % r.returncode
probe("unshare_cmd", unshare_cmd)
probe("uid", lambda: os.getuid())
probe("gid", lambda: os.getgid())
probe("project_owner", lambda: os.stat(P["project"]).st_uid)

if P["sysKeyctl"] > 0:
    probe("keyctl_user_keyring", lambda: call(lambda: libc.syscall(P["sysKeyctl"], 0, -4, 0)) > 0 and "id")
    probe("add_key", lambda: call(lambda: libc.syscall(P["sysAddKey"], b"user", b"pbs-hardening", b"payload", 7, -4)) > 0 and "added")
    probe("request_key", lambda: call(lambda: libc.syscall(P["sysRequestKey"], b"user", b"pbs-hardening-absent", None, 0)))
    def key_read():
        buf = ctypes.create_string_buffer(64)
        n = call(lambda: libc.syscall(P["sysKeyctl"], 11, P["keyId"], buf, 64))
        return buf.raw[:n].decode()
    probe("keyctl_read_host_key", key_read)
print(json.dumps(R))
`;

/** Host-side resources the sandbox must not reach: a SysV segment, a POSIX queue and a user key. */
export type HostResources = { shmId: number; mqName: string; keyId: number };

export function createHostResources(): HostResources {
    const made = hostLibc(String.raw`
import ctypes, os, sys, json
libc = ctypes.CDLL(None, use_errno=True)
shm = libc.shmget(0, 4096, 0o1600)
name = "/pbs-hardening-%d" % os.getpid()
libc.mq_open.restype = ctypes.c_int
mq = libc.mq_open(name.encode(), os.O_CREAT | os.O_RDWR, 0o600, None)
key = -1
if int(sys.argv[1]) > 0:
    key = libc.syscall(int(sys.argv[1]), b"user", b"pbs-hardening", b"key-payload", 11, -4)
print(json.dumps({"shmId": shm, "mqName": name if mq >= 0 else "", "keyId": key}))
`, [String(syscalls?.add_key ?? -1)]);
    return made.status === 0 ? JSON.parse(made.stdout) : { shmId: -1, mqName: "", keyId: -1 };
}

export function removeHostResources(res: HostResources): void {
    if (res.shmId < 0 && !res.mqName && res.keyId < 0) return;
    hostLibc(String.raw`
import ctypes, sys
libc = ctypes.CDLL(None)
shm, mq, key, kc = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
if shm >= 0: libc.shmctl(shm, 0, None)
if mq: libc.mq_unlink(mq.encode())
if key > 0 and kc > 0: libc.syscall(kc, 3, key)
`, [String(res.shmId), res.mqName, String(res.keyId), String(syscalls?.keyctl ?? -1)]);
}

/** Whether the host kernel/container lets this process use the keyring syscalls at all (otherwise nothing is provable). */
export function hostKeyringUsable(): boolean {
    if (!syscalls) return false;
    const out = hostLibc(String.raw`
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
print(libc.syscall(int(sys.argv[1]), 0, -4, 0))
`, [String(syscalls.keyctl)]);
    return out.status === 0 && Number(out.stdout.trim()) > 0;
}

/** Write the probe into the (read-only mounted) probe directory and run it in a confined launch. */
export async function runProbe(controller: ForegroundSandboxController, fx: Fixture, res: HostResources): Promise<Record<string, string>> {
    const script = join(fx.probeDir, "probe.py");
    writeFileSync(script, HARDENING_PROBE);
    const params = {
        project: fx.project, shmId: res.shmId, mqName: res.mqName, keyId: res.keyId,
        sysKeyctl: syscalls?.keyctl ?? -1, sysAddKey: syscalls?.add_key ?? -1, sysRequestKey: syscalls?.request_key ?? -1,
    };
    const out = await confinedExec(controller, fx, `${PYTHON} ${q(script)} ${q(JSON.stringify(params))}`, { timeoutSeconds: 60 });
    if (out.exitCode !== 0) throw new Error(`probe failed (${out.exitCode}): ${out.output}`);
    return lastJson(out.output);
}

// ---- inherited descriptors (see fd-launch-harness.ts) -----------------------------------
export type LauncherKind = "foreground" | "task-bash" | "background" | "subagent";
const HARNESS = join(import.meta.dirname, "fd-launch-harness.ts");
const PACKAGE = join(import.meta.dirname, "..", "..");

const PROBE = "{ echo leak3 >&3; } 2>/dev/null; { echo leak7 >&7; } 2>/dev/null; echo probe-done";

/** Start the launcher harness with descriptors 3 and 7 inherited (no close-on-exec). Returns which markers were written. */
export function launchWithInheritedFds(fx: Fixture, kind: LauncherKind, hardening: Record<string, unknown> | undefined, tag: string) {
    const dir = join(fx.root, `fds-${tag}`);
    mkdirSync(join(dir, "tmp"), { recursive: true });
    const run: Fixture = { ...fx };
    const config = join(dir, "config.json");
    writeFileSync(config, JSON.stringify({ kind, fixture: run, policy: rawPolicy(run, hardening), command: PROBE }));
    const marker3 = join(dir, "marker3"), marker7 = join(dir, "marker7");
    writeFileSync(marker3, ""); writeFileSync(marker7, "");
    const fd3 = openSync(marker3, "a"), fd7 = openSync(marker7, "a");
    try {
        const out = spawnSync(process.execPath, ["--import", "tsx", HARNESS, config], {
            cwd: PACKAGE, encoding: "utf8", timeout: 120_000,
            stdio: ["ignore", "pipe", "pipe", fd3, "ignore", "ignore", "ignore", fd7],
            env: { ...process.env, PI_CODING_AGENT_DIR: fx.agentDir, TMPDIR: join(dir, "tmp"), PI_SANDBOX_READ_CONFINEMENT_POLICY: "" },
        });
        const line = out.stdout.trim().split("\n").reverse().find((entry) => entry.startsWith("{"));
        assert.ok(line, `harness produced no result (status ${out.status}): ${out.stdout}${out.stderr}`);
        const result = JSON.parse(line) as { exitCode?: number | null; output?: string; error?: string };
        return { result, leaked3: readFileSync(marker3, "utf8").includes("leak3"), leaked7: readFileSync(marker7, "utf8").includes("leak7") };
    } finally {
        closeSync(fd3); closeSync(fd7);
    }
}


const LEAK_PROBE = "{ echo leak3 >&3; } 2>/dev/null; { echo leak7 >&7; } 2>/dev/null; echo probe-done";

/** A marker pair: two files, opened on host descriptors for a leak probe. */
function markers(dir: string) {
    mkdirSync(dir, { recursive: true });
    const m3 = join(dir, "marker3"), m7 = join(dir, "marker7");
    writeFileSync(m3, ""); writeFileSync(m7, "");
    return {
        m3, m7,
        read: () => ({ leaked3: readFileSync(m3, "utf8").includes("leak3"), leaked7: readFileSync(m7, "utf8").includes("leak7") }),
    };
}

/**
 * The argument builder level: build the confined command from the controller's frozen plan and spawn it with two
 * marker descriptors passed (the stdio slots 3 and 7 are open in the child's parent-side spawn, so they are
 * inherited without close-on-exec). This is what a spawner or an outer shell that leaves descriptors open looks
 * like to bubblewrap.
 */
export function leakProbeViaBuilder(fx: Fixture, hardening: Record<string, unknown> | undefined, tag: string) {
    const marks = markers(join(fx.root, `fds-builder-${tag}`));
    const controller = controllerFor(fx, rawPolicy(fx, hardening));
    const fd3 = openSync(marks.m3, "a"), fd7 = openSync(marks.m7, "a");
    try {
        const plan = controller.requireLaunchPlan();
        assert.ok(plan.confined);
        const command = buildSandboxCommand({ profilePath: join(fx.profiles, `${tag}.sb`), execPath: "/bin/sh", execArgs: ["-c", LEAK_PROBE], policy: plan.policy }, { env: {} });
        const out = spawnSync(command.file, command.fileArgs, {
            encoding: "utf8", cwd: fx.project, timeout: 60_000, env: { HOME: fx.home },
            stdio: ["ignore", "pipe", "pipe", fd3, "ignore", "ignore", "ignore", fd7],
        });
        return { exitCode: out.status, output: out.stdout + out.stderr, ...marks.read() };
    } finally {
        closeSync(fd3); closeSync(fd7);
        controller.dispose();
    }
}

/**
 * The foreground shell launcher with a leaky outer shell: the configured shell (a wrapper in a read-only mounted
 * directory) opens the marker files on descriptors 3 and 7 and then execs the real shell, as a user's shell
 * start-up file can. The foreground launcher then execs bubblewrap from that shell, so the descriptors reach it.
 * Inside the sandbox the marker paths do not exist, so the wrapper opens nothing there.
 */
export async function leakProbeViaOuterShell(fx: Fixture, hardening: Record<string, unknown> | undefined, tag: string) {
    const marks = markers(join(fx.root, `fds-shell-${tag}`));
    const wrapper = join(fx.probeDir, `leaky-shell-${tag}.sh`);
    writeFileSync(wrapper, `#!/bin/bash\nif [ -e ${q(marks.m3)} ]; then exec 3>>${q(marks.m3)} 7>>${q(marks.m7)}; fi\nexec /bin/bash "$@"\n`);
    chmodSync(wrapper, 0o755);
    const controller = controllerFor(fx, rawPolicy(fx, hardening));
    try {
        const out = await confinedExec(controller, fx, LEAK_PROBE, { seams: { shellPath: () => wrapper }, timeoutSeconds: 60 });
        return { ...out, ...marks.read() };
    } finally {
        controller.dispose();
    }
}
