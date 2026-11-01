/**
 * What the Linux bubblewrap confinement can and cannot limit (real bwrap).
 *
 * Main profile, Outside project = Off, commands On, read confinement active. Every
 * launch is built by the package's own planner and argv builder (the foreground
 * controller's frozen plan -> `buildSandboxCommand`); nothing here hand-writes bwrap
 * arguments. Each probe is a syscall the kernel allowed or refused, run by a small
 * interpreter script inside the sandbox.
 *
 * Two kinds of assertion, deliberately separate:
 *  - LIMITED rows assert a refusal, so a regression that loosens the boundary fails.
 *  - NOT LIMITED rows assert the *current, documented* behaviour so the README table
 *    cannot silently go stale; if one starts failing, the boundary got tighter (update
 *    the README) or the probe broke. They are not endorsements.
 * No resource-exhaustion is exercised: CPU, memory, disk fill, fork bombs and wall
 * time are documented from the mechanism (nothing in the argv sets them), plus a cheap
 * check that resource limits are inherited from the launcher unchanged.
 *
 * Skips cleanly without bubblewrap, without a working user namespace, or without
 * python3 under the runtime roots. Fixtures live under a non-scratch base (override with
 * PI_SANDBOX_TEST_NON_TEMP_BASE) and are removed afterwards.
 * @level kernel
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer as createUnixServer, type Server } from "node:net";
import { createSocket } from "node:dgram";
import { hostname, networkInterfaces, userInfo } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";

import { defaultSandboxPermissions } from "../permissions.ts";
import { buildSandboxCommand } from "../shared-sandbox-core.ts";
import { hashPolicy, parseReadConfinementPolicy } from "../shared-read-confinement.ts";
import { ForegroundSandboxController } from "../state.ts";
import { nonTempBase } from "./support/fixture-base.ts";
import { realBackendSkip } from "./support/resolvable-backend.ts";

const PYTHON = "/usr/bin/python3";
const hostLibc = (code: string, args: string[] = []) =>
    spawnSync(PYTHON, ["-c", code, ...args], { encoding: "utf8" });

function environmentSkip(): string | false {
    const backend = realBackendSkip();
    if (backend) return backend;
    // A user namespace with the confinement's own mount shape, plus the interpreter used for probes.
    const probe = spawnSync("bwrap", ["--unshare-pid", "--unshare-net", "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib64", "/lib64", "--", PYTHON, "-c", "print(1)"], { encoding: "utf8" });
    if (probe.status !== 0) return `bubblewrap with --unshare-pid/--unshare-net and ${PYTHON} unavailable: ${(probe.stderr || probe.error?.message || "").trim()}`;
    return false;
}
const skip = environmentSkip();
const base = nonTempBase();
const baseSkip = skip || (base ? false : "no writable non-scratch fixture base (set PI_SANDBOX_TEST_NON_TEMP_BASE)");

// ---- the in-sandbox probe -------------------------------------------------------
// One script, one JSON object: probe name -> "ok:<value>" | "err:<ERRNO NAME>".
const PROBE = String.raw`
import os, sys, json, socket, subprocess, errno, ctypes, time, resource, platform
P = json.loads(sys.argv[1])
R = {}
libc = ctypes.CDLL(None, use_errno=True)
def probe(name, fn):
    try: R[name] = "ok:" + str(fn())
    except OSError as e: R[name] = "err:" + errno.errorcode.get(e.errno, str(e.errno))
    except Exception as e: R[name] = "err:" + type(e).__name__
def write(path):
    with open(path, "w") as f: f.write("x")
    return "wrote"
def read(path):
    with open(path) as f: return f.read(40)
def tcp(host, port):
    s = socket.socket(); s.settimeout(2)
    try: s.connect((host, port)); return "connected"
    finally: s.close()
def udp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(b"pbs-probe", (host, port)); return "sent"
    finally: s.close()
def unix(path):
    s = socket.socket(socket.AF_UNIX); s.settimeout(2)
    try: s.connect(path); return "connected"
    finally: s.close()
def run(argv, **kw):
    r = subprocess.run(argv, capture_output=True, text=True, **kw); return "rc=%d %s" % (r.returncode, r.stdout.strip())
def errno_call(fn):
    ctypes.set_errno(0); r = fn()
    if r in (-1, None, ctypes.c_void_p(-1).value): raise OSError(ctypes.get_errno(), "x")
    return r

for k, path in P["reads"].items(): probe("read_" + k, lambda p=path: read(p))
for k, path in P["writes"].items(): probe("write_" + k, lambda p=path: write(p))
probe("tmp_host_marker", lambda: os.path.exists(P["hostTmpMarker"]))
probe("tmp_listing_has_host_marker", lambda: os.path.basename(P["hostTmpMarker"]) in os.listdir("/tmp"))
probe("exec_abs", lambda: run(["/usr/bin/id", "-u"]))
probe("exec_path", lambda: run(["id", "-u"]))
probe("exec_shell_path", lambda: run("id -u", shell=True))
def written_exec():
    p = os.path.join(P["project"], "run.sh"); open(p, "w").write("#!/bin/sh\necho ran\n"); os.chmod(p, 0o755); return run([p])
probe("exec_written_in_project", written_exec)
probe("exec_outside_binary", lambda: run([P["outsideBinary"]]))
probe("exec_via_project_symlink", lambda: run([P["linkedBinary"]]))
probe("exec_not_approved_tool_dir", lambda: os.listdir("/run/pi-confined/bin"))

probe("tcp_loopback", lambda: tcp("127.0.0.1", P["tcpPort"]))
probe("tcp_lan", lambda: tcp(P["lanAddress"], P["tcpPort"]) if P["lanAddress"] else "n/a")
probe("udp_loopback", lambda: udp("127.0.0.1", P["udpPort"]))
probe("dns_lookup", lambda: socket.getaddrinfo("localhost", None)[0][0].name)
probe("interfaces", lambda: ",".join(sorted(n for _, n in socket.if_nameindex())))
probe("unix_abstract", lambda: unix("\0" + P["abstractName"]))
probe("unix_fs_outside", lambda: unix(P["sockOutside"]))
probe("unix_fs_in_project", lambda: unix(P["sockProject"]))
probe("unix_fs_in_readonly_mount", lambda: unix(P["sockReadOnly"]))
probe("proc_listing", lambda: len(os.listdir("/proc")))
probe("kill_host_pid", lambda: os.kill(P["hostPid"], 0))
probe("kill_host_parent", lambda: os.kill(P["hostPpid"], 0))
probe("own_pid", lambda: os.getpid())
PTRACE_ATTACH = 16
probe("ptrace_host_pid", lambda: errno_call(lambda: libc.ptrace(PTRACE_ATTACH, P["hostPid"], 0, 0)))
probe("dev_listing", lambda: ",".join(sorted(os.listdir("/dev"))))
for node in ("kfd", "dri", "snd", "video0", "nvidiactl", "fuse", "kvm", "mem", "net"):
    probe("dev_" + node, lambda n=node: os.stat("/dev/" + n).st_mode)
probe("dev_tty_open", lambda: os.open("/dev/tty", os.O_RDWR))
probe("dev_null_write", lambda: write("/dev/null"))
probe("no_new_privs", lambda: libc.prctl(39, 0, 0, 0, 0))
probe("effective_uid", lambda: os.geteuid())
def capeff():
    class H(ctypes.Structure): _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class D(ctypes.Structure): _fields_ = [("e", ctypes.c_uint32), ("p", ctypes.c_uint32), ("i", ctypes.c_uint32)]
    h = H(0x20080522, 0); d = (D * 2)()
    errno_call(lambda: libc.syscall(P["sysCapget"], ctypes.byref(h), ctypes.byref(d)))
    return hex(d[0].e | (d[1].e << 32))
probe("capabilities_effective", capeff)
probe("capability_bounding_sys_admin", lambda: libc.prctl(23, 21, 0, 0, 0))
def nested_userns():
    pid = os.fork()
    if pid == 0:
        os._exit(0 if libc.unshare(0x10000000) == 0 else 1)
    return os.waitpid(pid, 0)[1] == 0
probe("nested_user_namespace", nested_userns)
probe("sysv_shm_attach_host_segment", lambda: errno_call(lambda: (setattr(libc.shmat, "restype", ctypes.c_void_p), libc.shmat(P["shmId"], None, 0))[1]) and "attached")
probe("posix_mq_open_host_queue", lambda: errno_call(lambda: libc.mq_open(P["mqName"].encode(), os.O_RDWR)) >= 0 and "opened")
def key_read():
    buf = ctypes.create_string_buffer(64)
    n = errno_call(lambda: libc.syscall(P["sysKeyctl"], 11, P["keyId"], buf, 64))
    return buf.raw[:n].decode()
probe("keyctl_read_host_key", key_read)
probe("inherited_fd3", lambda: os.read(3, 40).decode() if P["fd3"] else "n/a")
probe("hostname", lambda: os.uname().nodename)
probe("uid", lambda: os.getuid())
probe("clock_skew_seconds", lambda: abs(time.time() - P["hostTime"]) < 30)
probe("rlimit_nproc", lambda: resource.getrlimit(resource.RLIMIT_NPROC))
probe("rlimit_as", lambda: resource.getrlimit(resource.RLIMIT_AS))
probe("rlimit_fsize", lambda: resource.getrlimit(resource.RLIMIT_FSIZE))
probe("rlimit_nofile", lambda: resource.getrlimit(resource.RLIMIT_NOFILE))
probe("env_names", lambda: ",".join(sorted(os.environ)))
probe("env_secret_visible", lambda: "PBS_PROBE_SECRET" in os.environ)
probe("cwd_listing", lambda: ",".join(sorted(os.listdir("/"))))
print(json.dumps(R))
`;

// ---- fixtures -------------------------------------------------------------------
type Observed = Record<string, string>;
const servers: Server[] = [];
let fixtures = "";
let hostSockets: { tcpPort: number; udpPort: number; abstractName: string; sockOutside: string; sockProject: string; sockReadOnly: string; lanAddress: string };
let udpReceived: string[] = [];
let udpServer: ReturnType<typeof createSocket> | undefined;
let sysv: { shmId: number; mqName: string; keyId: number } = { shmId: -1, mqName: "", keyId: -1 };
let hostTmpMarker = "";
const runs: Record<string, Observed> = {};

// Linux syscall numbers per architecture; other architectures skip the syscall-based rows.
const SYSCALLS: Record<string, { add_key: number; keyctl: number; capget: number }> = {
    x64: { add_key: 248, keyctl: 250, capget: 125 },
    arm64: { add_key: 217, keyctl: 219, capget: 90 },
};
const syscalls = SYSCALLS[process.arch];

const listen = (server: Server, where: string | { port: number; host: string }) =>
    new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        if (typeof where === "string") server.listen(where, resolve);
        else server.listen(where.port, where.host, resolve);
    });

before(async () => {
    if (baseSkip) return;
    fixtures = realpathSync(mkdtempSync(join(base!, "pbs-bwrap-limits-")));
    const dir = (name: string) => join(fixtures, name);
    const [project, outside, linked, sockdir, shared, cfg, cfgSecret, home, profiles] =
        ["project", "outside", "linked", "outside-socks", "shared", "approved-config", "secret-config", "home", "profiles"].map(dir) as [string, string, string, string, string, string, string, string, string];
    for (const path of [project, outside, linked, sockdir, shared, cfg, cfgSecret, home, profiles]) mkdirSync(path, { recursive: true });
    writeFileSync(join(outside, "secret.txt"), "outside-secret\n");
    writeFileSync(join(outside, "tool.sh"), "#!/bin/sh\necho outside-binary-ran\n");
    chmodSync(join(outside, "tool.sh"), 0o755);
    writeFileSync(join(shared, "shared.txt"), "shared-readable\n");
    writeFileSync(join(cfg, "tool.conf"), "setting=1\n");
    writeFileSync(join(cfg, "unrelated.txt"), "any file in an approved config dir is readable\n");
    writeFileSync(join(cfgSecret, "token.conf"), "password=hunter2hunter2\n");
    writeFileSync(join(linked, "linked.txt"), "linked-secret\n");
    writeFileSync(join(linked, "tool.sh"), "#!/bin/sh\necho linked-binary-ran\n");
    chmodSync(join(linked, "tool.sh"), 0o755);
    symlinkSync(linked, join(project, "link-out"));
    hostTmpMarker = join(realpathSync("/tmp"), `pbs-limits-marker-${process.pid}`);
    writeFileSync(hostTmpMarker, "host tmp marker");

    // Host listeners the sandbox will try to reach.
    const tcp = createUnixServer(); servers.push(tcp);
    await listen(tcp, { port: 0, host: "0.0.0.0" });
    const abstractName = `pbs-limits-${process.pid}-${Date.now()}`;
    const abstract = createUnixServer(); servers.push(abstract);
    await listen(abstract, `\0${abstractName}`);
    const sockOutside = join(sockdir, "daemon.sock"), sockProject = join(project, "daemon.sock"), sockReadOnly = join(shared, "daemon.sock");
    for (const path of [sockOutside, sockProject, sockReadOnly]) { const s = createUnixServer(); servers.push(s); await listen(s, path); }
    udpServer = createSocket("udp4");
    udpServer.on("message", (message) => udpReceived.push(message.toString()));
    await new Promise<void>((resolve) => udpServer!.bind(0, "0.0.0.0", resolve));
    const lan = Object.values(networkInterfaces()).flat().find((entry) => entry && entry.family === "IPv4" && !entry.internal)?.address ?? "";
    hostSockets = {
        tcpPort: (tcp.address() as { port: number }).port, udpPort: udpServer.address().port, abstractName,
        sockOutside, sockProject, sockReadOnly, lanAddress: lan,
    };

    // Host SysV segment, POSIX queue and kernel key the sandbox will try to reach.
    const made = hostLibc(String.raw`
import ctypes, os, sys, json
libc = ctypes.CDLL(None, use_errno=True)
shm = libc.shmget(0, 4096, 0o1600)
name = "/pbs-limits-%d" % os.getpid()
libc.mq_open.restype = ctypes.c_int
mq = libc.mq_open(name.encode(), os.O_CREAT | os.O_RDWR, 0o600, None)
key = libc.syscall(int(sys.argv[1]), b"user", b"pbs-limits", b"key-payload", 11, -4)
print(json.dumps({"shmId": shm, "mqName": name if mq >= 0 else "", "keyId": key}))
`, [String(syscalls?.add_key ?? -1)]);
    if (made.status === 0) sysv = JSON.parse(made.stdout);

    // Variant launches. `A` is the default Main profile; `B` only turns Network on; `C` adds
    // generic policy extras (a readOnly folder, an approved tool with a config folder).
    const launch = (variant: "A" | "B" | "C"): Observed => {
        const raw: Record<string, unknown> = { version: 1 };
        if (variant === "C") Object.assign(raw, { readOnly: [shared], tools: { approved: [{ name: "cat", config: [cfg, cfgSecret] }] } });
        const seams: any = {
            platform: () => "linux", home: () => home, createProfileDir: () => profiles,
            readConfinement: {
                loadPolicy: () => ({ policy: parseReadConfinementPolicy(raw as Parameters<typeof parseReadConfinementPolicy>[0]), source: "fixture-policy", sha256: hashPolicy(raw as Parameters<typeof hashPolicy>[0]) }),
                plan: { passwdHomes: () => [], env: { PATH: "/usr/bin" } },
            },
        };
        const controller = new ForegroundSandboxController(seams);
        controller.beginSession(project);
        const settings = defaultSandboxPermissions();
        settings.main = { ...settings.main, enabled: true, outsideProject: "off", storedCredentials: "off", commands: true, network: variant === "B" };
        controller.setPermissionSettings(settings);
        try {
            const plan = controller.requireLaunchPlan();
            assert.ok(plan.confined && plan.policy.readConfinement, "read confinement must be in force for these probes");
            const sysKeyctl = syscalls?.keyctl ?? -1, sysCapget = syscalls?.capget ?? -1;
            const params = {
                ...hostSockets,
                reads: { outside: join(outside, "secret.txt"), via_project_symlink: join(project, "link-out", "linked.txt"),
                    readonly_folder: join(shared, "shared.txt"), approved_config: join(cfg, "tool.conf"),
                    approved_config_unrelated: join(cfg, "unrelated.txt"), approved_config_secret: join(cfgSecret, "token.conf") },
                writes: { outside: join(outside, "new"), usr: "/usr/pbs-probe", root: "/pbs-probe", project: join(project, "new.txt"),
                    private_tmp: "/tmp/pbs-probe", via_project_symlink: join(project, "link-out", "new"), readonly_folder: join(shared, "new") },
                project, outsideBinary: join(outside, "tool.sh"), linkedBinary: join(project, "link-out", "tool.sh"), hostPid: process.pid, hostPpid: process.ppid, hostTmpMarker,
                shmId: sysv.shmId, mqName: sysv.mqName, keyId: sysv.keyId, sysKeyctl, sysCapget,
                hostTime: Date.now() / 1000, fd3: true,
            };
            const fd = openSync(join(outside, "secret.txt"), "r");
            try {
                const command = buildSandboxCommand({ profilePath: join(profiles, "unused.sb"), execPath: PYTHON, execArgs: ["-c", PROBE, JSON.stringify(params)], policy: plan.policy }, { env: {} });
                const out = spawnSync(command.file, command.fileArgs, {
                    encoding: "utf8", cwd: project, timeout: 60_000, stdio: ["ignore", "pipe", "pipe", fd],
                    env: { PBS_PROBE_SECRET: "leak", HOME: home },
                });
                assert.equal(out.status, 0, out.stderr);
                return JSON.parse(out.stdout.trim().split("\n").pop()!);
            } finally {
                closeSync(fd);
            }
        } finally {
            controller.dispose();
        }
    };
    for (const variant of ["A", "B", "C"] as const) runs[variant] = launch(variant);
    await new Promise((resolve) => setTimeout(resolve, 300)); // let host receive any UDP datagram
    if (process.env.PI_SANDBOX_LIMITS_DUMP) console.error(JSON.stringify(runs, null, 1));
});

after(() => {
    for (const server of servers) server.close();
    udpServer?.close();
    if (hostTmpMarker) rmSync(hostTmpMarker, { force: true });
    if (sysv.shmId >= 0 || sysv.mqName || sysv.keyId >= 0) {
        hostLibc(String.raw`
import ctypes, sys
libc = ctypes.CDLL(None)
shm, mq, key, kc = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
if shm >= 0: libc.shmctl(shm, 0, None)
if mq: libc.mq_unlink(mq.encode())
if key > 0: libc.syscall(kc, 3, key)
`, [String(sysv.shmId), sysv.mqName, String(sysv.keyId), String(syscalls?.keyctl ?? -1)]);
    }
    if (fixtures) rmSync(fixtures, { recursive: true, force: true });
});

const observed = (variant: string, name: string): string => runs[variant]?.[name] ?? `missing:${name}`;
const A = (name: string) => observed("A", name);
const B = (name: string) => observed("B", name);
const C = (name: string) => observed("C", name);
const t = (name: string, body: () => void | Promise<void>) => test(name, { skip: baseSkip }, body);

// ---- LIMITED ---------------------------------------------------------------------
t("LIMITED: a file outside the allow set is not mounted; its absence is ENOENT, not EACCES", () => {
    assert.equal(A("read_outside"), "err:ENOENT");
    assert.equal(A("write_outside"), "err:ENOENT");
    assert.equal(A("exec_outside_binary"), "err:ENOENT");
});

t("LIMITED: writes land only in writable roots; runtime roots and the synthetic root are read-only", () => {
    assert.equal(A("write_usr"), "err:EROFS");
    assert.equal(A("write_root"), "err:EROFS");
    assert.equal(A("write_project"), "ok:wrote");
    assert.equal(A("write_via_project_symlink"), "err:EROFS", "a symlink-reachable folder is read-only");
    assert.equal(A("write_readonly_folder"), "err:ENOENT", "a readOnly folder exists only when the policy lists it");
    assert.equal(C("write_readonly_folder"), "err:EROFS");
    assert.equal(C("read_readonly_folder"), "ok:shared-readable\n");
});

t("LIMITED: the private /tmp is a fresh tmpfs, the host /tmp is invisible", () => {
    assert.equal(A("tmp_host_marker"), "ok:False");
    assert.equal(A("tmp_listing_has_host_marker"), "ok:False");
    assert.equal(A("write_private_tmp"), "ok:wrote");
    assert.equal(existsSync("/tmp/pbs-probe"), false, "the private /tmp write never reaches the host /tmp");
});

t("LIMITED: lookup by name finds nothing; the synthetic PATH holds only approved tools", () => {
    assert.equal(A("exec_path"), "err:ENOENT");
    assert.equal(A("exec_shell_path"), "ok:rc=127 ");
    assert.match(A("exec_not_approved_tool_dir"), /^(ok:\[\]|err:ENOENT)$/);
    assert.match(A("env_names"), /^ok:.*PATH/);
});

t("LIMITED: with Network Off the host network is unreachable (TCP, UDP, LAN, DNS, abstract unix sockets)", () => {
    // The sandbox gets its own namespace holding only its own loopback: nothing listens there.
    assert.match(A("tcp_loopback"), /^err:(ECONNREFUSED|ENETUNREACH)$/);
    assert.match(A("tcp_lan"), /^(err:(ENETUNREACH|ECONNREFUSED|EADDRNOTAVAIL)|ok:n\/a)$/);
    assert.match(A("unix_abstract"), /^err:ECONNREFUSED$/, "abstract sockets belong to the host's network namespace");
    assert.equal(A("dns_lookup").startsWith("err:"), true, A("dns_lookup"));
    assert.equal(A("interfaces"), "ok:lo", "only the sandbox's own loopback exists");
    assert.equal(C("interfaces"), "ok:lo");
    // A datagram "sent" to the sandbox's own loopback never reaches the host listener; only the Network On launch does.
    assert.equal(A("udp_loopback"), "ok:sent");
    assert.equal(udpReceived.filter((m) => m === "pbs-probe").length, 1, "exactly one datagram (the Network On launch) reached the host");
});

t("LIMITED: a unix socket whose path is not mounted cannot be reached (host daemons, D-Bus, ssh-agent, X11/Wayland files)", () => {
    assert.equal(A("unix_fs_outside"), "err:ENOENT");
    assert.equal(B("unix_fs_outside"), "err:ENOENT", "Network On does not mount host paths either");
});

t("LIMITED: host processes are invisible and unreachable (private PID namespace, no /proc)", () => {
    assert.equal(A("proc_listing"), "err:ENOENT");
    assert.equal(A("kill_host_pid"), "err:ESRCH");
    assert.equal(A("kill_host_parent"), "err:ESRCH");
    assert.equal(A("ptrace_host_pid"), "err:ESRCH");
    assert.match(A("own_pid"), /^ok:[1-9]\d?$/, "pids restart low in the private namespace");
});

t("LIMITED: /dev is a minimal synthetic set; GPU, DRM, disks and the controlling tty are absent", () => {
    const allowed = new Set(["null", "zero", "full", "random", "urandom", "tty", "ptmx", "pts", "shm", "fd", "stdin", "stdout", "stderr", "core"]);
    const listing = A("dev_listing").replace(/^ok:/, "").split(",");
    assert.deepEqual(listing.filter((name) => !allowed.has(name)), [], "unexpected device nodes");
    for (const node of ["kfd", "dri", "snd", "video0", "nvidiactl", "fuse", "kvm", "mem", "net"]) {
        assert.equal(A(`dev_${node}`), "err:ENOENT", node);
    }
    assert.match(A("dev_tty_open"), /^err:ENXIO$/, "--new-session: no controlling terminal");
    assert.equal(A("dev_null_write"), "ok:wrote");
});

t("LIMITED: no privilege gain: unchanged uid, no_new_privs set, no effective capabilities", () => {
    assert.equal(A("no_new_privs"), "ok:1");
    assert.equal(A("effective_uid"), `ok:${userInfo().uid}`);
    assert.equal(A("uid"), `ok:${userInfo().uid}`);
    assert.equal(A("capabilities_effective"), "ok:0x0");
});

t("LIMITED: environment is cleared; only PATH and a minimal set reach the child", () => {
    assert.equal(A("env_secret_visible"), "ok:False");
    assert.equal(A("env_secret_visible"), B("env_secret_visible"));
});

t("LIMITED: the filesystem seen is the synthetic root", () => {
    const entries = A("cwd_listing").replace(/^ok:/, "").split(",");
    assert.ok(entries.includes("usr") && entries.includes("tmp") && entries.includes("dev"));
    for (const hidden of ["home-of-host-user", "etc", "run", "var", "proc", "sys", "mnt", "opt", "root", "srv", "boot"]) {
        assert.equal(entries.includes(hidden), false, `${hidden} must not exist in the synthetic root`);
    }
});

// ---- NOT LIMITED / PARTIAL (documented expectations) ------------------------------
t("NOT LIMITED: any binary readable by absolute path runs, including one the agent wrote into a writable root", () => {
    assert.equal(A("exec_abs"), `ok:rc=0 ${userInfo().uid}`);
    assert.match(A("exec_written_in_project"), /^ok:rc=0 ran$/, "writable roots are not mounted noexec");
});

t("NOT LIMITED: a unix socket on any mounted path is connectable, even Network Off and even on a read-only mount", () => {
    assert.equal(A("unix_fs_in_project"), "ok:connected");
    assert.equal(C("unix_fs_in_readonly_mount"), "ok:connected");
});

t("NOT LIMITED: Network On is the host network (loopback, LAN, abstract unix sockets such as X11), not a filtered one", () => {
    assert.equal(B("tcp_loopback"), "ok:connected");
    if (hostSockets.lanAddress) assert.equal(B("tcp_lan"), "ok:connected");
    assert.equal(B("udp_loopback"), "ok:sent");
    assert.equal(B("unix_abstract"), "ok:connected");
    assert.match(B("interfaces"), /lo/);
    assert.ok(B("interfaces").split(",").length > 1 || !hostSockets.lanAddress, "host interfaces are visible");
});

t("PARTIAL: with Network On names still do not resolve: the resolver configuration is not mounted (an IP literal connects)", () => {
    assert.equal(B("dns_lookup").startsWith("err:"), true, B("dns_lookup"));
    assert.equal(B("tcp_loopback"), "ok:connected");
});

t("NOT LIMITED: SysV shared memory and POSIX message queues are the host's IPC namespace", () => {
    if (sysv.shmId < 0) return;
    assert.equal(A("sysv_shm_attach_host_segment"), "ok:attached");
    if (sysv.mqName) assert.equal(A("posix_mq_open_host_queue"), "ok:opened");
});

t("NOT LIMITED: the kernel keyring is the caller's (a host user key is readable by id)", () => {
    if (sysv.keyId <= 0) return;
    assert.equal(A("keyctl_read_host_key"), "ok:key-payload");
});

t("NOT LIMITED: inherited file descriptors above 2 stay open and readable", () => {
    assert.equal(A("inherited_fd3"), "ok:outside-secret\n");
});

t("NOT LIMITED: hostname, uid and clock are the host's; resource limits are inherited unchanged", () => {
    assert.equal(A("hostname"), `ok:${hostname()}`);
    assert.equal(A("clock_skew_seconds"), "ok:True");
    const probeLimits = hostLibc(`import resource,sys;print(resource.getrlimit(resource.RLIMIT_NPROC),resource.getrlimit(resource.RLIMIT_AS),resource.getrlimit(resource.RLIMIT_FSIZE),resource.getrlimit(resource.RLIMIT_NOFILE),sep="|")`).stdout.trim().split("|");
    assert.deepEqual([A("rlimit_nproc"), A("rlimit_as"), A("rlimit_fsize"), A("rlimit_nofile")].map((v) => v.replace(/^ok:/, "")), probeLimits);
});

t("NOT LIMITED: a user namespace can be created inside (it grants nothing on the host, but widens kernel attack surface)", () => {
    assert.equal(A("nested_user_namespace"), "ok:True");
});

t("PARTIAL: an approved tool's config folder is readable whole; files matching the secret detector are refused", () => {
    assert.equal(C("read_approved_config"), "ok:setting=1\n");
    assert.equal(C("read_approved_config_unrelated"), "ok:any file in an approved config dir is re");
    assert.equal(C("read_approved_config_secret"), "err:ENOENT");
    assert.equal(A("read_approved_config"), "err:ENOENT", "without the approval the folder is not mounted");
});

t("NOT LIMITED: a symlink in the project to a folder is followed read-only at launch", () => {
    assert.equal(A("read_via_project_symlink"), "ok:linked-secret\n");
    assert.equal(A("exec_via_project_symlink"), "ok:rc=0 linked-binary-ran", "and its executables run");
});
