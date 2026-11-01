/**
 * Confined-launch hardening with real bubblewrap: a confined launch gets a private IPC namespace and a private UTS
 * namespace (fixed or policy-named hostname), cannot create user namespaces, cannot use the kernel keyring,
 * and each `hardening` switch set to `false` removes exactly its own measure (the old behaviour returns while
 * the other measures stay in force). Launches go through the package's own controller, frozen plan and
 * argument builder (the foreground shell operations); nothing hand-writes bubblewrap arguments.
 *
 * Covers the private IPC and hostname, user-namespace, keyring and per-switch behaviour (the real-bubblewrap half of the switch proof).
 * Expected results come from kernel and bubblewrap semantics (a SysV id of another IPC namespace is EINVAL,
 * `--disable-userns` makes CLONE_NEWUSER fail, a seccomp filter makes keyctl/add_key/request_key fail with
 * EPERM or ENOSYS), not from the product's output.
 *
 * Skips cleanly without bubblewrap, a working user namespace, python3, or a non-scratch fixture base; with
 * PI_SANDBOX_REQUIRE_BACKEND set, a missing or unusable bubblewrap fails instead of skipping.
 * Host resources created (a SysV segment, a POSIX queue, a user key) are removed afterwards.
 * @level kernel
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import test, { after, before } from "node:test";

import { buildSandboxCommand } from "../shared-sandbox-core.ts";
import type { ForegroundSandboxController } from "../state.ts";
import {
    GIT, baseSkip, confinedExec, controllerFor, createHostResources, hostKeyringUsable, lookupWith, makeFixture,
    q, rawPolicy, removeHostResources, runProbe, syscalls, writeFakeBwrap, type Fixture, type HostResources,
} from "./support/hardening-support.ts";

const skip = baseSkip();
const CONFIGURED_HOSTNAME = "pbs-test-host";
const DENIED = /^err:(EPERM|ENOSYS)$/;

let fx: Fixture;
let res: HostResources = { shmId: -1, mqName: "", keyId: -1 };
const controllers: ForegroundSandboxController[] = [];
const runs: Record<string, Record<string, string>> = {};
let keyringProvable = false;

const VARIANTS: Record<string, Record<string, unknown> | undefined> = {
    default: undefined,
    ipcOff: { ipc: false },
    utsOff: { uts: false },
    usernsOff: { userns: false },
    keyringOff: { keyring: false },
    hostnameSet: { hostname: CONFIGURED_HOSTNAME },
    allOff: { ipc: false, uts: false, userns: false, keyring: false, fds: false },
};

before(async () => {
    if (skip) return;
    fx = makeFixture("pbs-hardening-");
    res = createHostResources();
    keyringProvable = hostKeyringUsable();
    for (const [name, hardening] of Object.entries(VARIANTS)) {
        const controller = controllerFor(fx, rawPolicy(fx, hardening));
        controllers.push(controller);
        runs[name] = await runProbe(controller, fx, res);
    }
    if (process.env.PI_SANDBOX_LIMITS_DUMP) console.error(JSON.stringify(runs, null, 1));
});

after(() => {
    for (const controller of controllers) controller.dispose();
    removeHostResources(res);
    if (fx) rmSync(fx.root, { recursive: true, force: true });
});

/** A test that skips (with its reason) when the environment, or a precondition evaluated at run time, does not allow it. */
const t = (name: string, body: () => void | Promise<void>, precondition: () => string | false = () => false) =>
    test(name, { skip }, async (context) => {
        const reason = precondition();
        if (reason) return context.skip(reason);
        await body();
    });
const R = (variant: string, name: string): string => runs[variant]?.[name] ?? `missing:${variant}.${name}`;
const noShm = () => (res.shmId >= 0 ? false : "the host cannot create a SysV segment here");
const noMq = () => (res.mqName ? false : "the host cannot create a POSIX queue here");
const noKeyring = () => (!syscalls ? `keyring probes need syscall numbers for this architecture (${process.arch})` : false);
const noHostKey = () => noKeyring() || (!keyringProvable ? "the host kernel or container already denies keyctl, so a filter cannot be told apart" : res.keyId > 0 ? false : "no host key could be created");

// ---- ipc-uts ----------------------------------------------------------------------
t("[ipc-uts] a host SysV shared-memory segment is not visible inside a confined launch; with ipc=false it is attachable again", () => {
    assert.match(R("default", "shm_attach"), /^err:/, "another IPC namespace has no such id");
    assert.equal(R("ipcOff", "shm_attach"), "ok:attached", "switch off: the host's segment is reachable (the old behaviour)");
}, noShm);

t("[ipc-uts] a host POSIX message queue is not visible inside; with ipc=false it opens again", () => {
    assert.match(R("default", "mq_open"), /^err:/);
    assert.equal(R("ipcOff", "mq_open"), "ok:opened");
}, noMq);

t("[ipc-uts] the hostname inside is not the host's and is never empty", () => {
    const inside = R("default", "hostname");
    assert.match(inside, /^ok:.+/);
    assert.notEqual(inside, `ok:${hostname()}`);
});

t("[ipc-uts] a hostname named by the policy is the one used", () => {
    assert.notEqual(CONFIGURED_HOSTNAME, hostname(), "the configured name differs from the host's, so the check is meaningful");
    assert.equal(R("hostnameSet", "hostname"), `ok:${CONFIGURED_HOSTNAME}`);
});

// ---- userns -----------------------------------------------------------------------
t("[userns] a nested user namespace cannot be created inside (syscall and `unshare -U true`); userns=false restores it", () => {
    assert.match(R("default", "userns_syscall"), /^err:/, "unshare(CLONE_NEWUSER) must fail (bubblewrap's --disable-userns yields ENOSPC)");
    const cmd = R("default", "unshare_cmd");
    if (cmd !== "ok:n/a") assert.notEqual(cmd, "ok:rc=0", "`unshare -U /usr/bin/true` must fail (exit 1, not 127: the command itself resolves)");
    assert.equal(R("usernsOff", "userns_syscall"), "ok:created", "switch off: nested user namespaces work again (the old behaviour)");
    if (cmd !== "ok:n/a") assert.equal(R("usernsOff", "unshare_cmd"), "ok:rc=0");
});

t("[userns] the user and group seen inside, and the owner of project files, are unchanged", () => {
    assert.equal(R("default", "uid"), `ok:${process.getuid!()}`);
    assert.equal(R("default", "gid"), `ok:${process.getgid!()}`);
    assert.equal(R("default", "project_owner"), `ok:${process.getuid!()}`, "files the user owns still look owned by that user");
});

const gitEnv = {
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid",
    GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid", GIT_TERMINAL_PROMPT: "0",
};
function hostGit(cwd: string, ...args: string[]): string {
    const out = spawnSync(GIT, ["-c", "protocol.file.allow=always", ...args], { cwd, encoding: "utf8", env: { ...process.env, ...gitEnv, HOME: fx.home } });
    assert.equal(out.status, 0, `git ${args.join(" ")}: ${out.stderr}`);
    return out.stdout;
}
function gitLayouts() {
    const dir = join(fx.root, "layouts");
    const lib = join(dir, "lib"), main = join(dir, "main");
    mkdirSync(lib, { recursive: true });
    mkdirSync(main, { recursive: true });
    hostGit(lib, "init", "-q");
    hostGit(lib, "commit", "-q", "--allow-empty", "-m", "lib");
    hostGit(main, "init", "-q");
    writeFileSync(join(main, "a.txt"), "a\n");
    hostGit(main, "add", "a.txt");
    hostGit(main, "commit", "-q", "-m", "first");
    hostGit(main, "submodule", "add", "-q", lib, "sm");
    hostGit(main, "commit", "-q", "-m", "sub");
    hostGit(main, "worktree", "add", "-q", "-b", "wt", join(dir, "wt"));
    return { main, wt: join(dir, "wt"), sm: join(main, "sm") };
}

t("[userns] git status, add, commit and log work in a main repository, a linked worktree and a submodule", async () => {
    for (const [name, project] of Object.entries(gitLayouts())) {
        const layoutFx: Fixture = { ...fx, project };
        const controller = controllerFor(layoutFx, rawPolicy(layoutFx));
        controllers.push(controller);
        const script = `export PATH=/usr/bin:/bin ${Object.entries(gitEnv).map(([k, v]) => `${k}=${v}`).join(" ")}; cd ${q(project)}; `
            + `${GIT} status --short && echo ${name} > n.txt && ${GIT} add n.txt && ${GIT} commit -q -m via-${name} && ${GIT} log --oneline`;
        const out = await confinedExec(controller, layoutFx, script, { timeoutSeconds: 60 });
        assert.equal(out.exitCode, 0, `${name}: ${out.output}`);
        assert.match(out.output, new RegExp(`via-${name}`), `${name}: the commit is in the log`);
        assert.match(hostGit(project, "log", "--oneline"), new RegExp(`via-${name}`), `${name}: and on the host`);
    }
}, () => (existsSync(GIT) ? false : "git is required"));

// ---- keyring ----------------------------------------------------------------------
t("[keyring] keyctl, add_key and request_key fail with EPERM or ENOSYS inside; a host user key is not readable by id", () => {
    for (const name of ["keyctl_user_keyring", "add_key", "request_key"]) assert.match(R("default", name), DENIED, name);
    if (res.keyId > 0) assert.match(R("default", "keyctl_read_host_key"), DENIED, "keyctl_read_host_key");
}, noKeyring);

t("[keyring] keyring=false restores the old behaviour: the host user key is readable by id", () => {
    assert.equal(R("keyringOff", "keyctl_read_host_key"), "ok:key-payload");
    assert.equal(R("keyringOff", "keyctl_user_keyring"), "ok:id");
    assert.doesNotMatch(R("keyringOff", "request_key"), DENIED);
}, noHostKey);

t("[keyring] ordinary tools still run in a confined launch: shell, git, node and (when installed) cmake", async () => {
    const node = realpathSync(process.execPath);
    const raw = rawPolicy(fx, undefined, { tools: { approved: ["sh", "cat", { path: node, install: "prefix" }], builtinDefaults: false } });
    const controller = controllerFor(fx, raw);
    controllers.push(controller);
    assert.equal(controller.readConfinementRecord()?.active, true, "the policy with an approved node prefix plans cleanly");
    const checks: [string, string, RegExp][] = [
        ["shell", "echo shell-ok", /shell-ok/],
        ["git", `${GIT} --version`, /git version/],
        ["node", `${q(node)} -e "process.stdout.write('node-ok')"`, /node-ok/],
    ];
    if (existsSync("/usr/bin/cmake")) checks.push(["cmake", "/usr/bin/cmake --version", /cmake version/]);
    for (const [name, command, expected] of checks) {
        const out = await confinedExec(controller, fx, `export PATH=/usr/bin:/bin; ${command}`, { timeoutSeconds: 60 });
        assert.equal(out.exitCode, 0, `${name}: ${out.output}`);
        assert.match(out.output, expected, name);
    }
});

// ---- switches: each false removes exactly its own measure ---------------------------
function measuresHeld(variant: string, except: "ipc" | "uts" | "userns" | "keyring"): void {
    if (except !== "ipc" && res.shmId >= 0) assert.match(R(variant, "shm_attach"), /^err:/, `${variant}: ipc stays private`);
    if (except !== "uts") assert.notEqual(R(variant, "hostname"), `ok:${hostname()}`, `${variant}: uts stays private`);
    if (except !== "userns") assert.match(R(variant, "userns_syscall"), /^err:/, `${variant}: userns stays blocked`);
    if (except !== "keyring" && syscalls) assert.match(R(variant, "keyctl_user_keyring"), DENIED, `${variant}: keyring stays blocked`);
}

t("[switches] ipc=false removes only the IPC namespace", () => {
    assert.equal(R("ipcOff", "shm_attach"), "ok:attached");
    measuresHeld("ipcOff", "ipc");
}, noShm);

t("[switches] uts=false removes only the UTS namespace: the hostname is the host's again", () => {
    assert.equal(R("utsOff", "hostname"), `ok:${hostname()}`);
    measuresHeld("utsOff", "uts");
});

t("[switches] userns=false removes only the user-namespace block", () => {
    assert.equal(R("usernsOff", "userns_syscall"), "ok:created");
    measuresHeld("usernsOff", "userns");
});

t("[switches] keyring=false removes only the keyring filter", () => {
    assert.doesNotMatch(R("keyringOff", "keyctl_user_keyring"), DENIED);
    measuresHeld("keyringOff", "keyring");
}, noHostKey);

t("[switches] all five switches false give the pre-hardening behaviour", () => {
    assert.equal(R("allOff", "hostname"), `ok:${hostname()}`);
    assert.equal(R("allOff", "userns_syscall"), "ok:created");
    if (res.shmId >= 0) assert.equal(R("allOff", "shm_attach"), "ok:attached");
    if (res.mqName) assert.equal(R("allOff", "mq_open"), "ok:opened");
    if (syscalls && keyringProvable) assert.doesNotMatch(R("allOff", "keyctl_user_keyring"), DENIED);
});

t("[switches] the documented bubblewrap flags are present by default and absent with every switch off", () => {
    const flagsOf = (hardening: Record<string, unknown> | undefined): string[] => {
        const controller = controllerFor(fx, rawPolicy(fx, hardening));
        controllers.push(controller);
        const plan = controller.requireLaunchPlan();
        assert.ok(plan.confined);
        return buildSandboxCommand({ profilePath: plan.profilePath, execPath: "/bin/sh", execArgs: ["-c", "true"], policy: plan.policy }, { env: {} }).fileArgs;
    };
    const on = flagsOf(undefined);
    for (const flag of ["--unshare-ipc", "--unshare-uts", "--hostname", "--disable-userns"]) assert.ok(on.includes(flag), `default argv has ${flag}`);
    assert.ok(on.includes("--seccomp") || on.includes("--add-seccomp-fd"), "default argv passes a seccomp program");
    const hostnameValue = on[on.indexOf("--hostname") + 1];
    assert.ok(hostnameValue && !hostnameValue.startsWith("--") && hostnameValue !== hostname(), "a fixed non-host hostname is passed");
    const off = flagsOf(VARIANTS.allOff);
    for (const flag of ["--unshare-ipc", "--unshare-uts", "--hostname", "--disable-userns", "--seccomp", "--add-seccomp-fd"]) {
        assert.equal(off.includes(flag), false, `with every switch off the argv has no ${flag}`);
    }
});

// ---- fail closed -------------------------------------------------------------------
async function attempt(hardening: Record<string, unknown> | undefined, fake: string): Promise<{ ran: boolean; detail: string }> {
    const seams = lookupWith(fake);
    const controller = controllerFor(fx, rawPolicy(fx, hardening), seams);
    controllers.push(controller);
    try {
        const out = await confinedExec(controller, fx, "echo CMD-RAN-MARK", { seams, timeoutSeconds: 30 });
        return { ran: out.exitCode === 0 && out.output.includes("CMD-RAN-MARK"), detail: out.output };
    } catch (error) {
        return { ran: false, detail: error instanceof Error ? error.message : String(error) };
    }
}

t("[switches] a measure that is on but cannot be applied fails the launch closed; switching it off lets the launch run", async () => {
    const fakes = join(fx.root, "fake");
    mkdirSync(fakes, { recursive: true });
    const noUserns = writeFakeBwrap(fakes, "bwrap-no-disable-userns", ["--disable-userns", "--assert-userns-disabled"], "0.4.1");
    const noSeccomp = writeFakeBwrap(fakes, "bwrap-no-seccomp", ["--seccomp", "--add-seccomp-fd"]);
    const control = await attempt({ userns: false, keyring: false }, noUserns);
    assert.equal(control.ran, true, `control (both measures off) runs with the old bubblewrap: ${control.detail}`);
    const userns = await attempt({ keyring: false }, noUserns);
    assert.equal(userns.ran, false, "userns on without --disable-userns support: the command must not run unconfined");
    const keyring = await attempt({ userns: false }, noSeccomp);
    assert.equal(keyring.ran, false, "keyring on without seccomp support: the command must not run unfiltered");
    const keyringOff = await attempt({ keyring: false }, noSeccomp);
    assert.equal(keyringOff.ran, true, `keyring off needs no seccomp support: ${keyringOff.detail}`);
});
