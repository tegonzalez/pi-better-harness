/**
 * The real controller and launch path in the three git layouts (main repo, linked worktree, submodule
 * folder) with the PACKAGED default deny rules: the launch must build, hooks must be protected where git
 * reads them, a redirected `.git` file must be refused, and `/sandbox check` must model the private /tmp.
 * Real git and real bubblewrap; fixtures live under a non-temp base (override: PI_SANDBOX_TEST_NON_TEMP_BASE).
 * @level integration
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join, sep } from "node:path";
import test, { after } from "node:test";

import { defaultSandboxPermissions } from "../permissions.ts";
import { PACKAGED_DENY_WRITE_TEMPLATES } from "../policy.ts";
import { buildSandboxCommand } from "../shared-sandbox-core.ts";
import { hashPolicy, parseReadConfinementPolicy } from "../shared-read-confinement.ts";
import { ForegroundSandboxController } from "../state.ts";
import { nonTempBase } from "./support/fixture-base.ts";
import { realBackendSkip } from "./support/resolvable-backend.ts";

const GIT = "/usr/bin/git";
const base = nonTempBase();
const skip = base === undefined ? "no writable non-temp fixture base" : !existsSync(GIT) ? "git is required" : process.platform !== "linux" ? "Linux bubblewrap only" : realBackendSkip();

const fixtures = base ? realpathSync(mkdtempSync(join(base, "pi-better-sandbox-gitlayouts-"))) : "";
const home = join(fixtures, "home");
const agentDir = join(fixtures, "agent");
const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
const originalPolicyEnv = process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY;
if (fixtures) {
    mkdirSync(home, { recursive: true });
    mkdirSync(agentDir, { recursive: true });
    process.env.PI_CODING_AGENT_DIR = agentDir;
    delete process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY;
}
after(() => {
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
    if (originalPolicyEnv === undefined) delete process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY; else process.env.PI_SANDBOX_READ_CONFINEMENT_POLICY = originalPolicyEnv;
    if (fixtures) rmSync(fixtures, { recursive: true, force: true });
});

const gitEnv = {
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid",
    GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid", GIT_TERMINAL_PROMPT: "0",
};
function host(cwd: string, ...args: string[]): string {
    const out = spawnSync(GIT, ["-c", "protocol.file.allow=always", ...args], { cwd, encoding: "utf8", env: { ...process.env, ...gitEnv, HOME: home } });
    assert.equal(out.status, 0, `git ${args.join(" ")}: ${out.stderr}`);
    return out.stdout;
}

function layout(name: string) {
    const dir = join(fixtures, name);
    const lib = join(dir, "lib");
    const main = join(dir, "main");
    mkdirSync(lib, { recursive: true });
    mkdirSync(main, { recursive: true });
    host(lib, "init", "-q");
    host(lib, "commit", "-q", "--allow-empty", "-m", "lib");
    host(main, "init", "-q");
    writeFileSync(join(main, "a.txt"), "a\n");
    host(main, "add", "a.txt");
    host(main, "commit", "-q", "-m", "first");
    host(main, "submodule", "add", "-q", lib, "sm");
    host(main, "commit", "-q", "-m", "sub");
    host(main, "worktree", "add", "-q", "-b", "wt", join(dir, "wt"));
    const common = join(main, ".git");
    return {
        main: { project: main, hooks: [join(common, "hooks")], gitDirs: [common], victim: join(dir, "lib") },
        wt: { project: join(dir, "wt"), hooks: [join(common, "worktrees", "wt", "hooks"), join(common, "hooks")], gitDirs: [join(common, "worktrees", "wt"), common], victim: join(dir, "lib") },
        sm: { project: join(main, "sm"), hooks: [join(common, "modules", "sm", "hooks")], gitDirs: [join(common, "modules", "sm")], victim: join(dir, "lib") },
    };
}

const rawPolicy = { version: 1 as const, tools: { approved: ["sh", "cat"], builtinDefaults: false } };

function controllerFor(project: string, policy: { version: 1; [key: string]: unknown } = rawPolicy): ForegroundSandboxController {
    const controller = new ForegroundSandboxController({
        home: () => home,
        readConfinement: {
            loadPolicy: () => ({ policy: parseReadConfinementPolicy(policy), source: "fixture-policy", sha256: hashPolicy(policy) }),
            plan: { passwdHomes: () => [], env: { PATH: "/usr/bin:/bin" } },
        },
    });
    controller.beginSession(project);
    const settings = defaultSandboxPermissions();
    settings.main = { ...settings.main, enabled: true, projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false };
    controller.setPermissionSettings(settings);
    assert.deepEqual([...controller.denyWriteTemplates()], [...PACKAGED_DENY_WRITE_TEMPLATES], "the packaged default deny rules are in force");
    return controller;
}

function run(controller: ForegroundSandboxController, project: string, script: string) {
    const launch = controller.requireLaunchPlan();
    assert.ok(launch.confined);
    const command = buildSandboxCommand({
        profilePath: launch.profilePath, execPath: "/bin/sh",
        execArgs: ["-c", `export PATH=/usr/bin:/bin ${Object.entries(gitEnv).map(([k, v]) => `${k}=${v}`).join(" ")}; cd '${project}'; ${script}`],
        policy: launch.policy,
    }, { env: { HOME: home } });
    return spawnSync(command.file, command.fileArgs, { encoding: "utf8", env: { HOME: home } });
}

test("every layout launches with the packaged deny rules; hooks are protected where git reads them; git works", { skip }, () => {
    const layouts = layout("layouts");
    for (const [name, { project, hooks }] of Object.entries(layouts)) {
        const controller = controllerFor(project);
        try {
            const ok = run(controller, project, `/usr/bin/git status --short && echo ${name} > n.txt && /usr/bin/git add n.txt && /usr/bin/git commit -q -m via-${name}`);
            assert.equal(ok.status, 0, `${name}: ${ok.stdout}${ok.stderr}`);
            assert.match(host(project, "log", "--oneline"), new RegExp(`via-${name}`));
            for (const dir of hooks) {
                const attack = run(controller, project, `echo '#!/bin/sh' > '${dir}/pre-commit'`);
                assert.notEqual(attack.status, 0, `${name}: write to ${dir}`);
                assert.equal(existsSync(join(dir, "pre-commit")), false, `${name}: ${dir}`);
            }
            assert.notEqual(run(controller, project, "echo x > .env").status, 0, "the project's .env stays denied");
            const probe = controller.checkPath(join(hooks[0]!, "pre-commit"));
            assert.equal(probe.write.allowed, false, `${name}: /sandbox check agrees (hooks are not writable)`);
        } finally { controller.dispose(); }
    }
});

test("a redirected .git file cannot be written in the session and a planted in-project target fails the next launch closed", { skip }, () => {
    const { wt, sm } = layout("redirect");
    for (const { project } of [wt, sm]) {
        const controller = controllerFor(project);
        try {
            const original = readFileSync(join(project, ".git"), "utf8");
            const attack = run(controller, project, `/usr/bin/git init -q --bare evilgit && printf 'gitdir: ${project}/evilgit' > .git`);
            assert.notEqual(attack.status, 0);
            assert.equal(readFileSync(join(project, ".git"), "utf8"), original);
            assert.notEqual(run(controller, project, "rm -f .git").status, 0);
            assert.notEqual(run(controller, project, "mv .git .git.x").status, 0);
        } finally { controller.dispose(); }
        // The agent could not do it in-session; if the redirect exists anyway (host-side), the next session refuses it.
        host(project, "init", "-q", "--bare", "evilgit2");
        writeFileSync(join(project, ".git"), `gitdir: ${join(project, "evilgit2")}\n`);
        const next = controllerFor(project);
        try {
            const record = next.readConfinementRecord();
            assert.equal(record?.active, false);
            assert.match(record && !record.active ? record.reason : "", /writable root/);
            assert.throws(() => next.requireLaunchPlan(), /Read confinement failed closed/);
        } finally { next.dispose(); }
    }
});

test("/sandbox check models the private /tmp: writable scratch, not the host's files", { skip }, () => {
    const { main } = layout("tmpcheck");
    const controller = controllerFor(main.project);
    const marker = mkdtempSync("/tmp/pi-check-host-");
    try {
        writeFileSync(join(marker, "host.txt"), "host");
        const fresh = controller.checkPath("/tmp/x");
        assert.equal(fresh.write.allowed, true, fresh.write.reason);
        assert.match(fresh.write.reason, /private tmpfs/);
        assert.equal(fresh.read.allowed, true);
        const kernel = run(controller, main.project, "echo hi > /tmp/x && cat /tmp/x");
        assert.equal(kernel.status, 0, kernel.stderr);
        assert.equal(run(controller, main.project, `test -e '${join(marker, "host.txt")}'`).status, 1, "the host's /tmp content is not visible");
        assert.equal(controller.checkPath(join(main.project, "a.txt")).write.allowed, true);
    } finally {
        rmSync(marker, { recursive: true, force: true });
        controller.dispose();
    }
});

// ---- every guarded git file, every layout, kernel + in-process parity -----------------------------------
const GUARDED_FILES = ["commondir", "gitdir", "config", "config.worktree", "info/attributes", "objects/info/alternates", "objects/info/http-alternates"];
const snapshot = (path: string): string => {
    const info = lstatSync(path);
    return `${info.ino}:${info.isDirectory() ? readdirSync(path).sort().join(",") : readFileSync(path, "utf8")}`;
};

test("every guarded git file and dir is unwritable and unreplaceable in main, linked-worktree and submodule layouts (kernel and in-process)", { skip }, () => {
    const layouts = layout("guarded");
    for (const [name, { project, gitDirs }] of Object.entries(layouts)) {
        const controller = controllerFor(project);
        try {
            const nodes = gitDirs.flatMap((dir) => [...GUARDED_FILES.map((rel) => join(dir, rel)), join(dir, "hooks")]);
            if (name !== "main") nodes.push(join(project, ".git"));
            for (const node of nodes) {
                assert.ok(existsSync(node), `${name}: ${node} exists after planning`);
                const before = snapshot(node);
                const isDir = lstatSync(node).isDirectory();
                const attacks = isDir
                    ? [`touch '${node}/x'`, `rm -rf '${node}'`, `mv '${node}' '${node}.x'`, `mv '${node}' '${node}.x' && mkdir '${node}'`]
                    : [`echo x >> '${node}'`, `: > '${node}'`, `rm -f '${node}'`, `mv '${node}' '${node}.x'`,
                        `echo x > '${node}.new' && mv '${node}.new' '${node}'`, `ln -f '${node}' '${node}.hl' && echo x > '${node}.hl'`];
                for (const attack of attacks) {
                    const out = run(controller, project, attack);
                    assert.notEqual(out.status, 0, `${name}: ${attack}`);
                    assert.equal(snapshot(node), before, `${name}: ${attack} changed ${node}`);
                    assert.equal(existsSync(`${node}.x`), false, `${name}: ${node}.x`);
                }
                const probe = controller.checkPath(isDir ? join(node, "x") : node);
                assert.equal(probe.write.allowed, false, `${name}: in-process parity for ${node}`);
            }
            // Ancestors of guarded nodes cannot be renamed or removed to rebuild them (the mounts below pin them).
            for (const dir of gitDirs) {
                for (const rel of ["info", "objects/info", "objects"]) {
                    const node = join(dir, rel);
                    for (const attack of [`mv '${node}' '${node}.x'`, `rmdir '${node}'`]) {
                        assert.notEqual(run(controller, project, attack).status, 0, `${name}: ${attack}`);
                        assert.ok(existsSync(join(dir, "objects", "info", "alternates")), `${name}: ${attack}`);
                        assert.equal(existsSync(`${node}.x`), false, `${name}: ${node}.x`);
                    }
                }
                if (dir !== gitDirs[gitDirs.length - 1]) {
                    for (const attack of [`mv '${dir}' '${dir}.x'`, `mv '${join(dir, "..")}' '${join(dir, "..")}.x'`]) {
                        assert.notEqual(run(controller, project, attack).status, 0, `${name}: ${attack}`);
                    }
                }
            }
            const ok = run(controller, project, `echo g > g.txt && /usr/bin/git add g.txt && /usr/bin/git commit -q -m guarded-${name}`);
            assert.equal(ok.status, 0, `${name}: ${ok.stdout}${ok.stderr}`);
        } finally { controller.dispose(); }
    }
});

test("mount order: no writable bind after a read-only overlay on the same path or below it (every layout)", { skip }, () => {
    const layouts = layout("order");
    for (const [name, { project }] of Object.entries(layouts)) {
        const controller = controllerFor(project);
        try {
            const launch = controller.requireLaunchPlan();
            assert.ok(launch.confined);
            const command = buildSandboxCommand({ profilePath: launch.profilePath, execPath: "/bin/true", execArgs: [], policy: launch.policy }, { env: { HOME: home } });
            const args = command.fileArgs;
            const mounts: { index: number; rw: boolean; dest: string }[] = [];
            for (let i = 0; i < args.length; i++) {
                const option = args[i]!;
                if (/^--(ro-)?bind(-try)?$/.test(option)) { mounts.push({ index: i, rw: !option.startsWith("--ro-"), dest: args[i + 2]! }); i += 2; }
            }
            assert.ok(mounts.some((m) => !m.rw) && mounts.some((m) => m.rw));
            const covers = (outer: string, inner: string) => inner === outer || inner.startsWith(outer.endsWith(sep) ? outer : outer + sep);
            for (const later of mounts.filter((m) => m.rw)) {
                for (const earlier of mounts.filter((m) => !m.rw && m.index < later.index)) {
                    // A writable bind hides every earlier read-only mount at or below it, unless that path is
                    // read-only mounted again after it (the guards are laid last).
                    if (mounts.some((m) => !m.rw && m.index > later.index && m.dest === earlier.dest)) continue;
                    assert.equal(covers(later.dest, earlier.dest), false, `${name}: writable ${later.dest} (arg ${later.index}) hides read-only ${earlier.dest} (arg ${earlier.index})`);
                }
            }
        } finally { controller.dispose(); }
    }
});

// ---- V4-2: alternates under a nested git dir -------------------------------------------------------------
test("alternates in an agent-created modules/<x> pointing at another repository fail the next launch closed in every layout; readOnly opts in", { skip }, () => {
    const layouts = layout("alternates");
    for (const [name, { project, gitDirs, victim }] of Object.entries(layouts)) {
        const secret = spawnSync(GIT, ["hash-object", "-w", "--stdin"], { cwd: victim, input: `VICTIMSECRET-${name}`, encoding: "utf8", env: { ...process.env, ...gitEnv, HOME: home } }).stdout.trim();
        const modulesDir = join(gitDirs[gitDirs.length - 1]!, "modules", "evil");
        const first = controllerFor(project);
        try {
            const made = run(first, project, `mkdir -p '${modulesDir}/objects/info' '${modulesDir}/objects/pack' '${modulesDir}/refs' && echo 'ref: refs/heads/x' > '${modulesDir}/HEAD' && echo '${join(victim, ".git", "objects")}' > '${modulesDir}/objects/info/alternates'`);
            assert.equal(made.status, 0, `${name}: the agent can create an unguarded modules/<x>: ${made.stderr}`);
        } finally { first.dispose(); }
        const next = controllerFor(project);
        try {
            const record = next.readConfinementRecord();
            assert.equal(record?.active, false, `${name}: next launch fails closed`);
            assert.match(record && !record.active ? record.reason : "", /nested git directory/, name);
            assert.throws(() => next.requireLaunchPlan(), /Read confinement failed closed/);
        } finally { next.dispose(); }
        // Opt-in: a policy readOnly entry naming the victim honours the alternate and the object is readable.
        const optIn = controllerFor(project, { ...rawPolicy, readOnly: [join(victim, ".git")] });
        try {
            const out = run(optIn, project, `GIT_DIR='${modulesDir}' /usr/bin/git cat-file -p ${secret}`);
            assert.equal(out.status, 0, `${name}: ${out.stderr}`);
            assert.equal(out.stdout, `VICTIMSECRET-${name}`);
        } finally { optIn.dispose(); }
        rmSync(modulesDir, { recursive: true, force: true });
    }
});
