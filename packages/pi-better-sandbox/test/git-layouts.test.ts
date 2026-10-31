/**
 * The real controller and launch path in the three git layouts (main repo, linked worktree, submodule
 * folder) with the PACKAGED default deny rules: the launch must build, hooks must be protected where git
 * reads them, a redirected `.git` file must be refused, and `/sandbox check` must model the private /tmp.
 * Real git and real bubblewrap; fixtures live under a non-temp base (override: PI_SANDBOX_TEST_NON_TEMP_BASE).
 * @level integration
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
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
        main: { project: main, hooks: [join(common, "hooks")] },
        wt: { project: join(dir, "wt"), hooks: [join(common, "worktrees", "wt", "hooks"), join(common, "hooks")] },
        sm: { project: join(main, "sm"), hooks: [join(common, "modules", "sm", "hooks")] },
    };
}

const rawPolicy = { version: 1 as const, tools: { approved: ["sh", "cat"], builtinDefaults: false } };

function controllerFor(project: string): ForegroundSandboxController {
    const controller = new ForegroundSandboxController({
        home: () => home,
        readConfinement: {
            loadPolicy: () => ({ policy: parseReadConfinementPolicy(rawPolicy), source: "fixture-policy", sha256: hashPolicy(rawPolicy) }),
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
