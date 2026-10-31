/**
 * Mount anchors for git write-denials: every directory above a read-only overlay inside a writable
 * region is a mount point, so renaming or removing it fails (EBUSY) and cannot be used to rebuild the
 * directory without the overlay. Real git repos (main, linked worktree, submodule) and real bubblewrap
 * when usable; the in-process evaluator must refuse the same operations. Fixtures live outside temp roots.
 * @level integration
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
    buildSandboxCommand, compileWritePolicy, describeSandboxSupport, evaluateDeleteAccess, evaluateWriteAccess,
    type SandboxCommandArgs,
} from "./index.ts";
import { hashPolicy, parseReadConfinementPolicy, planReadConfinement, type ReadConfinementPolicy } from "./read-confinement.ts";

function fixtureBase(): string {
    return process.env.PI_READ_CONFINEMENT_TEST_BASE ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
}

const GIT = "/usr/bin/git";
const gitEnv = {
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid",
    GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid", GIT_TERMINAL_PROMPT: "0",
};
const usable = (() => {
    const support = describeSandboxSupport();
    if (!support.supported || support.backend !== "linux-bubblewrap") return false;
    return existsSync(GIT) && spawnSync(support.executable, ["--ro-bind", "/", "/", "--unshare-net", "true"]).status === 0;
})();

let root: string;
let home: string;
const plans: { syntheticDir: string | undefined }[] = [];

function host(cwd: string, ...args: string[]) {
    const out = spawnSync(GIT, ["-c", "protocol.file.allow=always", ...args], { cwd, encoding: "utf8", env: { ...process.env, ...gitEnv, HOME: home } });
    assert.equal(out.status, 0, `git ${args.join(" ")}: ${out.stderr}`);
    return out.stdout;
}

/** A main repo with a submodule, a sibling worktree and a linked worktree to confine. */
function layout(name: string) {
    const base = join(root, name);
    const lib = join(base, "lib");
    const main = join(base, "main");
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
    host(main, "worktree", "add", "-q", "-b", "sib", join(base, "sib"));
    host(main, "worktree", "add", "-q", "-b", "wt", join(base, "wt"));
    return { base, main, sib: join(base, "sib"), wt: join(base, "wt"), lib };
}

function plan(project: string) {
    const policy: ReadConfinementPolicy = { version: 1, tools: { approved: ["sh", "cat"], builtinDefaults: false } };
    const result = planReadConfinement({ policy: parseReadConfinementPolicy(policy), source: "test-fixture", sha256: hashPolicy(policy) }, project, {
        home, env: { PATH: "/usr/bin:/bin" }, passwdHomes: () => [],
    });
    plans.push(result);
    return result;
}

function sandboxed(result: ReturnType<typeof plan>, project: string, script: string) {
    const args: SandboxCommandArgs = {
        profilePath: join(root, "unused.sb"), execPath: "/bin/sh",
        execArgs: ["-c", `export PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid; cd '${project}'; ${script}`],
        policy: {
            writableRoot: project, home, denyWrite: [],
            permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
            readConfinement: result,
        },
    };
    const command = buildSandboxCommand(args, { env: { HOME: home } });
    return spawnSync(command.file, command.fileArgs, { encoding: "utf8", env: { HOME: home } });
}

before(() => {
    root = realpathSync(mkdtempSync(join(fixtureBase(), "git-anchors-")));
    home = join(root, "home");
    mkdirSync(home, { recursive: true });
});
after(() => {
    for (const p of plans) if (p.syntheticDir) rmSync(p.syntheticDir, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
});

function policyFor(project: string, result: ReturnType<typeof plan>) {
    return compileWritePolicy({
        writableRoot: project, home, denyWrite: [],
        permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
        readConfinement: result,
    });
}

/** What every layout must guarantee, given its git dirs. `gitDirs`: [dir, whether it is a main/submodule git dir]. */
function assertAnchored(project: string, gitDir: string, common: string) {
    const result = plan(project);
    const anchors = result.denyRemove ?? [];
    for (const expected of [join(common, "worktrees"), join(common, "modules"), join(common, "modules", "sm"), join(common, "objects", "info"),
        join(common, "info"), join(common, "objects"), join(common, "modules", "sm", "objects", "info")]) {
        assert.ok(anchors.includes(expected), `denyRemove lists ${expected}`);
    }
    if (gitDir === join(project, ".git")) assert.ok(anchors.includes(gitDir), "the in-project .git is an anchor");
    // The anchors are derived from the deny list, never outside a writable region.
    for (const a of anchors) assert.ok(a.startsWith(project + "/") || a.startsWith(common + "/") || a.startsWith(gitDir + "/") || a === common || a === gitDir, a);
    const policy = policyFor(project, result);
    return { result, anchors, policy };
}

describe("git mount anchors: real git and bubblewrap", { skip: !usable && "usable bubblewrap and /usr/bin/git are required" }, () => {
    it("in-project .git: every ancestor of an overlay resists mv, rmdir and rm -rf; git keeps working", () => {
        const { main } = layout("inproject");
        const { result, anchors, policy } = assertAnchored(main, join(main, ".git"), join(main, ".git"));
        const before = anchors.map((a) => existsSync(a));
        assert.ok(before.every(Boolean));
        for (const a of anchors) {
            for (const [label, script] of [["mv", `mv '${a}' '${a}.moved'`], ["rmdir", `rmdir '${a}'`], ["rm -rf", `rm -rf '${a}'`]] as const) {
                const out = sandboxed(result, main, script);
                assert.notEqual(out.status, 0, `${label} ${a} must fail: ${out.stdout}`);
                assert.equal(existsSync(`${a}.moved`), false, `${label} ${a}`);
                assert.equal(existsSync(a), true, `${label} ${a}`);
                // In-process parity: the file tools may not remove or move it either.
                assert.equal(evaluateDeleteAccess(a, policy).allowed, false, `in-process remove ${a}`);
            }
        }
        // the escape from the review: rebuild .git without the overlays, then plant a hook.
        const attack = sandboxed(result, main, `mv .git .git.bak && mkdir .git && cp -r .git.bak/. .git && echo '#!/bin/sh' > .git/hooks/pre-commit`);
        assert.notEqual(attack.status, 0);
        assert.equal(existsSync(join(main, ".git.bak")), false);
        assert.equal(existsSync(join(main, ".git", "hooks", "pre-commit")), false);
        for (const sub of ["modules", "worktrees", "objects/info", "info"]) {
            sandboxed(result, main, `mv .git/${sub} .git/${sub}.bak && mkdir -p .git/${sub}/x`);
            assert.equal(existsSync(join(main, ".git", `${sub}.bak`)), false, sub);
        }
    });

    it("commondir and gitdir are never creatable: placeholders keep git working and cannot be changed", () => {
        const { main } = layout("placeholders");
        const result = plan(main);
        const common = join(main, ".git");
        for (const dir of [common, join(common, "modules", "sm")]) {
            assert.equal(readFileSync(join(dir, "commondir"), "utf8"), ".\n", "a commondir placeholder that git accepts");
            assert.equal(existsSync(join(dir, "gitdir")), true);
            for (const name of ["commondir", "gitdir"]) {
                const file = join(dir, name);
                const original = readFileSync(file, "utf8");
                for (const script of [`echo ../evil > '${file}'`, `rm -f '${file}'`, `mv '${file}' '${file}.x'`, `printf x >> '${file}'`]) {
                    assert.notEqual(sandboxed(result, main, script).status, 0, script);
                }
                assert.equal(readFileSync(file, "utf8"), original);
            }
        }
        // the escape from the review: point commondir at an agent-made dir that carries a config.
        const attack = sandboxed(result, main, `mkdir evilcommon && printf '[core]\\n\\tfsmonitor = touch /tmp/pwn\\n' > evilcommon/config && echo ../evilcommon > .git/commondir`);
        assert.notEqual(attack.status, 0);
        assert.equal(readFileSync(join(common, "commondir"), "utf8"), ".\n");
    });

    it("alternates, core.fsmonitor and core.hooksPath cannot be planted by moving a directory or the config", () => {
        const { main, lib } = layout("planting");
        const result = plan(main);
        const common = join(main, ".git");
        const planted = sandboxed(result, main, `mv .git/objects/info .git/objects/info.bak && mkdir .git/objects/info && echo '${join(lib, ".git", "objects")}' > .git/objects/info/alternates`);
        assert.notEqual(planted.status, 0);
        const alternates = join(common, "objects", "info", "alternates");
        assert.equal(existsSync(alternates) ? readFileSync(alternates, "utf8") : "", "", "no alternates (an empty read-only node at most)");
        assert.equal(existsSync(join(common, "objects", "info.bak")), false);
        const before = readFileSync(join(common, "config"), "utf8");
        for (const script of [
            `cp .git/config /tmp/c && mv /tmp/c .git/config`,
            `mv .git/config .git/config.old && cp .git/config.old .git/config && /usr/bin/git config core.fsmonitor 'touch pwn'`,
            `/usr/bin/git config core.fsmonitor 'touch pwn'`, `/usr/bin/git config core.hooksPath /tmp/hooks`,
            `/usr/bin/git config --file .git/modules/sm/config core.hooksPath /tmp/hooks`,
            `mv .git/modules .git/modules.bak && mkdir -p .git/modules/sm/hooks && echo x > .git/modules/sm/hooks/post-checkout`,
            `mv .git/worktrees .git/worktrees.bak && mkdir -p .git/worktrees/sib/hooks && echo x > .git/worktrees/sib/hooks/post-commit`,
        ]) assert.notEqual(sandboxed(result, main, script).status, 0, script);
        assert.equal(readFileSync(join(common, "config"), "utf8"), before);
        assert.equal(existsSync(join(common, "modules.bak")), false);
        assert.equal(existsSync(join(common, "worktrees.bak")), false);
        assert.equal(existsSync(join(main, "pwn")), false);
    });

    it("git works inside the sandbox and on the host afterwards (main repo)", () => {
        const { main } = layout("gitworks");
        const result = plan(main);
        const out = sandboxed(result, main, `/usr/bin/git status --short && echo hi > b.txt && /usr/bin/git add b.txt && /usr/bin/git commit -q -m second && /usr/bin/git log --oneline && /usr/bin/git worktree list && /usr/bin/git branch side && /usr/bin/git fsck`);
        assert.equal(out.status, 0, out.stdout + out.stderr);
        assert.match(out.stdout, /second/);
        assert.match(host(main, "log", "--oneline"), /second/);
        assert.match(host(main, "worktree", "list"), /wt/);
        host(main, "status");
        host(main, "fsck");
        host(main, "branch", "-d", "side");
    });

    it("linked worktree: ancestors in the common dir resist, git works inside and on the host", () => {
        const { main, wt } = layout("linked");
        const common = join(main, ".git");
        const gitDir = join(common, "worktrees", "wt");
        const { result, anchors, policy } = assertAnchored(wt, gitDir, common);
        for (const a of anchors) {
            for (const script of [`mv '${a}' '${a}.moved'`, `rmdir '${a}'`, `rm -rf '${a}'`]) {
                const out = sandboxed(result, wt, script);
                assert.notEqual(out.status, 0, `${script}: ${out.stdout}`);
                assert.equal(existsSync(a), true, script);
                assert.equal(existsSync(`${a}.moved`), false, script);
            }
            assert.equal(evaluateDeleteAccess(a, policy).allowed, false, `in-process remove ${a}`);
        }
        assert.notEqual(sandboxed(result, wt, `mv '${common}/worktrees' '${common}/worktrees.bak' && mkdir -p '${common}/worktrees/sib/hooks' && echo x > '${common}/worktrees/sib/hooks/post-commit'`).status, 0);
        assert.equal(existsSync(join(common, "worktrees.bak")), false);
        assert.notEqual(sandboxed(result, wt, `echo ../x > '${gitDir}/commondir'`).status, 0);
        assert.equal(readFileSync(join(gitDir, "commondir"), "utf8").trim(), "../..");
        // rm -rf legitimately empties the writable files (HEAD, index) below an anchor before the rmdir fails; use a fresh layout for git.
        const fresh = layout("linked-git");
        const result2 = plan(fresh.wt);
        const out = sandboxed(result2, fresh.wt, `echo w > w.txt && /usr/bin/git add w.txt && /usr/bin/git commit -q -m inwt && /usr/bin/git status --short && /usr/bin/git log --oneline && /usr/bin/git worktree list`);
        assert.equal(out.status, 0, out.stdout + out.stderr);
        assert.match(host(fresh.wt, "log", "--oneline"), /inwt/);
        assert.match(host(fresh.main, "worktree", "list"), /wt/);
        host(fresh.wt, "status");
        host(fresh.main, "fsck");
    });

    it("submodule working folder: its git dir (under the superproject) is anchored; git works inside and on the host", () => {
        const { main } = layout("submodule");
        const sm = join(main, "sm");
        const gitDir = join(main, ".git", "modules", "sm");
        const result = plan(sm);
        const anchors = result.denyRemove ?? [];
        assert.ok(anchors.includes(join(gitDir, "objects", "info")), "objects/info is an anchor");
        assert.ok(anchors.includes(join(gitDir, "info")) || !existsSync(join(gitDir, "info")));
        for (const a of anchors.filter((a) => a.startsWith(gitDir))) {
            for (const script of [`mv '${a}' '${a}.moved'`, `rmdir '${a}'`]) assert.notEqual(sandboxed(result, sm, script).status, 0, script);
            assert.equal(existsSync(`${a}.moved`), false, a);
        }
        for (const script of [`echo ../evil > '${gitDir}/commondir'`, `/usr/bin/git config core.hooksPath /tmp/h`, `mv '${gitDir}/objects/info' '${gitDir}/objects/info.bak'`]) {
            assert.notEqual(sandboxed(result, sm, script).status, 0, script);
        }
        const out = sandboxed(result, sm, `echo s > s.txt && /usr/bin/git add s.txt && /usr/bin/git commit -q -m insub && /usr/bin/git status --short && /usr/bin/git log --oneline`);
        assert.equal(out.status, 0, out.stdout + out.stderr);
        assert.match(host(sm, "log", "--oneline"), /insub/);
        host(sm, "status");
        host(main, "status");
    });

    it("in-process parity: the file tools refuse the same removals, creations and writes", () => {
        const { main } = layout("parity");
        const result = plan(main);
        const policy = policyFor(main, result);
        const common = join(main, ".git");
        for (const dir of [common, join(common, "modules", "sm")]) {
            for (const name of ["commondir", "gitdir", "config", "hooks"]) {
                assert.equal(evaluateWriteAccess(join(dir, name), policy).allowed, false, `write ${dir}/${name}`);
                assert.equal(evaluateDeleteAccess(join(dir, name), policy).allowed, false, `remove ${dir}/${name}`);
            }
        }
        for (const path of [join(common, "objects", "info", "alternates"), join(common, "info", "attributes"), join(common, "worktrees", "sib", "hooks", "x")]) {
            assert.equal(evaluateWriteAccess(path, policy).allowed, false, path);
        }
        for (const path of [common, join(common, "objects"), join(common, "worktrees"), join(common, "modules")]) {
            assert.equal(evaluateDeleteAccess(path, policy).allowed, false, `remove ${path}`);
        }
        // ordinary project work is untouched
        assert.equal(evaluateWriteAccess(join(main, "new.txt"), policy).allowed, true);
        assert.equal(evaluateWriteAccess(join(common, "refs", "heads", "x"), policy).allowed, true);
        assert.equal(evaluateDeleteAccess(join(common, "refs", "heads", "x"), policy).allowed, true);
    });
});
