/**
 * Git-dir redirects and planning-time placeholders, with real git and real bubblewrap (when usable):
 * the `.git` file of a linked worktree / submodule folder is read-only and an in-project or writable
 * `gitdir:` target is refused; deny entries under a `.git` file map onto the resolved git dirs; a
 * `readOnly` entry in a writable root or the private /tmp is denied; planning never follows symlinks
 * and writes every placeholder (real readable files), so the plan hash is stable from the first launch.
 * Fixtures live outside temp roots.
 * @level integration
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
    buildSandboxCommand, compileWritePolicy, describeSandboxSupport, evaluateDeleteAccess, evaluateWriteAccess,
    type SandboxCommandArgs,
} from "./index.ts";
import { hashPolicy, parseReadConfinementPolicy, planReadConfinement, ReadConfinementError, type ReadConfinementPolicy } from "./read-confinement.ts";

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
    host(main, "worktree", "add", "-q", "-b", "wt", join(base, "wt"));
    return { base, main, wt: join(base, "wt"), sm: join(main, "sm"), common: join(main, ".git"), admin: join(main, ".git", "worktrees", "wt"), smGit: join(main, ".git", "modules", "sm") };
}

function plan(project: string, extra: Partial<ReadConfinementPolicy> = {}, extraWritableRoots: string[] = []) {
    const policy: ReadConfinementPolicy = { version: 1, tools: { approved: ["sh", "cat"], builtinDefaults: false }, ...extra };
    const result = planReadConfinement({ policy: parseReadConfinementPolicy(policy), source: "test-fixture", sha256: hashPolicy(policy) }, project, {
        home, env: { PATH: "/usr/bin:/bin" }, passwdHomes: () => [], extraWritableRoots,
    });
    plans.push(result);
    return result;
}

/** The deny entries the packaged defaults produce for a project (see pi-better-sandbox policy.ts). */
const packagedDeny = (project: string) => [join(project, ".git", "hooks"), join(project, ".env"), join(project, ".env.local")];

function launch(result: ReturnType<typeof plan>, project: string, script: string, denyWrite: string[] = packagedDeny(project)) {
    const args: SandboxCommandArgs = {
        profilePath: join(root, "unused.sb"), execPath: "/bin/sh",
        execArgs: ["-c", `export PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid; cd '${project}'; ${script}`],
        policy: {
            writableRoot: project, home, denyWrite,
            permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
            readConfinement: result,
        },
    };
    const command = buildSandboxCommand(args, { env: { HOME: home } });
    return spawnSync(command.file, command.fileArgs, { encoding: "utf8", env: { HOME: home } });
}

const compiled = (project: string, result: ReturnType<typeof plan>, denyWrite = packagedDeny(project)) => compileWritePolicy({
    writableRoot: project, home, denyWrite,
    permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
    readConfinement: result,
});

before(() => {
    root = realpathSync(mkdtempSync(join(fixtureBase(), "git-redirect-")));
    home = join(root, "home");
    mkdirSync(home, { recursive: true });
});
after(() => {
    for (const p of plans) if (p.syntheticDir) rmSync(p.syntheticDir, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
});

describe("the .git file of a linked worktree or submodule folder", { skip: !usable && "usable bubblewrap and /usr/bin/git are required" }, () => {
    for (const which of ["wt", "sm"] as const) {
        it(`${which}: read-only in the sandbox (no write, unlink, rename, redirect) and denied in-process; git still works`, () => {
            const l = layout(`dotgit-${which}`);
            const project = l[which];
            const result = plan(project);
            const file = join(project, ".git");
            const original = readFileSync(file, "utf8");
            assert.ok(result.audit.denyWrite.includes(file));
            for (const script of [
                `rm -f .git`, `mv .git .git.x`, `: > .git`, `printf 'gitdir: ${project}/evilgit' > .git`, `printf x >> .git`,
                `/usr/bin/git init -q --bare evilgit && printf 'gitdir: ${project}/evilgit' > .git.new && mv .git.new .git`,
                `rm -rf .git`, `ln -sf evilgit .git`,
            ]) assert.notEqual(launch(result, project, script).status, 0, script);
            assert.equal(readFileSync(file, "utf8"), original);
            assert.equal(existsSync(`${file}.x`), false);
            const policy = compiled(project, result);
            assert.equal(evaluateWriteAccess(file, policy).allowed, false);
            assert.equal(evaluateDeleteAccess(file, policy).allowed, false);
            const ok = launch(result, project, `echo s > s.txt && /usr/bin/git add s.txt && /usr/bin/git commit -q -m inside && /usr/bin/git status --short`);
            assert.equal(ok.status, 0, ok.stdout + ok.stderr);
            host(project, "status");
        });
    }

    it("an in-project gitdir target (a planted redirect) is refused at plan time, recorded, nothing bound", () => {
        for (const which of ["wt", "sm"] as const) {
            const l = layout(`planted-${which}`);
            const project = l[which];
            mkdirSync(join(project, "evilgit"));
            host(project, "init", "-q", "--bare", "evilgit");
            writeFileSync(join(project, ".git"), `gitdir: ${join(project, "evilgit")}\n`);
            let error: unknown;
            try { plan(project); } catch (e) { error = e; }
            assert.ok(error instanceof ReadConfinementError, `${which}: ${String(error)}`);
            assert.match((error as Error).message, /writable root/);
            // A relative target is resolved the same way.
            writeFileSync(join(project, ".git"), "gitdir: evilgit\n");
            assert.throws(() => plan(project), ReadConfinementError);
        }
    });

    it("a gitdir target inside any other writable root, or around the project, is refused", () => {
        const l = layout("writable-roots");
        const extra = join(l.base, "elsewhere");
        mkdirSync(extra);
        assert.throws(() => plan(l.wt, {}, [l.base]), (e: Error) => e instanceof ReadConfinementError && /writable root/.test(e.message));
        assert.throws(() => plan(l.sm, {}, [join(l.main, ".git")]), ReadConfinementError);
        plan(l.wt, {}, [extra]); // unrelated writable roots do not matter
    });

    it("a commondir inside the project is refused too", () => {
        const l = layout("commondir-in-project");
        const evil = join(l.wt, "evilcommon");
        host(l.wt, "init", "-q", "--bare", "evilcommon");
        // The admin dir's commondir is a protected file the agent cannot change; model a pre-existing bad state on the host.
        writeFileSync(join(l.admin, "commondir"), `${evil}\n`);
        assert.throws(() => plan(l.wt), ReadConfinementError);
    });
});

describe("deny entries under a .git file (packaged defaults, real layouts)", { skip: !usable && "usable bubblewrap and /usr/bin/git are required" }, () => {
    it("main repo, linked worktree and submodule: hooks are protected where git reads them, nothing throws", () => {
        const l = layout("deny-map");
        for (const [project, hooks] of [[l.main, [join(l.common, "hooks")]], [l.wt, [join(l.admin, "hooks"), join(l.common, "hooks")]], [l.sm, [join(l.smGit, "hooks")]]] as const) {
            const result = plan(project);
            const policy = compiled(project, result);
            if (project !== l.main) {
                assert.equal(policy.denyWrite.includes(join(project, ".git", "hooks")), false, "the unusable entry is replaced");
                for (const dir of hooks) assert.ok(policy.denyWrite.includes(dir), `${dir} is in the compiled deny list`);
            }
            for (const dir of hooks) {
                assert.equal(evaluateWriteAccess(join(dir, "pre-commit"), policy).allowed, false, `in-process ${dir}`);
                const out = launch(result, project, `echo '#!/bin/sh' > '${dir}/pre-commit'`);
                assert.notEqual(out.status, 0, `sandbox write to ${dir}`);
                assert.equal(existsSync(join(dir, "pre-commit")), false);
            }
            const ok = launch(result, project, `/usr/bin/git status --short && echo ok > b.txt && /usr/bin/git add b.txt && /usr/bin/git commit -q -m viaplan`);
            assert.equal(ok.status, 0, `${project}: ${ok.stdout}${ok.stderr}`);
            assert.match(host(project, "log", "--oneline"), /viaplan/);
            // .env stays an ordinary project deny.
            assert.notEqual(launch(result, project, `echo x > .env`).status, 0);
        }
    });

    it("an extra deny entry under the .git file maps onto the git dirs and is enforced in the kernel", () => {
        const l = layout("deny-map-extra");
        const result = plan(l.wt);
        const extra = [...packagedDeny(l.wt), join(l.wt, ".git", "info", "exclude")];
        const policy = compiled(l.wt, result, extra);
        assert.ok(policy.denyWrite.includes(join(l.common, "info", "exclude")));
        assert.notEqual(launch(result, l.wt, `echo x >> '${join(l.common, "info", "exclude")}'`, extra).status, 0);
        assert.equal(evaluateWriteAccess(join(l.admin, "info", "exclude"), policy).allowed, false);
    });
});

describe("readOnly and scratch", () => {
    const project = () => join(root, "ro-project");
    it("a readOnly entry inside the writable project is denied and never approves a wildcard", () => {
        const p = project();
        mkdirSync(join(p, "v7", "a", "bin"), { recursive: true });
        writeFileSync(join(p, "v7", "a", "bin", "y"), "#!/bin/sh\n");
        const result = plan(p, { readOnly: [join(p, "v7")], tools: { approvedPathDirs: [`${p}/v7/*/bin`], builtinDefaults: false } });
        assert.ok(result.audit.denied.some((d) => d.path === join(p, "v7") && /writable root/.test(d.reason) && d.via === "readOnly"));
        assert.ok(!result.audit.binds.some((b) => b.path === join(p, "v7")));
        const wildcard = result.audit.wildcards?.[0];
        assert.ok(wildcard?.matches.every((m) => !m.accepted), JSON.stringify(wildcard));
    });

    it("readOnly entries that overlap the private /tmp are denied", () => {
        const p = project();
        const sub = mkdtempSync("/tmp/ro-overlap-");
        try {
            const result = plan(p, { readOnly: ["/tmp", sub] });
            assert.equal(result.audit.denied.filter((d) => /private \/tmp/.test(d.reason)).length, 2);
            assert.ok(!result.audit.binds.some((b) => b.path === "/tmp" || b.path === sub));
        } finally { rmSync(sub, { recursive: true, force: true }); }
    });
});

describe("planning does not follow symlinks and writes every placeholder", () => {
    it("a symlink inside a git dir is refused, nothing is created through it", () => {
        const l = layout("links");
        const outside = join(l.base, "outside");
        mkdirSync(outside);
        for (const [link, target] of [["objects", outside], ["info", join(l.base, "somedir")]] as const) {
            mkdirSync(join(l.base, "somedir"), { recursive: true });
            const dir = join(l.common, link);
            const backup = `${dir}.real`;
            // move the real directory aside and put a link in its place
            spawnSync("mv", [dir, backup]);
            symlinkSync(target, dir);
            try {
                let error: unknown;
                try { plan(l.main); } catch (e) { error = e; }
                assert.ok(error instanceof ReadConfinementError, `${link}: ${String(error)}`);
                assert.match((error as Error).message, /symbolic link/);
                assert.deepEqual(readdirSync(outside), [], "nothing was created below the link's target");
                assert.deepEqual(readdirSync(target), [], "nothing was created below the link's target");
            } finally {
                rmSync(dir);
                spawnSync("mv", [backup, dir]);
            }
        }
    });

    it("every placeholder exists after planning: real files, no /dev/null mounts, plan hash identical before and after the first launch", { skip: !usable && "usable bubblewrap and /usr/bin/git are required" }, () => {
        for (const which of ["main", "wt", "sm"] as const) {
            const l = layout(`stable-${which}`);
            const project = l[which];
            const first = plan(project);
            for (const dir of which === "main" ? [l.common] : which === "wt" ? [l.admin, l.common] : [l.smGit]) {
                for (const name of ["config", "config.worktree", "info/attributes", "objects/info/alternates", "objects/info/http-alternates", "commondir", "gitdir"]) {
                    assert.ok(lstatSync(join(dir, name)).isFile(), `${dir}/${name} is a regular file`);
                }
                assert.ok(lstatSync(join(dir, "hooks")).isDirectory());
            }
            assert.ok(!first.args.includes("/dev/null") && !first.overlayArgs?.includes("/dev/null"), "no /dev/null bind sources");
            const clone = launch(first, project, `/usr/bin/git clone -q . cl && test -d cl/.git`);
            assert.equal(clone.status, 0, `first-session clone: ${clone.stdout}${clone.stderr}`);
            const second = plan(project);
            assert.equal(second.hash, first.hash, `${which}: the first plan equals every later plan`);
            assert.equal(plan(project).hash, first.hash);
        }
    });
});
