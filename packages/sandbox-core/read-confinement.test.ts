/**
 * Read confinement: policy schema, mount planning and (when bwrap is usable) the
 * real kernel boundary. All fixtures live in temp dirs; nothing names a real host,
 * user, project or tool. A live run against a site policy is opt-in through
 * `PI_READ_CONFINEMENT_LIVE_POLICY` + `PI_READ_CONFINEMENT_LIVE_PROJECT`.
 * @level unit
 * @level integration
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
    buildSandboxCommand,
    compileWritePolicy,
    describeSandboxSupport,
    evaluateReadAccess,
    evaluateWriteAccess,
    type SandboxCommandArgs,
} from "./index.ts";
import {
    formatReadConfinementAudit,
    hashPolicy,
    loadReadConfinementPolicyFile,
    parseReadConfinementPolicy,
    planReadConfinement,
    ReadConfinementError,
    type ReadConfinementPolicy,
} from "./read-confinement.ts";

/** Not under /tmp: the sandbox's private /tmp is writable by design, which would mask the outside-write checks. */
function fixtureBase(): string {
    return process.env.PI_READ_CONFINEMENT_TEST_BASE ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
}

let root: string;
let home: string;
let project: string;
let other: string;
let shared: string;
let toolBin: string;
const plans: { syntheticDir: string | undefined }[] = [];

function write(path: string, text: string, mode = 0o644): void {
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, text);
    chmodSync(path, mode);
}

before(() => {
    root = realpathSync(mkdtempSync(join(fixtureBase(), "read-confinement-")));
    home = join(root, "home", "me");
    project = join(root, "work", "project");
    other = join(root, "work", "other-project");
    shared = join(root, "shared");
    toolBin = join(root, "tools", "bin");
    mkdirSync(join(home, ".ssh"), { recursive: true });
    write(join(home, ".ssh", "id_fixture"), "fixture-credential\n");
    write(join(home, "notes.txt"), "home notes\n");
    write(join(other, "secret.txt"), "other project\n");
    write(join(project, "file.txt"), "project file\n");
    write(join(shared, "ok", "data.txt"), "shared data\n");
    write(join(shared, "ok", "nested-target.txt"), "nested target\n");
    symlinkSync(join(shared, "ok"), join(project, "link-ok"));
    symlinkSync(join(home, ".ssh"), join(project, "link-denied"));
    symlinkSync(join(shared, "ok", "nested-target.txt"), join(shared, "ok", "nested-link"));
    symlinkSync("link-ok", join(project, "chain"));
    // Approved fixture tools.
    write(join(toolBin, "fixture-tool"), '#!/bin/sh\ncat "$FIXTURE_CONF" 2>&1\n', 0o755);
    write(join(toolBin, "unapproved-tool"), "#!/bin/sh\necho should-not-run\n", 0o755);
    write(join(home, ".config", "fixture", "ok.conf"), "setting=1\n");
    write(join(home, ".config", "fixture-secret", "leaky.conf"), "token = abcdef0123456789abcdef\n");
});

after(() => {
    for (const plan of plans) if (plan.syntheticDir) rmSync(plan.syntheticDir, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
});

function loaded(policy: ReadConfinementPolicy) {
    return { policy: parseReadConfinementPolicy(policy), source: "test-fixture", sha256: hashPolicy(policy) };
}

function plan(policy: ReadConfinementPolicy, extra: Parameters<typeof planReadConfinement>[2] = {}, at = project) {
    const result = planReadConfinement(loaded(policy), at, {
        home, env: { PATH: `${toolBin}:/usr/bin:/bin` }, passwdHomes: () => [], ...extra,
    });
    plans.push(result);
    return result;
}

describe("policy schema", () => {
    it("rejects unknown keys, bad versions and relative paths", () => {
        assert.throws(() => parseReadConfinementPolicy({ version: 2 }), /\$\.version/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, surprise: true }), /unknown key/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, deny: { paths: ["relative/x"] } }), /must be absolute/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, limits: { maxDepth: 0 } }), /integer >= 1/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, tools: { approved: [{ name: "a", path: "/b" }] } }), /exactly one/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, secretDetector: { patterns: ["("] } }), /invalid regular expression/);
    });

    it("hashes independent of key order and loads from a file", () => {
        const a = { version: 1 as const, limits: { maxDepth: 2, maxBinds: 3 } };
        const b = { version: 1 as const, limits: { maxBinds: 3, maxDepth: 2 } };
        assert.equal(hashPolicy(a), hashPolicy(b));
        const file = join(root, "policy.json");
        write(file, JSON.stringify(a));
        const result = loadReadConfinementPolicyFile(file);
        assert.equal(result.sha256, hashPolicy(a));
        assert.throws(() => loadReadConfinementPolicyFile(join(root, "missing.json")), /Cannot read/);
        write(join(root, "bad.json"), "{");
        assert.throws(() => loadReadConfinementPolicyFile(join(root, "bad.json")), /not valid JSON/);
    });
});

describe("symlink closure", () => {
    it("binds allowed targets, records denied ones, and never mounts them", () => {
        const result = plan({ version: 1 });
        assert.ok(result.readRoots.includes(join(shared, "ok")));
        assert.ok(result.audit.binds.some((b) => b.path === join(shared, "ok") && b.mode === "ro"));
        const denied = result.audit.denied.find((d) => d.path === join(home, ".ssh"));
        assert.ok(denied, "the credential link target is recorded");
        assert.match(denied.reason, /denied path/);
        assert.ok(!result.args.includes(join(home, ".ssh")));
        assert.ok(!result.readRoots.some((r) => r.startsWith(join(home, ".ssh"))));
        assert.match(formatReadConfinementAudit(result.audit, result.hash), /denied \(1\)/);
    });

    it("follows transitive links inside bound targets", () => {
        const deep = join(root, "deep-target");
        write(join(deep, "x.txt"), "x");
        const hop = join(root, "hop");
        mkdirSync(hop);
        symlinkSync(deep, join(hop, "to-deep"));
        const proj = join(root, "work", "transitive");
        mkdirSync(proj, { recursive: true });
        symlinkSync(hop, join(proj, "hop"));
        const result = plan({ version: 1 }, {}, proj);
        assert.ok(result.readRoots.includes(deep));
        assert.ok(result.readRoots.includes(hop));
    });

    it("denies other users' homes and policy deny entries, and dirs that contain denied paths", () => {
        const otherHome = join(root, "home", "someone");
        write(join(otherHome, "f"), "x");
        const proj = join(root, "work", "deny");
        mkdirSync(proj, { recursive: true });
        symlinkSync(otherHome, join(proj, "other-home"));
        symlinkSync(join(root, "home"), join(proj, "parent-of-home"));
        symlinkSync(join(shared, "ok"), join(proj, "policy-denied"));
        const result = plan({ version: 1, deny: { paths: [join(shared, "ok")] } }, { passwdHomes: () => [otherHome] }, proj);
        const reasons = Object.fromEntries(result.audit.denied.map((d) => [d.path, d.reason]));
        assert.match(reasons[otherHome]!, /inside denied path/);
        assert.match(reasons[join(root, "home")]!, /contains denied path/);
        assert.match(reasons[join(shared, "ok")]!, /inside denied path/);
        assert.deepEqual(result.readRoots, [proj]);
    });

    it("detects cycles and fails closed over the caps with a clear error", () => {
        const proj = join(root, "work", "cycle");
        const a = join(root, "cycle-a");
        const b = join(root, "cycle-b");
        mkdirSync(proj, { recursive: true });
        mkdirSync(a);
        mkdirSync(b);
        symlinkSync(b, join(a, "to-b"));
        symlinkSync(a, join(b, "to-a"));
        symlinkSync(a, join(proj, "a"));
        const result = plan({ version: 1 }, {}, proj);
        assert.ok(result.readRoots.includes(a) && result.readRoots.includes(b));

        assert.throws(() => plan({ version: 1, limits: { maxSymlinks: 1 } }, {}, proj), (e: unknown) =>
            e instanceof ReadConfinementError && /failed closed.*maxSymlinks/.test(e.message));
        assert.throws(() => plan({ version: 1, limits: { maxDepth: 1 } }, {}, proj), /maxDepth/);
        assert.throws(() => plan({ version: 1, limits: { maxWalkEntries: 1 } }, {}), /maxWalkEntries/);
        assert.throws(() => plan({ version: 1, limits: { maxBinds: 1 } }, {}, proj), /maxBinds/);
    });

    it("mounts intermediate symlinks that would not exist in the sandbox", () => {
        const real = join(root, "chain-real");
        write(join(real, "f"), "x");
        const via = join(root, "chain-via");
        symlinkSync(real, via);
        const proj = join(root, "work", "chained");
        mkdirSync(proj, { recursive: true });
        symlinkSync(join(via, "f"), join(proj, "f"));
        const result = plan({ version: 1 }, {}, proj);
        assert.deepEqual(result.audit.symlinkMounts, [{ path: via, text: real }]);
        assert.ok(result.args.join(" ").includes(`--symlink ${real} ${via}`));
    });

    it("binds a worktree's git dir writable", () => {
        const main = join(root, "main-repo");
        const gitdir = join(main, ".git", "worktrees", "wt");
        write(join(main, ".git", "HEAD"), "ref: x\n");
        write(join(gitdir, "commondir"), "../..\n");
        const wt = join(root, "work", "wt");
        write(join(wt, ".git"), `gitdir: ${gitdir}\n`);
        const result = plan({ version: 1 }, {}, wt);
        assert.deepEqual(result.writeRoots, [wt, join(main, ".git"), gitdir].sort());
        assert.ok(result.audit.gitDirs.includes(gitdir));
    });
});

describe("approved tools, configs and caches", () => {
    const policy = (over: Partial<ReadConfinementPolicy> = {}): ReadConfinementPolicy => ({
        version: 1,
        tools: { approved: [{ name: "fixture-tool", config: ["~/.config/fixture", "~/.config/fixture-secret", "~/.config/absent"], cache: ["~/.cache/fixture"] }], builtinDefaults: false },
        ...over,
    });

    it("builds a synthetic PATH with only approved tools", () => {
        const result = plan(policy());
        assert.deepEqual(result.audit.syntheticPath?.tools.map((t) => t.name), ["fixture-tool"]);
        assert.ok(result.syntheticDir && existsSync(join(result.syntheticDir, "fixture-tool")));
        assert.ok(!existsSync(join(result.syntheticDir!, "unapproved-tool")));
        assert.ok(result.readRoots.includes(join(toolBin, "fixture-tool")));
        assert.ok(result.args.join(" ").includes("--setenv PATH /run/pi-confined/bin"));
    });

    it("refuses configs matching the secret detector and records skips", () => {
        const result = plan(policy());
        assert.ok(result.readRoots.includes(join(home, ".config", "fixture")));
        const refused = result.audit.denied.find((d) => d.path.endsWith("fixture-secret"));
        assert.match(refused!.reason, /secret detected/);
        assert.ok(!refused!.reason.includes("abcdef0123456789"), "the secret value is never recorded");
        assert.ok(result.audit.skipped.some((s) => s.path.endsWith(".config/absent") && s.reason === "not found"));
        assert.ok(result.audit.binds.some((b) => b.mode === "tmpfs" && b.path === join(home, ".cache", "fixture")));
    });

    it("lets policy replace the detector and remove built-in defaults", () => {
        const loose = plan(policy({ secretDetector: { useDefaults: false } }));
        assert.ok(loose.readRoots.includes(join(home, ".config", "fixture-secret")));
        write(join(home, ".gitconfig"), "[user]\nname = x\n");
        const withDefault = plan({ version: 1, tools: { approved: ["sh"] } });
        assert.equal(withDefault.audit.syntheticPath?.tools[0]?.name, "sh");
        const git = spawnSync("git", ["--version"]).status === 0;
        if (git) {
            assert.ok(plan({ version: 1, tools: { approved: ["git"] } }).readRoots.includes(join(home, ".gitconfig")));
            assert.ok(!plan({ version: 1, tools: { approved: ["git"], builtinDefaults: false } }).readRoots.includes(join(home, ".gitconfig")));
        }
    });

    it("approves PATH directories only when they are on the launching PATH", () => {
        const onPath = plan({ version: 1, tools: { approvedPathDirs: [toolBin] } });
        assert.deepEqual(onPath.audit.syntheticPath?.tools.map((t) => t.name), ["fixture-tool", "unapproved-tool"]);
        const off = plan({ version: 1, tools: { approvedPathDirs: [toolBin] } }, { env: { PATH: "/usr/bin" } });
        assert.ok(off.audit.skipped.some((s) => /not on the launching PATH/.test(s.reason)));
        assert.equal(off.audit.syntheticPath, undefined);
    });

    it("follows shebang interpreters through env and ELF libraries through the seam", () => {
        const interpBin = join(root, "interp", "bin");
        write(join(interpBin, "fake-interp"), "#!/bin/sh\nexec sh \"$@\"\n", 0o755);
        write(join(toolBin, "scripted"), "#!/usr/bin/env fake-interp\necho hi\n", 0o755);
        const libs: string[] = [];
        const result = plan({ version: 1, tools: { approved: ["scripted"] } },
            { env: { PATH: `${toolBin}:${interpBin}:/usr/bin` }, listLibraries: (exe) => { libs.push(exe); return []; } });
        const names = result.audit.syntheticPath!.tools;
        assert.deepEqual(names.map((t) => [t.name, t.implicit]), [["fake-interp", true], ["scripted", false]]);
        assert.ok(result.readRoots.includes(join(interpBin, "fake-interp")));
        assert.ok(libs.includes(realpathSync("/usr/bin/env")), "the ELF interpreter of the script is asked for its libraries");
    });

    it("uses a persistent per-agent cache when the policy configures one", () => {
        const base = join(root, "persist");
        const result = plan({ version: 1, caches: { persistentDir: base },
            tools: { approved: [{ name: "fixture-tool", cache: ["~/.cache/p"], cachePersistent: true }] } }, { agentId: "agent-1" });
        const bind = result.audit.binds.find((b) => b.path === join(home, ".cache", "p"));
        assert.equal(bind?.mode, "rw");
        assert.ok(result.writeRoots.includes(join(home, ".cache", "p")));
        const index = result.args.indexOf("--bind");
        assert.ok(result.args[index + 1]!.startsWith(join(base, "agent-1")));
    });
});

describe("in-process allow set", () => {
    it("allows reads and writes only inside the computed set", () => {
        const result = plan({ version: 1, tools: { approved: [{ name: "fixture-tool", cache: ["~/.cache/fixture"] }], builtinDefaults: false } });
        const policy = compileWritePolicy({
            writableRoot: project, home, runtimeCompatibility: true,
            permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
            readConfinement: result,
        });
        const read = (p: string) => evaluateReadAccess(p, policy).allowed;
        assert.equal(read(join(project, "file.txt")), true);
        assert.equal(read(join(shared, "ok", "data.txt")), true, "symlink target readable");
        assert.equal(read(join(project, "link-ok", "data.txt")), true, "via the link too");
        assert.equal(read(join(other, "secret.txt")), false);
        assert.equal(read(join(home, "notes.txt")), false);
        assert.equal(read(join(home, ".ssh", "id_fixture")), false);
        assert.equal(read("/usr/bin/env"), true);
        assert.equal(evaluateWriteAccess(join(project, "new.txt"), policy).allowed, true);
        assert.equal(evaluateWriteAccess(join(shared, "ok", "data.txt"), policy).allowed, false, "ro targets are not writable");
        assert.equal(evaluateWriteAccess(join(other, "x"), policy).allowed, false);
    });
});

const bwrapUsable = (() => {
    const support = describeSandboxSupport();
    if (!support.supported || support.backend !== "linux-bubblewrap") return false;
    return spawnSync(support.executable, ["--ro-bind", "/", "/", "--unshare-net", "true"]).status === 0;
})();

describe("real bubblewrap", { skip: !bwrapUsable && "usable bubblewrap is not available" }, () => {
    function run(result: ReturnType<typeof plan>, script: string, atProject = project, env: Record<string, string> = {}) {
        const args: SandboxCommandArgs = {
            profilePath: join(root, "unused.sb"),
            execPath: "/bin/sh",
            execArgs: ["-c", script],
            policy: {
                writableRoot: atProject, home, denyWrite: [],
                permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
                readConfinement: result,
            },
        };
        const command = buildSandboxCommand(args);
        return spawnSync(command.file, command.fileArgs, { encoding: "utf8", env: { HOME: home, ...env } });
    }

    const fixturePolicy: ReadConfinementPolicy = {
        version: 1,
        tools: { approved: [{ name: "fixture-tool", config: ["~/.config/fixture/ok.conf"] }, "sh", "cat"], builtinDefaults: false },
    };

    it("hides other projects, home files and credentials", () => {
        const result = plan(fixturePolicy);
        for (const hidden of [join(other, "secret.txt"), join(home, "notes.txt"), join(home, ".ssh", "id_fixture"), join(home, ".config", "fixture-secret", "leaky.conf")]) {
            const out = run(result, `cat '${hidden}'`);
            assert.notEqual(out.status, 0, hidden);
            assert.match(out.stderr, /No such file or directory/, hidden);
        }
        assert.equal(run(result, `cat '${join(project, "file.txt")}'`).stdout, "project file\n");
    });

    it("reads through allowed symlinks, including chains, but not denied ones", () => {
        const result = plan(fixturePolicy);
        assert.equal(run(result, `cat '${join(project, "link-ok", "data.txt")}'`).stdout, "shared data\n");
        assert.equal(run(result, `cat '${join(project, "chain", "data.txt")}'`).stdout, "shared data\n");
        assert.equal(run(result, `cat '${join(shared, "ok", "nested-link")}'`).stdout, "nested target\n");
        const denied = run(result, `cat '${join(project, "link-denied", "id_fixture")}'`);
        assert.notEqual(denied.status, 0);
        assert.ok(result.audit.denied.some((d) => d.path === join(home, ".ssh")));
    });

    it("runs approved tools with their config; unapproved ones are absent; secret configs are not bound", () => {
        const result = plan(fixturePolicy);
        const ok = run(result, "fixture-tool", project, { FIXTURE_CONF: join(home, ".config", "fixture", "ok.conf") });
        assert.equal(ok.stdout, "setting=1\n", ok.stderr);
        const missing = run(result, "unapproved-tool");
        assert.notEqual(missing.status, 0);
        assert.match(missing.stderr, /not found/);
        assert.notEqual(run(result, `'${join(toolBin, "unapproved-tool")}'`).status, 0, "even by its host path");
        const secret = run(result, "fixture-tool", project, { FIXTURE_CONF: join(home, ".config", "fixture-secret", "leaky.conf") });
        assert.match(secret.stdout + secret.stderr, /No such file/);
        assert.equal(run(result, "echo $PATH").stdout.trim(), "/run/pi-confined/bin");
    });

    it("allows writes only to the project, a private /tmp, and nothing outside", () => {
        const result = plan(fixturePolicy);
        assert.equal(run(result, `echo w > '${join(project, "written.txt")}'`).status, 0);
        assert.equal(existsSync(join(project, "written.txt")), true);
        assert.notEqual(run(result, `echo w > '${join(other, "w.txt")}'`).status, 0);
        assert.notEqual(run(result, `echo w > '${join(shared, "ok", "w.txt")}'`).status, 0, "symlink targets are read-only");
        assert.notEqual(run(result, `echo w > '${join(home, "w.txt")}'`).status, 0);
        assert.equal(run(result, "echo w > /tmp/scratch && cat /tmp/scratch").stdout, "w\n");
        assert.equal(existsSync(join(root, "scratch")), false);
        assert.equal(existsSync("/tmp/scratch"), false, "/tmp is private to the sandbox");
    });

    it("keeps the network namespace unshared", () => {
        const result = plan(fixturePolicy);
        const command = buildSandboxCommand({
            profilePath: join(root, "unused.sb"), execPath: "/bin/true", execArgs: [],
            policy: { writableRoot: project, home, permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false }, readConfinement: result },
        });
        assert.ok(command.fileArgs.includes("--unshare-net"));
    });
});

const livePolicy = process.env.PI_READ_CONFINEMENT_LIVE_POLICY;
const liveProject = process.env.PI_READ_CONFINEMENT_LIVE_PROJECT;
describe("live site policy", { skip: !(livePolicy && liveProject && bwrapUsable) && "set PI_READ_CONFINEMENT_LIVE_POLICY and PI_READ_CONFINEMENT_LIVE_PROJECT" }, () => {
    it("plans and launches under the supplied policy", () => {
        const result = planReadConfinement(loadReadConfinementPolicyFile(livePolicy!), liveProject!);
        plans.push(result);
        const command = buildSandboxCommand({
            profilePath: join(root, "unused.sb"), execPath: "/bin/sh", execArgs: ["-c", "true"],
            policy: { writableRoot: liveProject!, home: process.env.HOME ?? home, permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false }, readConfinement: result },
        });
        assert.equal(spawnSync(command.file, command.fileArgs).status, 0);
    });
});
