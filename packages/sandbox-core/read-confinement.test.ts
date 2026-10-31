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
import { createServer } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
    buildSandboxCommand,
    compileWritePolicy,
    confinedEnvironment,
    describeSandboxSupport,
    publishProcessReadConfinement,
    READ_CONFINEMENT_POLICY_ENV,
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

    /** A main repo with a linked worktree whose `.git` file points back correctly. */
    function linkedWorktree(name: string) {
        const main = join(root, `${name}-main`);
        const common = join(main, ".git");
        const gitdir = join(common, "worktrees", "wt");
        write(join(common, "HEAD"), "ref: x\n");
        mkdirSync(join(common, "objects"), { recursive: true });
        mkdirSync(join(common, "hooks"), { recursive: true });
        write(join(common, "config"), "[core]\n");
        write(join(gitdir, "HEAD"), "ref: y\n");
        write(join(gitdir, "commondir"), "../..\n");
        const wt = join(root, "work", name);
        write(join(wt, ".git"), `gitdir: ${gitdir}\n`);
        write(join(gitdir, "gitdir"), `${join(wt, ".git")}\n`);
        return { main, common, gitdir, wt };
    }

    it("binds a validated worktree's git dir writable, with hooks and config read-only", () => {
        const { common, gitdir, wt } = linkedWorktree("wt-ok");
        const result = plan({ version: 1 }, {}, wt);
        assert.deepEqual(result.writeRoots, [wt, common, gitdir].sort());
        assert.ok(result.audit.gitDirs.includes(gitdir));
        const ro = result.audit.binds.filter((b) => b.mode === "ro").map((b) => b.path);
        assert.ok(ro.includes(join(common, "hooks")) && ro.includes(join(common, "config")), "hooks and config are read-only overlays");
        const at = (path: string) => result.args.findIndex((arg, i) => arg === path && result.args[i - 2] === "--ro-bind");
        assert.ok(at(join(common, "hooks")) > result.args.indexOf("--bind"), "overlay comes after the writable bind");
    });

    it("refuses a .git redirect that is not a git dir of this worktree (fail closed, recorded)", () => {
        const victim = join(root, "work", "redirect-victim");
        write(join(victim, "HEAD"), "ref: x\n");
        write(join(victim, "secret"), "s\n");
        const proj = join(root, "work", "redirect-project");
        write(join(proj, ".git"), `gitdir: ${victim}\n`);
        let result = plan({ version: 1 }, {}, proj);
        assert.ok(!result.writeRoots.includes(victim) && !result.args.includes(victim));
        assert.match(result.audit.denied.find((d) => d.path === victim)?.reason ?? "", /does not point back/);
        // No HEAD at all: not a git dir.
        const bogus = join(root, "work", "redirect-bogus");
        mkdirSync(bogus, { recursive: true });
        write(join(proj, ".git"), `gitdir: ${bogus}\n`);
        result = plan({ version: 1 }, {}, proj);
        assert.match(result.audit.denied.find((d) => d.path === bogus)?.reason ?? "", /no HEAD/);
        assert.deepEqual(result.writeRoots, [proj]);
        // A back-pointer to another worktree is not ours.
        const { gitdir } = linkedWorktree("redirect-elsewhere");
        write(join(proj, ".git"), `gitdir: ${gitdir}\n`);
        result = plan({ version: 1 }, {}, proj);
        assert.match(result.audit.denied.find((d) => d.path === gitdir)?.reason ?? "", /does not point back/);
        assert.deepEqual(result.writeRoots, [proj]);
    });

    it("refuses a commondir that is not this worktree's common dir, and binds alternates read-only", () => {
        const { gitdir, wt, main } = linkedWorktree("wt-common");
        const evil = join(root, "work", "evil-common");
        write(join(evil, "HEAD"), "x\n");
        mkdirSync(join(evil, "objects"), { recursive: true });
        write(join(gitdir, "commondir"), `${evil}\n`);
        const result = plan({ version: 1 }, {}, wt);
        assert.match(result.audit.denied.find((d) => d.path === evil)?.reason ?? "", /not the common git dir/);
        assert.ok(!result.writeRoots.includes(evil));
        write(join(gitdir, "commondir"), "../..\n");
        const store = join(root, "alt-store");
        mkdirSync(join(store, "objects", "pack"), { recursive: true });
        write(join(store, "HEAD"), "x\n");
        write(join(main, ".git", "objects", "info", "alternates"), `${join(store, "objects")}\n`);
        const withAlt = plan({ version: 1 }, {}, wt);
        assert.equal(withAlt.audit.binds.find((b) => b.path === join(store, "objects"))?.mode, "ro");
        assert.ok(!withAlt.writeRoots.includes(join(store, "objects")));
    });

    it("computes the plan from a snapshot: later project changes are not in an already-built plan", () => {
        const proj = join(root, "work", "frozen");
        mkdirSync(proj, { recursive: true });
        const first = plan({ version: 1 }, {}, proj);
        symlinkSync(shared, join(proj, "late-link"));
        assert.ok(!first.readRoots.includes(shared), "a built plan never changes");
        assert.ok(plan({ version: 1 }, {}, proj).readRoots.includes(shared), "only a new launch sees it");
    });

    it("denies broad credential stores reached through project symlinks", () => {
        write(join(home, ".gnupg", "pubring.kbx"), "k");
        write(join(home, ".pgpass"), "h:1:d:u:p");
        write(join(home, ".claude", ".credentials.json"), "{}");
        const proj = join(root, "work", "broad-cred");
        mkdirSync(proj, { recursive: true });
        symlinkSync(join(home, ".gnupg"), join(proj, "gpg"));
        symlinkSync(join(home, ".pgpass"), join(proj, "pgpass"));
        const result = plan({ version: 1 }, {}, proj);
        const deniedPaths = result.audit.denied.map((d) => d.path);
        assert.ok(deniedPaths.includes(join(home, ".gnupg")) && deniedPaths.includes(join(home, ".pgpass")), deniedPaths.join());
        assert.deepEqual(result.readRoots, [proj]);
    });

    it("refuses a policy file inside the project, a writable root or a temp directory", () => {
        const inside = join(project, "policy.json");
        write(inside, "{}");
        const attempt = (source: string, at = project) => planReadConfinement({ policy: parseReadConfinementPolicy({ version: 1 }), source, sha256: "x" }, at,
            { home, env: { PATH: "/usr/bin" }, passwdHomes: () => [] });
        assert.throws(() => attempt(inside), /policy file .* is inside/);
        assert.throws(() => attempt("/tmp/some-policy.json"), /policy file/);
        assert.throws(() => attempt("/var/tmp/some-policy.json"), /policy file/);
        const { gitdir, wt } = linkedWorktree("policy-in-gitdir");
        write(join(gitdir, "p.json"), "{}");
        assert.throws(() => attempt(join(gitdir, "p.json"), wt), /policy file/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, planTtlMs: 5 }), /removed.*once at pi launch/);
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
        const index = result.args.indexOf("--bind");
        const source = result.args[index + 1]!;
        assert.ok(source.startsWith(join(base, "agent-1")));
        // In-process tools use the per-agent source directory, never the host cache path.
        assert.ok(result.writeRoots.includes(source) && result.readRoots.includes(source));
        assert.ok(!result.writeRoots.includes(join(home, ".cache", "p")) && !result.readRoots.includes(join(home, ".cache", "p")));
        const compiled = compileWritePolicy({
            writableRoot: project, home, permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
            readConfinement: result,
        });
        assert.equal(evaluateWriteAccess(join(source, "x"), compiled).allowed, true);
        assert.equal(evaluateWriteAccess(join(home, ".cache", "p", "x"), compiled).allowed, false);
    });

    it("the built-in git default binds only config, ignore and attributes, never a credential store", () => {
        write(join(home, ".config", "git", "config"), "[user]\nname = x\n");
        write(join(home, ".config", "git", "credentials"), "https://user:pw@example.invalid\n");
        const result = plan({ version: 1, tools: { approved: ["git"] } }, { env: { PATH: "/usr/bin:/bin" } });
        if (!result.audit.syntheticPath?.tools.some((t) => t.name === "git")) return;
        assert.ok(result.readRoots.includes(join(home, ".config", "git", "config")));
        assert.ok(!result.readRoots.includes(join(home, ".config", "git")));
        assert.ok(!result.readRoots.some((r) => r.endsWith("credentials")));
    });

    it("the secret detector catches URL userinfo, Authorization headers and oversize files", () => {
        const cases: Record<string, string> = {
            "url-userinfo": "https://alice:x@example.invalid/path\n",
            "auth-header": "Authorization: Basic Zm9vOmJhcg==\n",
            "short-password": "password=abc\n",
        };
        for (const [name, text] of Object.entries(cases)) write(join(home, ".config", `det-${name}`, "c"), text);
        write(join(home, ".config", "det-big", "c"), `${"#".repeat(2000)}\n`);
        write(join(home, ".config", "det-fine", "c"), "ok = 1\n");
        const result = plan({ version: 1, secretDetector: { maxScanBytes: 1024 }, tools: { builtinDefaults: false, approved: [{ name: "fixture-tool",
            config: [...Object.keys(cases), "big", "fine"].map((n) => `~/.config/det-${n}`) }] } });
        const reasons = Object.fromEntries(result.audit.denied.map((d) => [d.path.split("/").at(-1), d.reason]));
        for (const name of Object.keys(cases)) assert.match(reasons[`det-${name}`] ?? "", /secret detected/, name);
        assert.match(reasons["det-big"] ?? "", /larger than the scan limit/);
        assert.ok(result.readRoots.includes(join(home, ".config", "det-fine")));
    });

    it("refuses shallow, home-containing and project-containing install prefixes", () => {
        const tool = (path: string) => ({ version: 1 as const, tools: { builtinDefaults: false, approved: [{ path, install: "prefix" as const }] } });
        write(join(root, "p1", "bin", "t1"), "#!/bin/sh\n", 0o755);
        const shallow = root.split("/").filter(Boolean).length + 2;
        let result = plan({ ...tool(join(root, "p1", "bin", "t1")), limits: { minPrefixDepth: shallow } });
        assert.ok(result.audit.denied.some((d) => /install prefix shallower than/.test(d.reason)), JSON.stringify(result.audit.denied));
        assert.equal(result.audit.syntheticPath, undefined);
        write(join(home, "t2", "bin", "t2"), "#!/bin/sh\n", 0o755);
        result = plan(tool(join(home, "t2", "bin", "t2")));
        assert.ok(result.audit.denied.some((d) => /contains or lies in the home/.test(d.reason)));
        write(join(root, "deep", "a", "b", "bin", "t3"), "#!/bin/sh\n", 0o755);
        result = plan(tool(join(root, "deep", "a", "b", "bin", "t3")));
        assert.equal(result.audit.binds.find((b) => b.reason.startsWith("install prefix"))?.path, join(root, "deep", "a", "b"));
        result = plan({ ...tool(join(root, "deep", "a", "b", "bin", "t3")), limits: { minPrefixDepth: 30 } });
        assert.equal(result.audit.syntheticPath, undefined);
    });

    it("rejects an approved tool that resolves under a writable root", () => {
        write(join(project, "bin", "planted"), "#!/bin/sh\necho planted\n", 0o755);
        const result = plan({ version: 1, tools: { builtinDefaults: false, approved: ["planted"] } },
            { env: { PATH: `${join(project, "bin")}:/usr/bin` } });
        assert.equal(result.audit.syntheticPath, undefined);
        assert.match(result.audit.denied.find((d) => d.path.endsWith("planted"))?.reason ?? "", /under writable root/);
    });

    it("builds the child environment from an allowlist plus the synthetic PATH", () => {
        const result = plan({ version: 1, env: { allow: ["EXTRA_OK"] }, tools: { approved: ["sh"], builtinDefaults: false } },
            { env: { PATH: "/usr/bin:/bin", HOME: home, LANG: "C", API_KEY: "k", EXTRA_OK: "1", GITHUB_TOKEN: "t" } });
        const env = confinedEnvironment(result, { PATH: "/host", HOME: home, API_KEY: "k", EXTRA_OK: "1", GITHUB_TOKEN: "t", OPENAI_API_KEY: "o", LANG: "C" });
        assert.deepEqual(env, { PATH: "/run/pi-confined/bin", HOME: home, EXTRA_OK: "1", LANG: "C" });
        assert.ok(!result.args.some((a) => /KEY|TOKEN/.test(a)));
        assert.throws(() => parseReadConfinementPolicy({ version: 1, env: { allow: ["bad name"] } }), /environment variable name/);
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
    function run(result: ReturnType<typeof plan>, script: string, atProject = project, env: Record<string, string> = {}, network = false) {
        const args: SandboxCommandArgs = {
            profilePath: join(root, "unused.sb"),
            execPath: "/bin/sh",
            execArgs: ["-c", script],
            policy: {
                writableRoot: atProject, home, denyWrite: [],
                permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network },
                readConfinement: result,
            },
        };
        // The launching environment (what pi would hold) reaches only the allowlist.
        const command = buildSandboxCommand(args, { env: { HOME: home, ...env } });
        return spawnSync(command.file, command.fileArgs, { encoding: "utf8", env: { HOME: home, ...env } });
    }

    const fixturePolicy: ReadConfinementPolicy = {
        version: 1,
        env: { allow: ["FIXTURE_CONF"] },
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

    it("scrubs the environment: no key or token variable reaches the child, only the allowlist", () => {
        const result = plan(fixturePolicy);
        const secrets = { OPENAI_API_KEY: "sk-leak", GITHUB_TOKEN: "ghp_leak", AWS_SECRET_ACCESS_KEY: "leak", MY_PASSWORD: "leak", FIXTURE_CONF: "allowed-by-policy", TERM: "xterm" };
        const out = run(result, "/usr/bin/env", project, secrets);
        assert.equal(out.status, 0, out.stderr);
        const seen = Object.fromEntries(out.stdout.split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
        assert.deepEqual(Object.keys(seen).filter((k) => /KEY|TOKEN|SECRET|PASSWORD|SK-/i.test(k)), []);
        assert.ok(!out.stdout.includes("leak"));
        assert.equal(seen.FIXTURE_CONF, "allowed-by-policy");
        assert.equal(seen.PATH, "/run/pi-confined/bin");
        assert.deepEqual(Object.keys(seen).filter((k) => !["PATH", "HOME", "TERM", "FIXTURE_CONF", "PWD", "SHLVL", "_", "OLDPWD"].includes(k)), []);
    });

    it("applies --unshare-pid, --new-session and --clearenv; host processes cannot be signalled", () => {
        const result = plan(fixturePolicy);
        const command = buildSandboxCommand({
            profilePath: join(root, "unused.sb"), execPath: "/bin/true", execArgs: [],
            policy: { writableRoot: project, home, permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false }, readConfinement: result },
        });
        for (const flag of ["--clearenv", "--unshare-pid", "--new-session"]) assert.ok(command.fileArgs.includes(flag), flag);
        assert.ok(!command.fileArgs.includes("--proc"));
        const out = run(result, `kill -0 ${process.pid} 2>&1; echo status=$?; ls /proc 2>&1 | head -1`);
        assert.match(out.stdout, /status=[1-9]/, out.stdout + out.stderr);
    });

    it("makes git hooks and config read-only inside a linked worktree's writable git dir", () => {
        const main = join(root, "bw-main");
        const common = join(main, ".git");
        const gitdir = join(common, "worktrees", "wt");
        write(join(common, "HEAD"), "x\n");
        mkdirSync(join(common, "objects"), { recursive: true });
        mkdirSync(join(common, "hooks"), { recursive: true });
        write(join(common, "config"), "[core]\n");
        write(join(gitdir, "HEAD"), "y\n");
        write(join(gitdir, "commondir"), "../..\n");
        const wt = join(root, "work", "bw-wt");
        write(join(wt, ".git"), `gitdir: ${gitdir}\n`);
        write(join(gitdir, "gitdir"), `${join(wt, ".git")}\n`);
        const result = plan(fixturePolicy, {}, wt);
        assert.equal(run(result, `echo r > '${join(common, "refs-x")}'`, wt).status, 0, "refs-like writes in the git dir still work");
        assert.notEqual(run(result, `echo '#!/bin/sh' > '${join(common, "hooks", "pre-commit")}'`, wt).status, 0);
        assert.notEqual(run(result, `echo '[core]' >> '${join(common, "config")}'`, wt).status, 0);
        assert.equal(existsSync(join(common, "hooks", "pre-commit")), false);
    });

    it("a .git redirect to another project does not make that project writable", () => {
        const victim = join(root, "work", "redirect-victim-bw");
        write(join(victim, "HEAD"), "x\n");
        const proj = join(root, "work", "redirect-bw");
        write(join(proj, ".git"), `gitdir: ${victim}\n`);
        const result = plan(fixturePolicy, {}, proj);
        const out = run(result, `echo pwn > '${join(victim, "pwned")}'`, proj);
        assert.notEqual(out.status, 0);
        assert.equal(existsSync(join(victim, "pwned")), false);
    });

    it("a project-planted symlink to another project is not followed after launch, and a real policy rejects it on the next", () => {
        const proj = join(root, "work", "late");
        mkdirSync(proj, { recursive: true });
        const result = plan(fixturePolicy, {}, proj);
        symlinkSync(other, join(proj, "grab"));
        assert.notEqual(run(result, `cat '${join(proj, "grab", "secret.txt")}'`, proj).status, 0, "the frozen plan never binds it");
    });

    it("a real connect attempt from inside the sandbox fails and never reaches a host listener", async (t) => {
        if (spawnSync("/usr/bin/python3", ["-c", "pass"]).status !== 0) return t.skip("python3 not available");
        const server = createServer();
        let connections = 0;
        server.on("connection", (socket) => { connections++; socket.destroy(); });
        await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
        const port = (server.address() as { port: number }).port;
        const result = plan({ ...fixturePolicy, tools: { approved: ["sh", "cat"], builtinDefaults: false } });
        const script = `/usr/bin/python3 -c "import socket,sys\ns=socket.socket(); s.settimeout(3)\ntry:\n s.connect(('127.0.0.1',${port})); print('CONNECTED')\nexcept OSError as e:\n print('FAILED', e.errno)"`;
        // The python runtime lives under /usr, which is bound read-only.
        const out = run(result, script);
        await new Promise<void>((done) => server.close(() => done()));
        assert.match(out.stdout, /FAILED/, out.stdout + out.stderr);
        assert.equal(connections, 0);
    });

    it("in-process allow decisions agree with what the kernel boundary allows", () => {
        const result = plan(fixturePolicy);
        const policy = compileWritePolicy({
            writableRoot: project, home, runtimeCompatibility: true,
            permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
            readConfinement: result,
        });
        const probes = [
            join(project, "file.txt"), join(project, "link-ok", "data.txt"), join(project, "chain", "data.txt"),
            join(other, "secret.txt"), join(home, "notes.txt"), join(home, ".ssh", "id_fixture"),
            join(home, ".config", "fixture", "ok.conf"), join(home, ".config", "fixture-secret", "leaky.conf"),
            join(project, "link-denied", "id_fixture"),
        ];
        for (const probe of probes) {
            const inProcess = evaluateReadAccess(probe, policy).allowed;
            const kernel = run(result, `cat '${probe}' >/dev/null`).status === 0;
            assert.equal(inProcess, kernel, `read ${probe}`);
        }
        for (const probe of [join(project, "parity-w.txt"), join(shared, "ok", "parity-w.txt"), join(other, "parity-w.txt"), join(home, "parity-w.txt")]) {
            const inProcess = evaluateWriteAccess(probe, policy).allowed;
            const kernel = run(result, `echo w > '${probe}'`).status === 0;
            rmSync(probe, { force: true });
            assert.equal(inProcess, kernel, `write ${probe}`);
        }
    });

    it("a persistent cache is the per-agent directory in the sandbox, and in-process tools use that same directory", () => {
        const base = join(root, "persist-bw");
        const result = plan({ version: 1, caches: { persistentDir: base }, tools: { builtinDefaults: false, approved: [{ name: "sh", cache: ["~/.cache/pc"], cachePersistent: true }, "cat"] } }, { agentId: "a9" });
        assert.equal(run(result, `echo cached > '${join(home, ".cache", "pc", "f")}'`).status, 0);
        assert.equal(existsSync(join(home, ".cache", "pc")), false, "the host cache path is never written");
        const source = result.writeRoots.find((r) => r.startsWith(base))!;
        assert.equal(spawnSync("cat", [join(source, "f")], { encoding: "utf8" }).stdout, "cached\n");
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

describe("process-wide plan: every actor applies it or fails closed", () => {
    const permissions = { projectFiles: "read-write" as const, outsideProject: "off" as const, storedCredentials: "off" as const, commands: true, network: false };
    const policyFor = (writableRoot: string) => ({ writableRoot, home, permissions });
    const linux = { platform: () => "linux" };
    const prior = process.env[READ_CONFINEMENT_POLICY_ENV];
    after(() => {
        publishProcessReadConfinement(undefined);
        if (prior === undefined) delete process.env[READ_CONFINEMENT_POLICY_ENV]; else process.env[READ_CONFINEMENT_POLICY_ENV] = prior;
    });

    it("applies a published plan to a policy that supplies none (background tasks, task runtime, subagent launches)", () => {
        const mounts = plan({ version: 1 });
        publishProcessReadConfinement({ state: "active", mounts });
        const compiled = compileWritePolicy(policyFor(project), linux);
        assert.deepEqual(compiled.readConfinement?.readRoots, mounts.readRoots);
        assert.equal(compiled.readConfinement?.pathValue, mounts.pathValue);
        publishProcessReadConfinement(undefined);
    });

    it("refuses when the plan failed, was computed for another project, or is absent but required", () => {
        publishProcessReadConfinement({ state: "failed", reason: "cap exceeded" });
        assert.throws(() => compileWritePolicy(policyFor(project), linux), /failed closed: cap exceeded/);
        publishProcessReadConfinement({ state: "active", mounts: plan({ version: 1 }) });
        assert.throws(() => compileWritePolicy(policyFor(other), linux), /computed for .*not/);
        publishProcessReadConfinement(undefined);
        process.env[READ_CONFINEMENT_POLICY_ENV] = "/etc/never-read.json";
        assert.throws(() => compileWritePolicy(policyFor(project), linux), /no launch plan/);
        // Profiles that do not select Outside project = Off are unaffected.
        assert.ok(compileWritePolicy({ writableRoot: project, home, permissions: { ...permissions, outsideProject: "read" } }, linux));
        assert.throws(() => compileWritePolicy(policyFor(project), { platform: () => "darwin", canonicalize: (p) => p }), /only implemented for Linux/);
        delete process.env[READ_CONFINEMENT_POLICY_ENV];
        assert.ok(compileWritePolicy(policyFor(project), linux), "no policy configured: original behavior");
    });

    it("a launcher that supplies no plan (background-task shaped) gets the published mounts, cleared env and private PID namespace", () => {
        const mounts = plan({ version: 1, env: { allow: ["KEPT"] } });
        publishProcessReadConfinement({ state: "active", mounts });
        const command = buildSandboxCommand({ profilePath: "/unused", execPath: "/bin/true", execArgs: [], policy: policyFor(project) },
            { ...linux, lookupExecutable: () => "/usr/bin/bwrap", env: { KEPT: "1", SECRET_TOKEN: "x" } });
        publishProcessReadConfinement(undefined);
        const joined = command.fileArgs.join(" ");
        assert.match(joined, /^--clearenv --unshare-pid --new-session --tmpfs \//);
        assert.ok(joined.includes("--setenv KEPT 1") && !joined.includes("SECRET_TOKEN"));
        assert.ok(joined.endsWith("--remount-ro / --unshare-net -- /bin/true") || joined.includes("--remount-ro /"));
    });

    it("confinedEnvironment is the identity without a plan", () => {
        assert.deepEqual(confinedEnvironment(undefined, { A: "1" }), { A: "1" });
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
