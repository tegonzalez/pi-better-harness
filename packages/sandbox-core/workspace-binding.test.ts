/**
 * Workspace binding in the read-confinement planner: policy `readOnly` paths and limited
 * single-segment wildcards (approved PATH dirs / tool paths). Fixtures use an explicit
 * non-temp base (`/var/tmp`, or PI_READ_CONFINEMENT_TEST_BASE) because the sandbox's private
 * /tmp is writable by design; nothing names a real host, user, project or tool.
 * @level unit
 * @level integration
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildSandboxCommand, describeSandboxSupport, type SandboxCommandArgs } from "./index.ts";
import {
    hashPolicy,
    parseReadConfinementPolicy,
    planReadConfinement,
    ReadConfinementError,
    type ReadConfinementPolicy,
} from "./read-confinement.ts";

function fixtureBase(): string {
    return process.env.PI_READ_CONFINEMENT_TEST_BASE ?? (existsSync("/var/tmp") ? "/var/tmp" : tmpdir());
}

let root: string;
let home: string;
let project: string;
let share: string;
let wc: string;
const plans: { syntheticDir: string | undefined }[] = [];

function write(path: string, text: string, mode = 0o644): void {
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, text);
    chmodSync(path, mode);
}

before(() => {
    root = realpathSync(mkdtempSync(join(fixtureBase(), "workspace-binding-")));
    home = join(root, "home", "me");
    project = join(root, "work", "project");
    share = join(root, "shared-folder");
    wc = join(root, "versions");
    write(join(project, "file.txt"), "project\n");
    write(join(home, ".ssh", "id_fixture"), "credential\n");
    write(join(share, "doc.txt"), "shared doc\n");
    write(join(share, "link-out"), "");
    rmSync(join(share, "link-out"));
    write(join(root, "elsewhere", "leak.txt"), "not shared\n");
    symlinkSync(join(root, "elsewhere"), join(share, "link-out"));
    write(join(wc, "v1", "bin", "wtool-one"), "#!/bin/sh\necho one\n", 0o755);
    write(join(wc, "v2", "bin", "wtool-two"), "#!/bin/sh\necho two\n", 0o755);
    // A match whose realpath is outside every approved/bound location.
    write(join(root, "unapproved-bin", "sneaky"), "#!/bin/sh\necho sneaky\n", 0o755);
    symlinkSync(join(root, "unapproved-bin"), join(wc, "v3"));
    mkdirSync(join(wc, "v3-real-parent"), { recursive: true });
    symlinkSync(join(root, "unapproved-bin"), join(wc, "v3-real-parent", "bin"));
});

after(() => {
    for (const plan of plans) if (plan.syntheticDir) rmSync(plan.syntheticDir, { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
});

function plan(policy: ReadConfinementPolicy, pathDirs: string[] = [], at = project, extra: Parameters<typeof planReadConfinement>[2] = {}) {
    const raw = parseReadConfinementPolicy(policy);
    const result = planReadConfinement({ policy: raw, source: "test-fixture", sha256: hashPolicy(raw) }, at, {
        home, env: { PATH: [...pathDirs, "/usr/bin", "/bin"].join(":") }, passwdHomes: () => [], ...extra,
    });
    plans.push(result);
    return result;
}

describe("readOnly", () => {
    it("binds each realpath'd path read-only and records it", () => {
        const link = join(root, "share-link");
        symlinkSync(share, link);
        const result = plan({ version: 1, readOnly: [link] });
        assert.ok(result.readRoots.includes(share));
        const bind = result.audit.binds.find((b) => b.path === share);
        assert.equal(bind?.mode, "ro");
        assert.match(bind!.reason, /readOnly/);
        assert.ok(!result.writeRoots.includes(share));
        rmSync(link);
    });

    it("refuses paths that fail the deny list, contain a writable root or are missing, and records why", () => {
        const result = plan({ version: 1, readOnly: [join(home, ".ssh"), join(root, "work"), home, join(root, "nope")] });
        assert.ok(result.audit.denied.some((d) => d.path === join(home, ".ssh") && /denied path/.test(d.reason) && d.via === "readOnly"));
        assert.ok(result.audit.denied.some((d) => d.path === join(root, "work") && /contains the writable root/.test(d.reason)));
        assert.ok(result.audit.denied.some((d) => d.path === home && /contains denied path/.test(d.reason)), "a parent of a credential dir is refused");
        assert.ok(result.audit.skipped.some((d) => d.path === join(root, "nope") && d.reason === "not found"));
        assert.ok(!result.readRoots.includes(join(home, ".ssh")) && !result.readRoots.includes(home));
    });

    it("honours policy deny.paths", () => {
        const result = plan({ version: 1, deny: { paths: [share] }, readOnly: [share] });
        assert.ok(result.audit.denied.some((d) => d.path === share));
        assert.ok(!result.readRoots.includes(share));
    });

    it("rejects wildcards and non-path entries at parse time", () => {
        assert.throws(() => parseReadConfinementPolicy({ version: 1, readOnly: [`${share}/*`] }), /wildcards are not supported/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, readOnly: ["relative"] }), /must be absolute/);
    });

    it("changes the policy hash (it is part of the policy) and does not change plans without it", () => {
        const base = plan({ version: 1 });
        assert.notEqual(hashPolicy({ version: 1, readOnly: [share] }), hashPolicy({ version: 1 }));
        assert.equal(base.audit.wildcards, undefined);
    });
});

describe("wildcards", () => {
    it("rejects ** , relative and dotdot patterns", () => {
        assert.throws(() => parseReadConfinementPolicy({ version: 1, tools: { approvedPathDirs: [`${wc}/**/bin`] } }), /"\*\*" is not supported/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, tools: { approvedPathDirs: ["v*/bin"] } }), /must be absolute/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, tools: { approvedPathDirs: [`${wc}/*/../bin`] } }), /\.\./);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, tools: { approved: [{ path: `${wc}/**/x` }] } }), /\*\*/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, limits: { maxWildcardMatches: 0 } }), /integer >= 1/);
    });

    it("expands approvedPathDirs at launch; matches outside approved or bound locations are denied and audited", () => {
        const dirs = ["v1", "v2", "v3"].map((v) => join(wc, v, "bin"));
        const result = plan(
            { version: 1, readOnly: [wc], tools: { approvedPathDirs: [`${wc}/v*/bin`], builtinDefaults: false } },
            dirs,
        );
        const record = result.audit.wildcards?.find((w) => w.kind === "approvedPathDir");
        assert.ok(record && record.pattern === `${wc}/v*/bin`);
        assert.equal(record.matches.length, 3);
        assert.deepEqual(record.matches.filter((m) => m.accepted).map((m) => m.path), [join(wc, "v1", "bin"), join(wc, "v2", "bin")]);
        const rejected = record.matches.find((m) => !m.accepted)!;
        assert.equal(rejected.real, join(root, "unapproved-bin"));
        assert.match(rejected.reason!, /not inside an approved or bound location/);
        assert.ok(result.audit.denied.some((d) => d.path === join(root, "unapproved-bin") && d.via === "approved PATH directory"));
        const names = result.audit.syntheticPath!.tools.map((t) => t.name);
        assert.ok(names.includes("wtool-one") && names.includes("wtool-two"));
        assert.ok(!names.includes("sneaky"));
    });

    it("without an approved or bound location every match is refused", () => {
        const result = plan({ version: 1, tools: { approvedPathDirs: [`${wc}/v*/bin`], builtinDefaults: false } }, [join(wc, "v1", "bin")]);
        assert.equal(result.audit.wildcards![0]!.matches.every((m) => !m.accepted), true);
        assert.equal(result.audit.syntheticPath, undefined);
    });

    it("a tool bind counts as a bound location", () => {
        const result = plan({
            version: 1,
            tools: { approved: [{ name: "wtool-one", bind: [wc] }], approvedPathDirs: [`${wc}/v1*/bin`], builtinDefaults: false },
        }, [join(wc, "v1", "bin")]);
        assert.equal(result.audit.wildcards![0]!.matches[0]!.accepted, true);
    });

    it("expands a tool path wildcard", () => {
        const result = plan({ version: 1, readOnly: [wc], tools: { approved: [{ path: `${wc}/v*/bin/wtool-*` }], builtinDefaults: false } });
        const record = result.audit.wildcards?.find((w) => w.kind === "toolPath");
        assert.equal(record?.matches.filter((m) => m.accepted).length, 2);
        assert.deepEqual(result.audit.syntheticPath!.tools.map((t) => t.name).sort(), ["wtool-one", "wtool-two"]);
    });

    it("fails closed when a pattern exceeds the match cap", () => {
        assert.throws(() => plan({ version: 1, limits: { maxWildcardMatches: 1 }, readOnly: [wc], tools: { approvedPathDirs: [`${wc}/v*/bin`] } }, [join(wc, "v1", "bin")]),
            (error) => error instanceof ReadConfinementError && /maxWildcardMatches/.test(error.message));
    });

    it("`*` stays inside one segment and does not match dot entries", () => {
        write(join(wc, ".hidden", "bin", "ht"), "#!/bin/sh\n", 0o755);
        const result = plan({ version: 1, readOnly: [wc], tools: { approvedPathDirs: [`${wc}/*/bin`], builtinDefaults: false } }, [join(wc, "v1", "bin")]);
        const paths = result.audit.wildcards![0]!.matches.map((m) => m.path);
        assert.ok(!paths.some((p) => p.includes(".hidden")));
        assert.ok(paths.every((p) => p.split("/").length === `${wc}/x/bin`.split("/").length));
        rmSync(join(wc, ".hidden"), { recursive: true });
    });

    it("matching nothing is recorded as skipped", () => {
        const result = plan({ version: 1, tools: { approvedPathDirs: [`${root}/none-*/bin`] } });
        assert.ok(result.audit.skipped.some((s) => s.path === `${root}/none-*/bin`));
    });
});

const bwrapUsable = (() => {
    const support = describeSandboxSupport();
    if (!support.supported || support.backend !== "linux-bubblewrap") return false;
    return spawnSync(support.executable, ["--ro-bind", "/", "/", "--unshare-net", "true"]).status === 0;
})();

describe("real bubblewrap", { skip: !bwrapUsable && "usable bubblewrap is not available" }, () => {
    function run(result: ReturnType<typeof plan>, script: string) {
        const args: SandboxCommandArgs = {
            profilePath: join(root, "unused.sb"), execPath: "/bin/sh", execArgs: ["-c", script],
            policy: {
                writableRoot: project, home, denyWrite: [],
                permissions: { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false },
                readConfinement: result,
            },
        };
        const command = buildSandboxCommand(args, { env: { HOME: home } });
        return spawnSync(command.file, command.fileArgs, { encoding: "utf8", env: { HOME: home } });
    }
    const policy: ReadConfinementPolicy = {
        version: 1, readOnly: [share, wc],
        tools: { approved: ["sh", "cat", "ls"], approvedPathDirs: [`${wc}/v*/bin`], builtinDefaults: false },
    };
    const dirs = ["v1", "v2", "v3"].map((v) => join(wc, v, "bin"));

    it("a readOnly folder is readable, not writable, and its symlinks are not followed", () => {
        const result = plan(policy, dirs);
        assert.equal(run(result, `cat '${join(share, "doc.txt")}'`).stdout, "shared doc\n");
        assert.notEqual(run(result, `echo x > '${join(share, "new.txt")}'`).status, 0);
        assert.equal(existsSync(join(share, "new.txt")), false);
        const out = run(result, `cat '${join(share, "link-out", "leak.txt")}'`);
        assert.notEqual(out.status, 0);
    });

    it("wildcard-approved tools run; the refused match is absent; other projects stay hidden", () => {
        const result = plan(policy, dirs);
        assert.equal(run(result, "wtool-one").stdout, "one\n");
        assert.equal(run(result, "wtool-two").stdout, "two\n");
        assert.notEqual(run(result, "sneaky").status, 0);
        assert.notEqual(run(result, `cat '${join(root, "elsewhere", "leak.txt")}'`).status, 0);
        assert.notEqual(run(result, `cat '${join(home, ".ssh", "id_fixture")}'`).status, 0);
    });
});
