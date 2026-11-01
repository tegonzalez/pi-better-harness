/**
 * Inherited descriptors (`hardening.fds`): a confined child sees only descriptors 0, 1 and 2 (plus any the launch passes on purpose, such as a
 * seccomp program). /proc is absent inside, so the probe is `>&N` writes to two marker files that the host holds
 * open on descriptors 3 and 7 WITHOUT close-on-exec; a leak shows up as marker content on the host.
 *
 * Three levels of evidence, each with a control (`hardening.fds = false`) that proves the probe can see a leak:
 *  1. argument builder: the confined command built from the controller's frozen plan, spawned with the markers
 *     left open (how a spawner or outer shell that leaks descriptors looks to bubblewrap);
 *  2. foreground launcher with a leaky outer shell (a configured shell that opens the markers, then execs the
 *     real shell, as a user's shell start-up file can): the real launcher path leaks them unless the measure holds;
 *  3. every launcher type with a test seam, started in its own process that inherits the markers: foreground
 *     bash, task bash, background tasks (process.ts) and subagents (spawn.ts + sandbox.ts).
 *
 * NOTE on level 3: Node's own child_process closes every descriptor that is not named in `stdio`, so a launcher
 * that spawns bubblewrap directly cannot leak an inherited descriptor on this Node, with or without the measure;
 * level 3 therefore has no working control and only guards against a launcher starting to pass descriptors on
 * purpose. The falsifiable evidence is levels 1 and 2.
 *
 * Not covered: task file operations (task-sandbox/files.ts) run a fixed worker program with JSON on
 * stdin. No seam lets a test put a probe inside, and /proc is absent, so a descriptor leak there cannot be observed
 * from outside, so nothing is claimed for it. Its spawn also names only stdio, so it shares the level 3 reasoning.
 *
 * Expected results come from kernel semantics. Skips without bubblewrap; with PI_SANDBOX_REQUIRE_BACKEND set, a
 * missing or unusable bubblewrap fails instead.
 * @level kernel
 */
import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import test, { after, before } from "node:test";

import { baseSkip, launchWithInheritedFds, leakProbeViaBuilder, leakProbeViaOuterShell, makeFixture, type Fixture } from "./support/hardening-support.ts";

const skip = baseSkip();
const KINDS = ["foreground", "task-bash", "background", "subagent"] as const;

let fx: Fixture;
before(() => { if (!skip) fx = makeFixture("pbs-hardening-fds-"); });
after(() => { if (fx) rmSync(fx.root, { recursive: true, force: true }); });

test("[fds] argument builder: descriptors left open by the spawner are not usable inside; fds=false lets them through again", { skip }, () => {
    const hardened = leakProbeViaBuilder(fx, undefined, "default");
    assert.equal(hardened.exitCode, 0, hardened.output);
    assert.match(hardened.output, /probe-done/, "the probe ran to the end");
    assert.equal(hardened.leaked3, false, "descriptor 3 must not be usable inside");
    assert.equal(hardened.leaked7, false, "descriptor 7 must not be usable inside");

    const open = leakProbeViaBuilder(fx, { fds: false }, "off");
    assert.equal(open.exitCode, 0, open.output);
    assert.equal(open.leaked3 && open.leaked7, true, "fds=false: both descriptors are usable inside (the old behaviour; proves the probe)");
});

test("[fds] foreground launcher with a leaky outer shell: descriptors the shell holds are not usable inside; fds=false lets them through again", { skip }, async () => {
    const hardened = await leakProbeViaOuterShell(fx, undefined, "default");
    assert.equal(hardened.exitCode, 0, hardened.output);
    assert.match(hardened.output, /probe-done/);
    assert.equal(hardened.leaked3, false, "descriptor 3 must not be usable inside");
    assert.equal(hardened.leaked7, false, "descriptor 7 must not be usable inside");

    const open = await leakProbeViaOuterShell(fx, { fds: false }, "off");
    assert.equal(open.exitCode, 0, open.output);
    assert.equal(open.leaked3 && open.leaked7, true, "fds=false: the shell's descriptors reach the sandbox (the old behaviour; proves the probe)");
});

for (const kind of KINDS) {
    test(`[fds] ${kind} launcher, started with inherited descriptors: none is usable inside (guard; no control on this Node, see file header)`, { skip }, () => {
        const hardened = launchWithInheritedFds(fx, kind, undefined, `${kind}-default`);
        assert.equal(hardened.result.error, undefined, `the launch worked: ${hardened.result.error}`);
        assert.equal(hardened.result.exitCode, 0, hardened.result.output);
        assert.match(hardened.result.output ?? "", /probe-done/, "the probe ran to the end");
        assert.equal(hardened.leaked3, false, "descriptor 3 must not be usable inside");
        assert.equal(hardened.leaked7, false, "descriptor 7 must not be usable inside");
    });
}
