/**
 * Implementer tests for the internal helpers of confined-launch hardening: the generated seccomp program,
 * the measure states and the policy parser. Not the acceptance tests (those are the test author's).
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { hardeningStates, keyringSeccompProgram, KEYRING_SYSCALLS, resolveHardening, DEFAULT_HARDENING_HOSTNAME } from "./index.ts";
import { hashPolicy, parseReadConfinementPolicy } from "./read-confinement.ts";

/** Minimal classic-BPF interpreter for the opcodes the program uses. */
function run(program: Buffer, arch: number, nr: number): number {
    const data = (offset: number): number => (offset === 0 ? nr : offset === 4 ? arch : NaN) >>> 0;
    let a = 0;
    for (let pc = 0; pc < program.length / 8; pc++) {
        const code = program.readUInt16LE(pc * 8), jt = program[pc * 8 + 2]!, jf = program[pc * 8 + 3]!, k = program.readUInt32LE(pc * 8 + 4);
        if (code === 0x20) a = data(k);
        else if (code === 0x15) pc += a === k ? jt : jf;
        else if (code === 0x45) pc += (a & k) !== 0 ? jt : jf;
        else if (code === 0x06) return k;
        else assert.fail(`unexpected opcode ${code}`);
    }
    return assert.fail("fell off the program");
}

const X86_64 = 0xc000003e, AARCH64 = 0xc00000b7, I386 = 0x40000003;
const ALLOW = 0x7fff0000, DENY = 0x00050001, KILL = 0x80000000;

describe("keyring seccomp program", () => {
    const program = keyringSeccompProgram();
    it("is whole 8-byte instructions ending in a verdict", () => {
        assert.equal(program.length % 8, 0);
        assert.ok(program.length > 0 && program.length / 8 <= 64);
    });
    it("denies the three keyring calls with EPERM on x86_64 and aarch64", () => {
        for (const nr of Object.values(KEYRING_SYSCALLS.x86_64)) assert.equal(run(program, X86_64, nr), DENY, `x86_64 ${nr}`);
        for (const nr of Object.values(KEYRING_SYSCALLS.aarch64)) assert.equal(run(program, AARCH64, nr), DENY, `aarch64 ${nr}`);
    });
    it("allows other calls, including a keyring number of the other architecture", () => {
        for (const nr of [0, 1, 39, 59, 231]) assert.equal(run(program, X86_64, nr), ALLOW);
        for (const nr of [63, 93, 221]) assert.equal(run(program, AARCH64, nr), ALLOW);
        assert.equal(run(program, X86_64, KEYRING_SYSCALLS.aarch64.keyctl), ALLOW);
        assert.equal(run(program, AARCH64, KEYRING_SYSCALLS.x86_64.keyctl), ALLOW);
    });
    it("kills a process using the x32 ABI or another architecture instead of leaving a way around", () => {
        assert.equal(run(program, X86_64, 0x40000000 | KEYRING_SYSCALLS.x86_64.keyctl), KILL);
        assert.equal(run(program, I386, 288), KILL);
    });
});

describe("hardening states", () => {
    const help = "--unshare-ipc --unshare-uts --hostname NAME --unshare-user --uid UID --gid GID --disable-userns --seccomp FD\n--unshare-pid";
    const all = resolveHardening();
    it("defaults every measure on with a generic hostname", () => {
        assert.deepEqual([all.ipc, all.uts, all.userns, all.keyring, all.fds], [true, true, true, true, true]);
        assert.equal(all.hostname, DEFAULT_HARDENING_HOSTNAME);
    });
    it("reports on, off by policy and unavailable with a reason", () => {
        const states = hardeningStates(resolveHardening({ ipc: false }), "/x/bwrap", { bwrapHelp: () => help });
        assert.equal(states.ipc.state, "off");
        assert.equal(states.uts.state, "on");
        const old = hardeningStates(all, "/x/bwrap", { bwrapHelp: () => help.replace("--disable-userns", "") });
        assert.equal(old.userns.state, "unavailable");
        assert.match((old.userns as { reason: string }).reason, /--disable-userns/);
        assert.equal(old.ipc.state, "on");
    });
    it("makes the keyring unavailable on an architecture without a table, and everything without bubblewrap", () => {
        const riscv = hardeningStates(all, "/x/bwrap", { bwrapHelp: () => help, arch: "riscv64" });
        assert.equal(riscv.keyring.state, "unavailable");
        assert.equal(riscv.ipc.state, "on");
        const none = hardeningStates(all, undefined, {});
        assert.ok(["ipc", "uts", "userns", "keyring", "fds"].every((m) => (none as Record<string, { state: string }>)[m]!.state === "unavailable"));
    });
});

describe("hardening policy", () => {
    it("parses switches and a hostname, refuses unknown keys and bad values, and hashes them", () => {
        const base = parseReadConfinementPolicy({ version: 1 });
        const set = parseReadConfinementPolicy({ version: 1, hardening: { keyring: false, hostname: "box-1" } });
        assert.deepEqual(set.hardening, { keyring: false, hostname: "box-1" });
        assert.notEqual(hashPolicy(base), hashPolicy(set));
        assert.throws(() => parseReadConfinementPolicy({ version: 1, hardening: { ipcc: true } }), /unknown key/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, hardening: { ipc: "no" } }), /boolean/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, hardening: { hostname: "a b" } }), /host name/);
        assert.throws(() => parseReadConfinementPolicy({ version: 1, hardening: { hostname: "x".repeat(65) } }), /host name/);
    });
});
