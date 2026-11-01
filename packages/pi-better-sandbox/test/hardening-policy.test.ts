/**
 * Row `switches` (parser half): the read-confinement policy's optional `hardening` object. Boolean keys `ipc`,
 * `uts`, `userns`, `keyring`, `fds` (all default true) and an optional string `hostname`. Unknown keys are
 * refused at load, values of the wrong type are refused, and every switch is part of `policyHash`.
 * The frozen interface is the key set; error wording is the product's.
 * @level unit
 */
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test, { after } from "node:test";

import { hashPolicy, loadReadConfinementPolicyFile, parseReadConfinementPolicy } from "../shared-read-confinement.ts";
import { base } from "./support/hardening-support.ts";

const SWITCHES = ["ipc", "uts", "userns", "keyring", "fds"] as const;
const parse = (hardening: unknown) => parseReadConfinementPolicy({ version: 1, hardening });
const hash = (hardening?: unknown) => hashPolicy(parseReadConfinementPolicy({ version: 1, ...(hardening === undefined ? {} : { hardening }) }));

type Hardened = { hardening?: Record<string, unknown> };

test("[switches] a policy without a hardening object parses, and every switch is on by default", () => {
    const policy = parseReadConfinementPolicy({ version: 1 }) as Hardened;
    for (const key of SWITCHES) assert.notEqual(policy.hardening?.[key], false, `${key} defaults to true`);
    assert.equal(policy.hardening?.hostname, undefined, "no hostname is configured by default");
});

test("[switches] every switch accepts true and false and keeps its value; hostname keeps its string", () => {
    for (const key of SWITCHES) {
        assert.equal((parse({ [key]: false }) as Hardened).hardening?.[key], false, `${key}=false is kept`);
        assert.notEqual((parse({ [key]: true }) as Hardened).hardening?.[key], false, `${key}=true is kept`);
    }
    const all = parse({ ipc: false, uts: false, userns: false, keyring: false, fds: false, hostname: "pbs-test-host" }) as Hardened;
    for (const key of SWITCHES) assert.equal(all.hardening?.[key], false);
    assert.equal(all.hardening?.hostname, "pbs-test-host");
    assert.doesNotThrow(() => parse({}), "an empty object is the all-defaults form");
});

test("[switches] unknown hardening keys are refused at load, not ignored", () => {
    for (const bad of [{ bogus: true }, { ipcc: false }, { IPC: false }, { ipc: true, extra: 1 }, { resources: {} }]) {
        assert.throws(() => parse(bad), /hardening/, JSON.stringify(bad));
    }
    assert.throws(() => parseReadConfinementPolicy({ version: 1, hardnening: {} }), /hardnening|unknown/i, "a misspelled object name is refused too");
});

test("[switches] values of the wrong type are refused", () => {
    for (const key of SWITCHES) {
        for (const bad of ["false", 0, 1, null, {}, []]) assert.throws(() => parse({ [key]: bad }), /hardening/, `${key}=${JSON.stringify(bad)}`);
    }
    for (const bad of [5, true, null, [], {}, ""]) assert.throws(() => parse({ hostname: bad }), /hardening/, `hostname=${JSON.stringify(bad)}`);
    for (const bad of [null, true, "on", []]) assert.throws(() => parseReadConfinementPolicy({ version: 1, hardening: bad }), /hardening|object/i, `hardening=${JSON.stringify(bad)}`);
});

test("[switches] policyHash changes when any switch changes, and when the hostname changes", () => {
    const hashes = new Map<string, string>([["default", hash()]]);
    for (const key of SWITCHES) hashes.set(`${key}=false`, hash({ [key]: false }));
    hashes.set("hostname=a", hash({ hostname: "pbs-test-a" }));
    hashes.set("hostname=b", hash({ hostname: "pbs-test-b" }));
    const distinct = new Set(hashes.values());
    assert.equal(distinct.size, hashes.size, `every variant hashes differently: ${JSON.stringify([...hashes])}`);
    assert.equal(hash({ ipc: false }), hash({ ipc: false }), "the hash is stable");
    assert.equal(hash({ ipc: false, uts: false }), hash({ uts: false, ipc: false }), "and independent of key order");
});

const dirs: string[] = [];
after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
const scratch = (): string => {
    const dir = realpathSync(mkdtempSync(join(base!, "pbs-hardening-policy-")));
    dirs.push(dir);
    return dir;
};

test("[switches] a policy file is loaded through the same checks: unknown keys refused, switches in the loaded hash", { skip: base ? false : "no writable non-scratch fixture base" }, () => {
    const dir = scratch();
    const write = (name: string, body: unknown): string => { const file = join(dir, name); writeFileSync(file, JSON.stringify(body)); return file; };
    assert.throws(() => loadReadConfinementPolicyFile(write("bad.json", { version: 1, hardening: { bogus: true } })), /hardening/);
    const plain = loadReadConfinementPolicyFile(write("plain.json", { version: 1 }));
    const off = loadReadConfinementPolicyFile(write("off.json", { version: 1, hardening: { keyring: false } }));
    assert.notEqual(plain.sha256, off.sha256, "the hash the controller records and the views show changes with a switch");
    assert.equal(off.sha256, hashPolicy(off.policy));
});
