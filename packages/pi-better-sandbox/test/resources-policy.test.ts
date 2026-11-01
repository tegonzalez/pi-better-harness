/**
 * Command limits and private /tmp size (parser half): the read-confinement policy's optional `resources`
 * object, with optional `resources.command` (keys `memoryMax`, `memorySwapMax`, `tasksMax`, `cpuQuota`,
 * `runtimeMaxSec`) and optional `resources.tmpSize`. Every key is optional; any other key, form or value is
 * refused at load (fail closed); every value is part of `policyHash`.
 *
 * Forms (frozen): sizes are a decimal integer with an optional suffix K, M, G or T (powers of 1024); `tasksMax`,
 * `cpuQuota` (percent of one CPU) and `runtimeMaxSec` (seconds) are positive integers. Error wording is the
 * product's; these tests only require that the refusal mentions `resources` (or says unknown).
 * @level unit
 */
import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test, { after } from "node:test";

import { hashPolicy, loadReadConfinementPolicyFile, parseReadConfinementPolicy } from "../shared-read-confinement.ts";
import { base } from "./support/hardening-support.ts";

const REFUSED = /resources|unknown|memoryMax|memorySwapMax|tasksMax|cpuQuota|runtimeMaxSec|tmpSize/i;
const parse = (resources: unknown) => parseReadConfinementPolicy({ version: 1, resources });
const command = (c: unknown) => parse({ command: c });
const hash = (resources?: unknown) => hashPolicy(parseReadConfinementPolicy({ version: 1, ...(resources === undefined ? {} : { resources }) }));

const SIZE_KEYS = ["memoryMax", "memorySwapMax"] as const;
const INT_KEYS = ["tasksMax", "cpuQuota", "runtimeMaxSec"] as const;

test("[resources] a policy without resources parses (unset limits are the default)", () => {
    assert.doesNotThrow(() => parseReadConfinementPolicy({ version: 1 }));
    const policy = parseReadConfinementPolicy({ version: 1 }) as { resources?: { command?: unknown; tmpSize?: unknown } };
    assert.equal(policy.resources?.command, undefined, "no command limit is configured by default");
    assert.equal(policy.resources?.tmpSize, undefined, "no tmp size is configured by default");
});

test("[resources] the empty forms are accepted: resources {}, resources.command {}", () => {
    assert.doesNotThrow(() => parse({}));
    assert.doesNotThrow(() => command({}));
});

test("[resources] each key accepts a valid form; all keys together are accepted", () => {
    for (const value of ["1024", "1K", "64M", "2G", "1T", "512K", "10"]) {
        for (const key of SIZE_KEYS) assert.doesNotThrow(() => command({ [key]: value }), `${key}=${value}`);
        assert.doesNotThrow(() => parse({ tmpSize: value }), `tmpSize=${value}`);
    }
    assert.doesNotThrow(() => command({ memorySwapMax: "0" }), "memorySwapMax=0 (no swap) is a decimal integer");
    for (const value of [1, 16, 200, 100000]) {
        for (const key of INT_KEYS) assert.doesNotThrow(() => command({ [key]: value }), `${key}=${value}`);
    }
    assert.doesNotThrow(() => parse({
        command: { memoryMax: "64M", memorySwapMax: "0", tasksMax: 32, cpuQuota: 200, runtimeMaxSec: 30 }, tmpSize: "1M",
    }));
});

test("[resources] unknown keys are refused at load: at resources, in command, misplaced or misspelled", () => {
    const bad: unknown[] = [
        { bogus: 1 }, { command: { bogus: 1 } }, { command: { memoryMax: "64M", extra: true } }, { command: { MemoryMax: "64M" } },
        { command: { memory: "64M" } }, { command: { cpuQuotaPercent: 100 } }, { command: { runtimeMax: 5 } }, { command: { tasks: 5 } },
        { memoryMax: "64M" }, { tasksMax: 5 }, { command: { tmpSize: "1M" } }, { tmpsize: "1M" },
        { session: { memoryMax: "1G" } }, { command: { session: {} } }, { commandd: {} },
    ];
    for (const resources of bad) assert.throws(() => parse(resources), REFUSED, JSON.stringify(resources));
    assert.throws(() => parseReadConfinementPolicy({ version: 1, resource: {} }), /resource|unknown/i, "a misspelled object name is refused too");
});

test("[resources] malformed sizes are refused: fractions, unit words, signs, percent, spaces, empty, other suffixes", () => {
    const bad = ["1.5G", "64MB", "64MiB", "64Mi", "-1M", "-1", "50%", "6 4M", "64 M", " 64M", "64M ", "", "M", "K", "64P", "64E", "0x10", "1e3", "abc", "infinity", "64M64", "1,5G", "６４M"];
    for (const value of bad) {
        for (const key of SIZE_KEYS) assert.throws(() => command({ [key]: value }), REFUSED, `${key}=${JSON.stringify(value)}`);
        assert.throws(() => parse({ tmpSize: value }), REFUSED, `tmpSize=${JSON.stringify(value)}`);
    }
});

test("[resources] sizes of the wrong type are refused", () => {
    for (const value of [64, 0, 1.5, true, false, null, {}, [], ["64M"]]) {
        for (const key of SIZE_KEYS) assert.throws(() => command({ [key]: value }), REFUSED, `${key}=${JSON.stringify(value)}`);
        assert.throws(() => parse({ tmpSize: value }), REFUSED, `tmpSize=${JSON.stringify(value)}`);
    }
});

test("[resources] integer keys refuse zero, negatives, fractions, non-numbers and other types", () => {
    const bad: unknown[] = [0, -1, -200, 1.5, 0.5, 99.9, Number.NaN, Number.POSITIVE_INFINITY, "16", "1.5", "", "abc", "50%", null, true, false, {}, [], [16]];
    for (const value of bad) {
        for (const key of INT_KEYS) assert.throws(() => command({ [key]: value }), REFUSED, `${key}=${String(value)}`);
    }
});

test("[resources] wrong types for the objects themselves are refused", () => {
    for (const bad of [null, true, 5, "64M", [], [{}]]) assert.throws(() => parse(bad), REFUSED, `resources=${JSON.stringify(bad)}`);
    for (const bad of [null, true, 5, "64M", [], [{}]]) assert.throws(() => command(bad), REFUSED, `resources.command=${JSON.stringify(bad)}`);
});

test("[resources] policyHash changes with each value, with each key, and with tmpSize; it is stable and key-order independent", () => {
    const variants: [string, unknown][] = [
        ["none", undefined],
        ["memoryMax=64M", { command: { memoryMax: "64M" } }], ["memoryMax=128M", { command: { memoryMax: "128M" } }], ["memoryMax=1G", { command: { memoryMax: "1G" } }],
        ["memorySwapMax=0", { command: { memorySwapMax: "0" } }], ["memorySwapMax=64M", { command: { memorySwapMax: "64M" } }],
        ["tasksMax=16", { command: { tasksMax: 16 } }], ["tasksMax=32", { command: { tasksMax: 32 } }],
        ["cpuQuota=100", { command: { cpuQuota: 100 } }], ["cpuQuota=200", { command: { cpuQuota: 200 } }],
        ["runtimeMaxSec=30", { command: { runtimeMaxSec: 30 } }], ["runtimeMaxSec=60", { command: { runtimeMaxSec: 60 } }],
        ["tmpSize=1M", { tmpSize: "1M" }], ["tmpSize=2M", { tmpSize: "2M" }],
        ["all", { command: { memoryMax: "64M", memorySwapMax: "0", tasksMax: 32, cpuQuota: 200, runtimeMaxSec: 30 }, tmpSize: "1M" }],
    ];
    const hashes = new Map(variants.map(([name, resources]) => [name, hash(resources)]));
    assert.equal(new Set(hashes.values()).size, hashes.size, `every variant hashes differently: ${JSON.stringify([...hashes])}`);
    assert.equal(hash({ command: { tasksMax: 16 } }), hash({ command: { tasksMax: 16 } }), "the hash is stable");
    assert.equal(
        hash({ tmpSize: "1M", command: { runtimeMaxSec: 30, memoryMax: "64M" } }), hash({ command: { memoryMax: "64M", runtimeMaxSec: 30 }, tmpSize: "1M" }),
        "independent of key order",
    );
});

test("[resources] different sizes, units and keys never collide in the hash", () => {
    assert.notEqual(hash({ command: { memoryMax: "1K" } }), hash({ command: { memoryMax: "2K" } }));
    assert.notEqual(hash({ tmpSize: "1G" }), hash({ tmpSize: "1T" }));
    assert.notEqual(hash({ command: { memoryMax: "64M" } }), hash({ command: { memorySwapMax: "64M" } }), "the same value under another key is another policy");
});

const dirs: string[] = [];
after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });

test("[resources] a policy file is loaded through the same checks: bad forms refused, limits in the loaded hash", { skip: base ? false : "no writable non-scratch fixture base" }, () => {
    const dir = realpathSync(mkdtempSync(join(base!, "pbs-resources-policy-")));
    dirs.push(dir);
    const write = (name: string, body: unknown): string => { const file = join(dir, name); writeFileSync(file, JSON.stringify(body)); return file; };
    assert.throws(() => loadReadConfinementPolicyFile(write("bad-key.json", { version: 1, resources: { command: { bogus: 1 } } })), REFUSED);
    assert.throws(() => loadReadConfinementPolicyFile(write("bad-form.json", { version: 1, resources: { command: { memoryMax: "1.5G" } } })), REFUSED);
    assert.throws(() => loadReadConfinementPolicyFile(write("bad-tmp.json", { version: 1, resources: { tmpSize: "50%" } })), REFUSED);
    assert.throws(() => loadReadConfinementPolicyFile(write("bad-int.json", { version: 1, resources: { command: { tasksMax: 0 } } })), REFUSED);
    const plain = loadReadConfinementPolicyFile(write("plain.json", { version: 1 }));
    const limited = loadReadConfinementPolicyFile(write("limited.json", { version: 1, resources: { command: { tasksMax: 16 } } }));
    const sized = loadReadConfinementPolicyFile(write("sized.json", { version: 1, resources: { tmpSize: "1M" } }));
    assert.notEqual(plain.sha256, limited.sha256, "the hash the controller records and the views show changes with a command limit");
    assert.notEqual(plain.sha256, sized.sha256, "and with tmpSize");
    assert.notEqual(limited.sha256, sized.sha256);
    assert.equal(limited.sha256, hashPolicy(limited.policy));
});
