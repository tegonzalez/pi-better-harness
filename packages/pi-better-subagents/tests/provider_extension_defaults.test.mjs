/**
 * Security/spend regression: a child launched on an `ollama-cloud` model must
 * NOT automatically load `pi-ollama-cloud`. That package registers web tools
 * that post to ollama.com and overrides the role's `--tools`, so loading it is
 * an explicit user choice made with a `providerExtensions` entry.
 *
 * An explicit entry still works (string, list, replacement), an empty list is
 * a no-op, and a mapped-but-missing package keeps surfacing the explicit
 * missing error instead of launching without provider auth.
 *
 * // @covers extensions.provider-auth
 * // @level integration
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as extensionsModule from "../extensions.mjs";
import { extensionArgs, resolveExtensions } from "../extensions.mjs";
import { loadConfig, resolveExtensionPath, setConfigPathForTests } from "../config.ts";

const OLLAMA = "npm:pi-ollama-cloud";
const MODEL = "ollama-cloud/deepseek-v4.1-flash";
const BUNDLED_CONFIG = join(dirname(fileURLToPath(import.meta.url)), "..", "config.json");

/** Real config loading and path materialization, isolated to a temp agent dir. */
function openEnvironment(t, { settings, installed = true } = {}) {
    const root = mkdtempSync(join(tmpdir(), "builtin-provider-"));
    const agentDir = join(root, "agent");
    const settingsPath = join(agentDir, "settings.json");
    mkdirSync(agentDir, { recursive: true });
    if (settings) {
        writeFileSync(settingsPath, JSON.stringify({ piBetterHarness: { subagents: settings } }));
    }
    if (installed) {
        mkdirSync(join(agentDir, "npm", "node_modules", "pi-ollama-cloud"), { recursive: true });
    }
    const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = agentDir;
    setConfigPathForTests(settingsPath, BUNDLED_CONFIG);
    t.after(() => {
        setConfigPathForTests(undefined);
        if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
        else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
        rmSync(root, { recursive: true, force: true });
    });
    return { agentDir };
}

function resolveFromShippedConfig(tools = "read,bash") {
    return resolveExtensions({ tools, model: MODEL, config: loadConfig() });
}

describe("provider extensions are explicit only", () => {
    it("does not load the ollama-cloud provider package on the model name alone", (t) => {
        openEnvironment(t);
        const resolution = resolveFromShippedConfig();
        assert.deepEqual(resolution.specs, []);
        assert.deepEqual(resolution.reasons, {});
        const child = extensionArgs(resolution, resolveExtensionPath);
        assert.deepEqual(child.missing, []);
        assert.deepEqual(child.args, ["--no-extensions"]);
    });

    it("ships no built-in provider map and no provider default in the shipped config", () => {
        assert.equal("BUILTIN_PROVIDER_EXTENSIONS" in extensionsModule, false);
        const shipped = loadConfig();
        assert.deepEqual(shipped.providerExtensions ?? {}, {});
        for (const model of [MODEL, "ollama-cloud/x", "xai/grok-4.5"]) {
            assert.deepEqual(resolveExtensions({ tools: "read", model, config: shipped }).specs, []);
        }
        assert.deepEqual(resolveExtensions({ tools: "read", model: MODEL, config: {} }).specs, []);
    });

    it("loads the provider package when the user maps it explicitly", (t) => {
        const { agentDir } = openEnvironment(t, { settings: { providerExtensions: { "ollama-cloud": OLLAMA } } });
        const resolution = resolveFromShippedConfig();
        assert.deepEqual(resolution.specs, [OLLAMA]);
        assert.deepEqual(resolution.reasons[OLLAMA], ["provider:ollama-cloud"]);
        const child = extensionArgs(resolution, resolveExtensionPath);
        assert.deepEqual(child.missing, []);
        assert.deepEqual(child.args, [
            "--no-extensions",
            "--extension",
            join(agentDir, "npm", "node_modules", "pi-ollama-cloud"),
        ]);
    });

    it("keeps an explicitly mapped but missing provider package an explicit missing error", (t) => {
        openEnvironment(t, { installed: false, settings: { providerExtensions: { "ollama-cloud": OLLAMA } } });
        const child = extensionArgs(resolveFromShippedConfig(), resolveExtensionPath);
        assert.deepEqual(child.missing, [OLLAMA]);
        assert.deepEqual(child.args, ["--no-extensions"]);
    });

    it("loads exactly the package the user maps, and an empty entry loads nothing", (t) => {
        openEnvironment(t, {
            settings: { providerExtensions: { "ollama-cloud": "npm:pi-ollama-alternative" } },
        });
        assert.deepEqual(resolveFromShippedConfig().specs, ["npm:pi-ollama-alternative"]);
        const empty = resolveExtensions({ tools: "read", model: MODEL, config: { providerExtensions: { "ollama-cloud": [] } } });
        assert.deepEqual(empty.specs, []);
    });
});
