/**
 * Launcher harness for the descriptor tests. It runs as its OWN process, started by the test with extra
 * descriptors that are open WITHOUT close-on-exec (they are inherited stdio slots of this process), which is
 * exactly "a descriptor opened without close-on-exec in the launching process". It then launches one probe
 * command through the named launcher's own code path and prints a JSON result line.
 *
 * Launchers (one per spawn site of a confined bubblewrap command that has a test seam):
 *  - foreground:  pi-better-sandbox/shell.ts            (`createSandboxedBashOperations`)
 *  - task-bash:   task-sandbox/index.ts                 (`createTaskBashOperations`, vendored copy)
 *  - background:  pi-better-background-tasks/src        (`confineCommandSpec` + `spawnCommand`, process.ts)
 *  - subagent:    pi-better-subagents                   (`sandbox.ts` buildSandboxCommand + `spawn.ts` spawnDetached)
 *
 * Usage: node --import tsx fd-launch-harness.ts <config.json>
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { createTaskBashOperations } from "../../shared-task-sandbox.ts";
import { confinedExec, controllerFor, type Fixture, type RawPolicy } from "./hardening-support.ts";

type Config = { kind: "foreground" | "task-bash" | "background" | "subagent"; fixture: Fixture; policy: RawPolicy; command: string };
const config = JSON.parse(readFileSync(process.argv[2]!, "utf8")) as Config;
const { fixture: fx } = config;
const packages = resolve(dirname(new URL(import.meta.url).pathname), "../../..");
const load = (relative: string) => import(pathToFileURL(join(packages, relative)).href);

const controller = controllerFor(fx, config.policy);
const permissions = { projectFiles: "read-write", outsideProject: "off", storedCredentials: "off", commands: true, network: false };

async function run(): Promise<{ exitCode: number | null; output: string }> {
    if (config.kind === "foreground") return confinedExec(controller, fx, config.command);
    if (config.kind === "task-bash") {
        const operations = createTaskBashOperations(controller);
        let output = "";
        const { exitCode } = await operations.exec(config.command, fx.project, { onData: (chunk: Buffer) => { output += chunk.toString(); }, env: { HOME: fx.home } });
        return { exitCode, output };
    }
    if (config.kind === "background") {
        const { confineCommandSpec } = await load("pi-better-background-tasks/src/sandbox.ts");
        const { spawnCommand } = await load("pi-better-background-tasks/src/process.ts");
        const spec = { shell: false, argv: ["/bin/sh", "-c", config.command], cwd: fx.project, env: {} };
        const confined = confineCommandSpec(spec, { confined: true, writableRoot: fx.project, denyWrite: [], permissions }, join(fx.profiles, "bg.sb"));
        const logPath = join(fx.outside, "bg.log");
        const { child } = spawnCommand(confined, logPath, true);
        const exitCode = await new Promise<number | null>((done) => { child.on("close", (code: number | null) => done(code)); });
        return { exitCode, output: readFileSync(logPath, "utf8") };
    }
    const { buildSandboxCommand } = await load("pi-better-subagents/sandbox.ts");
    const { spawnDetached } = await load("pi-better-subagents/spawn.ts");
    const built = buildSandboxCommand({ profilePath: join(fx.profiles, "sub.sb"), writableDir: fx.project, home: fx.home, piBin: "/bin/sh", piArgs: ["-c", config.command], permissions });
    const logPath = join(fx.outside, "sub.log");
    const { exit } = spawnDetached({ file: built.file, fileArgs: built.fileArgs, cwd: fx.project, logPath, env: {} });
    return { exitCode: await exit, output: readFileSync(logPath, "utf8") };
}

// spawnDetached unrefs the child; keep this process alive until the launch settles.
const keepAlive = setInterval(() => undefined, 1000);
try {
    const result = await run();
    console.log(JSON.stringify(result));
} catch (error) {
    console.log(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
} finally {
    clearInterval(keepAlive);
    controller.dispose();
}
