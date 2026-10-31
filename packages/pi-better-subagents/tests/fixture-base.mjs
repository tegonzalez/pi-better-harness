/**
 * Test support: an explicit fixture base that is writable and outside every temp root (temp is always
 * removable, so a fixture home there proves nothing about the home rules). Override with
 * PI_SANDBOX_TEST_NON_TEMP_BASE; the checkout's own directory and the user's home are the other candidates,
 * so the suite passes wherever the checkout lives.
 */
import { accessSync, constants, realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";

export function nonTempFixtureBase(checkoutDir) {
    const scratch = ["/tmp", "/var/tmp", "/dev/shm", tmpdir()].map((path) => { try { return realpathSync(path); } catch { return path; } });
    for (const dir of [process.env.PI_SANDBOX_TEST_NON_TEMP_BASE, checkoutDir, homedir()]) {
        if (!dir) continue;
        let real;
        try { real = realpathSync(dir); accessSync(real, constants.W_OK); } catch { continue; }
        if (!scratch.some((root) => real === root || real.startsWith(root + "/"))) return real;
    }
    throw new Error("no writable fixture base outside the temp directories; set PI_SANDBOX_TEST_NON_TEMP_BASE");
}
