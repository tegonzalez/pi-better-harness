/**
 * Explicit fixture bases, so no test depends on where the checkout lives.
 * `nonTempBase()` is a writable directory outside every scratch location (the
 * sandbox's private /tmp is writable by design, and a policy file may not live
 * in one); override it with PI_SANDBOX_TEST_NON_TEMP_BASE.
 */
import { accessSync, constants, realpathSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { sep } from "node:path";

const SCRATCH = ["/tmp", "/var/tmp", "/dev/shm", tmpdir()].map((path) => { try { return realpathSync(path); } catch { return path; } });

export function insideScratch(path: string): boolean {
    const real = (() => { try { return realpathSync(path); } catch { return path; } })();
    return SCRATCH.some((root) => real === root || real.startsWith(root + sep));
}

/** The first candidate that is writable and not scratch, or undefined (callers skip with a reason). */
export function nonTempBase(...candidates: string[]): string | undefined {
    const list = [process.env.PI_SANDBOX_TEST_NON_TEMP_BASE, ...candidates, homedir()].filter((entry): entry is string => !!entry);
    return list.find((dir) => {
        try { accessSync(dir, constants.W_OK); } catch { return false; }
        return !insideScratch(dir);
    });
}
