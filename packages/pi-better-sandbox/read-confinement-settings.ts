/**
 * Where the read-confinement policy comes from. The location is configuration,
 * never code: the `PI_SANDBOX_READ_CONFINEMENT_POLICY` environment variable
 * wins, otherwise the harness setting `sandboxReadConfinement.policyFile`.
 * Without either, `outsideProject: "off"` keeps its original behavior.
 */
import { harnessSettingsPath, readHarnessSetting, type HarnessSettingsSeams } from "./shared-harness-settings.ts";
import { isAbsolute } from "node:path";
import { loadReadConfinementPolicyFile, type LoadedReadConfinementPolicy } from "./shared-read-confinement.ts";

export const READ_CONFINEMENT_POLICY_ENV = "PI_SANDBOX_READ_CONFINEMENT_POLICY";
export const READ_CONFINEMENT_SETTING_KEY = "sandboxReadConfinement";

export type ReadConfinementSettingSeams = HarnessSettingsSeams & { env?: NodeJS.ProcessEnv };

/** Absolute path of the configured policy file, or undefined when the mode is not configured. */
export function configuredReadConfinementPolicyFile(seams: ReadConfinementSettingSeams = {}): string | undefined {
    const fromEnv = (seams.env ?? process.env)[READ_CONFINEMENT_POLICY_ENV];
    const stored = fromEnv ? undefined : readHarnessSetting<unknown>(READ_CONFINEMENT_SETTING_KEY, seams);
    const file = fromEnv ?? (stored && typeof stored === "object" ? (stored as { policyFile?: unknown }).policyFile : undefined);
    if (file === undefined) return undefined;
    if (typeof file !== "string" || !isAbsolute(file)) {
        throw new Error(`${fromEnv ? READ_CONFINEMENT_POLICY_ENV : `${READ_CONFINEMENT_SETTING_KEY}.policyFile in ${harnessSettingsPath(seams)}`} must be an absolute path.`);
    }
    return file;
}

/** Load and validate the configured policy; throws a clear error on any problem. */
export function loadConfiguredReadConfinementPolicy(seams: ReadConfinementSettingSeams = {}): LoadedReadConfinementPolicy | undefined {
    const file = configuredReadConfinementPolicyFile(seams);
    return file === undefined ? undefined : loadReadConfinementPolicyFile(file);
}
export const READ_CONFINEMENT_ENTRY = "pi-better-sandbox-read-confinement";
