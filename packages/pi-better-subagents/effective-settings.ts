import { createHash } from "node:crypto";
import { DELEGATION_MODES, delegationPrompt, type DelegationMode } from "./delegation.ts";

export const SUBAGENT_SETTINGS_CONTEXT = "pi-better-subagents-settings";

export interface EffectiveSubagentSettings {
    revision: string;
    delegationMode: DelegationMode;
    maxConcurrent: number;
    sources: { delegationMode: "session" | "config"; maxConcurrent: "session" | "config" };
    runningCount: number;
    pendingCount: number;
    occupiedSlots: number;
    availableSlots: number;
}

/** The settings that define a revision: mode, limit, and their sources. Never occupancy. */
export type StableSubagentSettings = Pick<EffectiveSubagentSettings, "revision" | "delegationMode" | "maxConcurrent" | "sources">;

export function stableSubagentSettings(
    settings: Pick<EffectiveSubagentSettings, "delegationMode" | "maxConcurrent" | "sources">,
): StableSubagentSettings {
    const revision = createHash("sha256").update(JSON.stringify([
        settings.delegationMode, settings.maxConcurrent, settings.sources.delegationMode, settings.sources.maxConcurrent,
    ])).digest("hex").slice(0, 12);
    return { revision, delegationMode: settings.delegationMode, maxConcurrent: settings.maxConcurrent,
        sources: { delegationMode: settings.sources.delegationMode, maxConcurrent: settings.sources.maxConcurrent } };
}

export function effectiveSubagentSettings(
    settings: Pick<EffectiveSubagentSettings, "delegationMode" | "maxConcurrent" | "sources">,
    runningCount: number,
    pendingCount: number,
): EffectiveSubagentSettings {
    const { revision } = stableSubagentSettings(settings);
    const occupiedSlots = runningCount + pendingCount;
    return { ...settings, revision, runningCount, pendingCount, occupiedSlots,
        availableSlots: Math.max(0, settings.maxConcurrent - occupiedSlots) };
}

/**
 * Deterministic delegation guidance for the system prompt. It covers every mode and carries
 * no counts or timestamps, so it stays byte-identical across requests and setting changes;
 * the latest settings message names the active mode.
 */
export function subagentDelegationSystemPrompt(): string {
    return [
        "Subagent delegation: the latest Subagent settings message in the conversation is authoritative for the active delegation mode and concurrency limit. " +
            "Its mode replaces earlier mode-specific guidance, including guidance in a plan. Follow only the guidance for the active mode:",
        ...DELEGATION_MODES.map((mode) => `- ${delegationPrompt(mode)}`),
        "The concurrency limit is a ceiling, not a target number of agents. Launch ready, independent, useful work within available capacity. " +
            "Lowering the limit does not stop existing runs. Settings messages carry no live counts: call subagent_settings for current running, reserved, and available slots. " +
            "Spawn admission rechecks capacity.",
    ].join("\n");
}

/** Compact settings message, added to the conversation once per settings revision. */
export function formatSubagentSettingsMessage(settings: StableSubagentSettings): string {
    return `Subagent settings revision ${settings.revision}: delegation mode ${settings.delegationMode} (${settings.sources.delegationMode}); ` +
        `concurrency limit ${settings.maxConcurrent} (${settings.sources.maxConcurrent}). ` +
        `Apply the ${settings.delegationMode} delegation guidance from the system prompt. Call subagent_settings for live capacity.`;
}

export function formatSubagentSettings(settings: EffectiveSubagentSettings): string {
    return [
        `Subagent settings: revision ${settings.revision}`,
        `Delegation: ${settings.delegationMode} (${settings.sources.delegationMode})`,
        `Concurrency limit: ${settings.maxConcurrent} (${settings.sources.maxConcurrent})`,
        `Running: ${settings.runningCount}; reserved: ${settings.pendingCount}`,
        `Occupied slots: ${settings.occupiedSlots}`,
        `Available slots: ${settings.availableSlots}`,
        "The limit is a ceiling, not a target. Launch ready, independent, useful work within available capacity. " +
            "This is a point-in-time snapshot; spawn admission rechecks capacity. Lowering the limit does not stop existing runs.",
        delegationPrompt(settings.delegationMode),
    ].join("\n");
}

export function subagentSettingsTool(Type: any, read: () => EffectiveSubagentSettings) {
    return {
        name: "subagent_settings",
        label: "Subagent Settings",
        description: "Inspect effective subagent delegation mode, concurrency limit, setting sources, revision, and running/reserved/available slots. Read-only; does not change settings or launch work. The limit is a ceiling, not a target. Call it for live capacity: settings messages in the conversation carry no running or available counts.",
        parameters: Type.Object({}),
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
        outputSchema: Type.Object({
            revision: Type.String(), delegationMode: Type.String(), maxConcurrent: Type.Number({ minimum: 1, multipleOf: 1 }),
            sources: Type.Object({ delegationMode: Type.String(), maxConcurrent: Type.String() }),
            runningCount: Type.Number({ minimum: 0, multipleOf: 1 }), pendingCount: Type.Number({ minimum: 0, multipleOf: 1 }),
            occupiedSlots: Type.Number({ minimum: 0, multipleOf: 1 }), availableSlots: Type.Number({ minimum: 0, multipleOf: 1 }),
        }),
        async execute() {
            const settings = read();
            return { content: [{ type: "text" as const, text: formatSubagentSettings(settings) }],
                details: settings, structuredContent: settings };
        },
    };
}