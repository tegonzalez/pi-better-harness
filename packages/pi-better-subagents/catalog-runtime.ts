/**
 * Launch-time catalog wiring. Definitions are refreshed before a single launch
 * and once for a whole batch. Model and effort are resolved before
 * `spawnSubagentRun`. This module does not grant tools, sandbox modes, or
 * extensions, and it does not read task prose for model choices.
 */
import { describeDefaultLaunchCapabilities, formatModelEffort, LEGACY_CAPABILITY_CONTROLS, type LaunchEnricher, type LaunchEnrichment } from "./agent-inspection.ts";
import { resolveSelection, type EffectiveDefinition } from "./catalog-resolver.ts";
import { defaultUserRoot, loadCatalog, SOURCE_PRECEDENCE, type CatalogSnapshot } from "./catalog-store.ts";
import { loadConfig, loadLaunchConfig, type SubagentConfig } from "./config.ts";
import {
    assessCatalog,
    assessSelection,
    launchParameters,
    resolveModel,
    type CatalogResolutionAttachment,
    type EffortSelection,
    type ModelRegistryView,
    type ModelResolutionContext,
    type ModelSelection,
} from "./model-resolution.ts";
import { allocateCatalogLabel } from "./catalog-identity.ts";
import { resolveRoleAssignment, type RoleAssignment } from "./role-assignment.ts";
import { configureTierPolicy, DEFAULT_TIER_POLICY, type TierPolicy, type TierSpec } from "./tier-policy.ts";
import { canonicalAgentId, canonicalRoleId, DiagnosticCodes, shortRoleName, type Diagnostic, type ThinkingLevel } from "./catalog-schema.ts";
import { withAgentSessionSettings, type AgentSessionOverrides } from "./agent-session-settings.ts";
import { currentSandboxPermissions } from "./permission-policy.ts";

export interface CatalogHost {
    cwd: string;
    projectTrusted: boolean;
    userRoot?: string;
    projectConfigDirName?: string;
    bundledRoot?: string;
    registry?: ModelRegistryView;
    foregroundModel?: string;
    configuredDefaultModel?: string | null;
    tiers?: TierPolicy;
    hasUI?: boolean;
    select?: (title: string, options: string[]) => Promise<string | undefined>;
    /** Passed through only when the caller already has a registry root. Omitted in production. */
    registryDir?: string;
    sessionSettings?: AgentSessionOverrides;
    /** Live UI edits; read once when admitting a launch snapshot. */
    getSessionSettings?: () => AgentSessionOverrides;
}

export interface CatalogJobFields {
    prompt: string;
    name?: string;
    agent?: string;
    role?: string | readonly string[];
    alias?: string;
    roleIds?: readonly string[];
    model?: string;
    thinking?: string;
    [key: string]: unknown;
}

export interface CatalogRunRecord {
    snapshotDigest: string;
    revision: string;
    loadedAt: string;
    kind: "role" | "agent";
    id: string;
    name?: string;
    roleId?: string;
    roleName?: string;
    alias?: string;
    displayName: string;
    /** Label the registry allocator adopts. Same string as `RunMeta.name`. */
    identity: {
        label: string;
        kind: "role" | "agent";
        id: string;
        name?: string;
        roleId?: string;
        roleName?: string;
        alias?: string;
    };
    instructionMode: string;
    source?: { scope: string; path: string; contentDigest: string; id: string };
    roleSource?: { scope: string; path: string; contentDigest: string; id: string };
    effective: {
        model: { value: string | null; source: string; explicit: boolean };
        effort: { value: string | null; source: string; explicit: boolean };
        tier: { value: string | null; source: string; explicit: boolean };
    };
    modelSelection: ModelSelection;
    effortSelection: EffortSelection;
    capabilities: { grantedByCatalog: false; note: string };
}

export interface ClarificationNeeded {
    status: "clarification-needed";
    launched: false;
    wrote: false;
    message: string;
    choices: string[];
}

export type PreparedCatalogJob =
    | { status: "legacy" }
    | { status: "blocked"; message: string; diagnostics: readonly Diagnostic[] }
    | {
        status: "ready";
        assign: {
            prompt: string;
            name: string;
            model?: string;
            thinking?: ThinkingLevel;
            catalog: CatalogRunRecord;
            catalogResolved: true;
        };
    };

const notedHost: { current?: CatalogHost } = {};

export function hasCatalogSelector(input: { agent?: unknown; role?: unknown; roleIds?: unknown } | undefined): boolean {
    if (!input) return false;
    return roleIdsOf(input).length > 0 || typeof input.agent === "string" && input.agent.trim() !== "";
}

/** Configured tier overrides join the built-in membership. Empty candidate lists stay empty. */
export function tiersForLaunch(config: Pick<SubagentConfig, "tierPolicy"> | undefined): TierPolicy {
    if (!config?.tierPolicy) return DEFAULT_TIER_POLICY;
    const overrides: Record<string, TierSpec> = {};
    for (const [name, spec] of Object.entries(config.tierPolicy)) {
        overrides[name] = {
            members: [...(spec?.members ?? [])],
            candidates: [...(spec?.candidates ?? [])],
        };
    }
    return configureTierPolicy(overrides);
}

export function noteCatalogHost(next: CatalogHost): void {
    const previous = notedHost.current;
    notedHost.current = {
        ...previous,
        ...next,
        userRoot: next.userRoot ?? previous?.userRoot,
        // A key that is present wins, even when the value is missing. Falling
        // through to the previous session kept a foreground, registry, or tier
        // policy the current context had already cleared.
        registry: "registry" in next ? next.registry : previous?.registry,
        foregroundModel: "foregroundModel" in next ? next.foregroundModel : previous?.foregroundModel,
        configuredDefaultModel: "configuredDefaultModel" in next ? next.configuredDefaultModel : previous?.configuredDefaultModel,
        tiers: "tiers" in next ? next.tiers : previous?.tiers,
        sessionSettings: next.sessionSettings,
        getSessionSettings: next.getSessionSettings,
    };
}

export function loadLaunchSnapshot(host: CatalogHost): CatalogSnapshot {
    return withAgentSessionSettings(loadCatalog({
        cwd: host.cwd,
        projectTrusted: host.projectTrusted,
        userRoot: host.userRoot ?? defaultUserRoot(),
        bundledRoot: host.bundledRoot,
        projectConfigDirName: host.projectConfigDirName,
    }), host.getSessionSettings?.() ?? host.sessionSettings);
}

export function createLaunchEnricher(pi?: unknown): LaunchEnricher {
    let cache: { key: string; rows: Map<string, CatalogResolutionAttachment> } | undefined;
    return ({ inspection, snapshotDigest }) => {
        const host = notedHost.current;
        if (!host?.cwd || !host.registry || typeof host.registry.getAvailable !== "function") return undefined;
        const config = loadConfig();
        const availability = readAvailability(host.registry);
        const context = resolutionContext(host, config);
        // Digest alone is not launchability. Availability and the config that
        // selects the default model or tier are part of the key so a later
        // registry or config change cannot reuse the previous decision.
        const key = JSON.stringify({
            snapshotDigest,
            foregroundModel: context.foregroundModel ?? null,
            configuredDefaultModel: context.configuredDefaultModel ?? null,
            tiers: context.tiers ?? null,
            configDefaultModel: config.defaultModel ?? null,
            configTierPolicy: config.tierPolicy ?? null,
            availability: availability.key,
        });
        if (!cache || cache.key !== key) {
            const snapshot = loadLaunchSnapshot({ ...host, userRoot: host.userRoot ?? defaultUserRoot() });
            if (snapshot.digest !== snapshotDigest) return undefined;
            const registry = availability.models === undefined
                ? host.registry
                : {
                    getAvailable: () => availability.models ?? [],
                    ...(host.registry.find ? { find: host.registry.find.bind(host.registry) } : {}),
                };
            cache = {
                key,
                rows: new Map(assessCatalog(snapshot, { ...context, registry }).map((row) => [row.id, row])),
            };
        }
        const attachment = cache.rows.get(inspection.id);
        if (!attachment) return undefined;
        if (!attachment.decision && attachment.schemaLaunchable && attachment.availability !== "catalog-blocked") return undefined;
        const enrichment = enrichmentFrom(attachment);
        return {
            ...enrichment,
            capabilities: {
                ...enrichment.capabilities,
                effective: describeDefaultLaunchCapabilities({
                    config,
                    model: enrichment.actualModel,
                    cwd: host.cwd,
                    sandboxPermissions: currentSandboxPermissions(pi)?.subagentPermissions,
                }),
            },
        };
    };
}

export async function clarifyCatalogRequest(
    jobs: readonly CatalogJobFields[],
    ui: { hasUI: boolean; select?: CatalogHost["select"] },
): Promise<{ status: "resolved"; jobs: CatalogJobFields[] } | ClarificationNeeded> {
    const normalized = jobs.map((job, index) => ({
        job: { ...job, catalogJobIndex: index },
        index,
        continuation: job.session_id !== undefined || job.session_name !== undefined,
        agent: job.session_id !== undefined || job.session_name !== undefined ? undefined : agentIdOf(job),
        roles: job.session_id !== undefined || job.session_name !== undefined ? [] : roleIdsOf(job),
    }));
    const clean: CatalogJobFields[] = [];
    const pending: { job: CatalogJobFields; index: number; agent?: string; roles: string[] }[] = [];
    for (const item of normalized) {
        // Saved conversations keep their launch recipe. Repeated selectors are
        // checked against that recipe at admission, never clarified or expanded.
        if (item.continuation) { clean.push(item.job); continue; }
        if (item.roles.length > 1 || (item.agent && item.roles.length > 0)) pending.push(item);
        else clean.push(withSelector(item.job, { agent: item.agent, role: item.roles[0] }));
    }
    if (pending.length === 0) return { status: "resolved", jobs: clean };

    const pureRoles = pending.filter((item) => !item.agent);
    const mixed = pending.filter((item) => item.agent);
    let resolvedPure: CatalogJobFields[] = [];
    if (pureRoles.length > 0) {
        const decision = await resolveRoleAssignment(pureRoles.flatMap((item) => item.roles.map((roleId) => ({
            jobId: String(item.index),
            roleId,
        } satisfies RoleAssignment))), { hasUI: ui.hasUI === true, select: ui.select });
        if (decision.status === "clarification-needed") return clarification(decision.message, decision.choices);
        for (const chosen of decision.jobs) {
            const index = Number(chosen.jobId.split("#")[0]);
            const source = pureRoles.find((item) => item.index === index)?.job;
            if (!source) return clarification(`Could not map role ${chosen.roleId} back to its run. Nothing was launched.`, decision.choices);
            resolvedPure.push(withSelector(source, { role: chosen.roleId }));
        }
    }
    let resolvedMixed: CatalogJobFields[] = [];
    if (mixed.length > 0) {
        const choice = await clarifyMixed(mixed, ui);
        if (choice.status === "clarification-needed") return choice;
        resolvedMixed = choice.jobs;
    }
    const ordered = [...clean, ...resolvedPure, ...resolvedMixed];
    ordered.sort((left, right) => sortKey(left) - sortKey(right));
    return { status: "resolved", jobs: ordered.map(stripBookkeeping) };
}

/**
 * Launch-line note for a catalog run whose effective model or effort differs
 * from the role or agent default. The wording names the cause, so a fallback
 * or a capped effort is not mistaken for a caller override:
 * - override: `model openai/gpt-6-astra@high (role developer default openai/gpt-6.1-sol@high)`
 * - fallback: `model openai/gpt-6.1-sol-backup@high (role developer default openai/gpt-6.1-sol@high unavailable; same-tier fallback)`
 * - capped effort: `model openai/gpt-6.1-sol@medium (role developer default openai/gpt-6.1-sol@high; effort capped at medium by the model)`
 * Undefined for a non-catalog run, a definition with no default, or a launch
 * that matches the default. Only the fields the definition sets are compared.
 */
export function catalogDefaultNote(
    record: Pick<CatalogRunRecord, "kind" | "effective" | "modelSelection" | "effortSelection"> & { id?: string } | undefined,
    model: string | undefined,
    thinking: string | undefined,
): string | undefined {
    if (!record) return undefined;
    const defaultModel = record.effective.model.value;
    const defaultEffort = record.effective.effort.value;
    const defaultLabel = formatModelEffort(defaultModel, defaultEffort);
    if (!defaultLabel) return undefined;
    const modelSource = record.modelSelection?.source;
    const modelFallback = defaultModel !== null && modelSource !== undefined && FALLBACK_SOURCES.has(modelSource);
    const modelDiffers = defaultModel !== null && (modelFallback || !sameModel(defaultModel, model, modelSource));
    const effortCapped = defaultEffort !== null && record.effortSelection?.adjusted === true && (thinking ?? null) !== defaultEffort;
    const effortDiffers = defaultEffort !== null && (thinking ?? null) !== defaultEffort;
    if (!modelDiffers && !effortDiffers) return undefined;
    const actual = formatModelEffort(model ?? "Pi default", thinking) ?? "Pi default";
    // A role run names its short role (`role developer default …`); an agent run keeps `agent default …`.
    const owner = record.kind === "role" && record.id ? `role ${shortRoleName(record.id)}` : record.kind;
    const causes = [
        modelFallback ? `${owner} default ${defaultLabel} unavailable; ${FALLBACK_LABELS[modelSource!] ?? modelSource} fallback` : `${owner} default ${defaultLabel}`,
        ...(effortCapped ? [`effort capped at ${thinking ?? "the model default"} by the model`] : []),
    ];
    return `model ${actual} (${causes.join("; ")})`;
}

/** Load diagnostics for a catalog file whose definition id could not be read. */
const UNATTRIBUTED_LOAD_FAILURES: ReadonlySet<string> = new Set([
    DiagnosticCodes.ioError,
    DiagnosticCodes.parserLimit,
    DiagnosticCodes.malformedFrontmatter,
    DiagnosticCodes.duplicateKey,
    DiagnosticCodes.invalidSchema,
    DiagnosticCodes.invalidKind,
    DiagnosticCodes.invalidId,
]);

/**
 * Files that failed to load or parse before their id was known. Any of them
 * could hold a definition that shadows the selection, so a catalog launch must
 * not silently continue with a lower-priority source. Failures in a scope below
 * every selected definition's scope cannot shadow them and are ignored. Pass
 * each definition the launch depends on (an agent and the role it inherits);
 * the lowest-ranked one decides, since a broken file above it could replace it.
 */
export function catalogLoadFailures(
    snapshot: Pick<CatalogSnapshot, "diagnostics">,
    selectedScope?: string | readonly (string | undefined)[],
): Diagnostic[] {
    const rank = (scope: string | undefined) => {
        const index = SOURCE_PRECEDENCE.indexOf(scope as (typeof SOURCE_PRECEDENCE)[number]);
        return index < 0 ? -1 : index;
    };
    const scopes = (Array.isArray(selectedScope) ? selectedScope : [selectedScope])
        .filter((scope): scope is string => scope !== undefined);
    const selected = scopes.length === 0 ? Number.POSITIVE_INFINITY : Math.max(...scopes.map(rank));
    // A file whose id was still read is attributed (for example invalid-shadow) and blocks only that id.
    const attributed = new Set(snapshot.diagnostics.filter((item) => item.id && item.path).map((item) => item.path));
    return snapshot.diagnostics.filter((item) => !item.id && item.path && !attributed.has(item.path)
        && UNATTRIBUTED_LOAD_FAILURES.has(item.code) && rank(item.scope) <= selected);
}

/** Model sources that mean the default could not be used, not that the caller chose another model. */
const FALLBACK_SOURCES: ReadonlySet<string> = new Set(["tier-candidate", "foreground", "configured-default"]);
const FALLBACK_LABELS: Record<string, string> = {
    "tier-candidate": "same-tier",
    foreground: "foreground",
    "configured-default": "configured-default",
};

function sameModel(defaultModel: string, actual: string | undefined, source: string | undefined): boolean {
    // The resolver launched the definition's own preference: same model, however it was spelled.
    if (source === "role-default" || source === "agent-override") return true;
    if (actual === undefined) return false;
    if (defaultModel === actual) return true;
    // A providerless default names the id; the resolved provider/id (the id may itself contain "/") still matches.
    return !defaultModel.includes("/") ? actual.endsWith(`/${defaultModel}`) : false;
}

export async function prepareCatalogJob(snapshot: CatalogSnapshot, job: CatalogJobFields, host: CatalogHost): Promise<PreparedCatalogJob> {
    const agent = agentIdOf(job);
    const roles = roleIdsOf(job);
    if (!agent && roles.length === 0) return { status: "legacy" };
    if (agent && roles.length > 0 || roles.length > 1) {
        return {
            status: "blocked",
            message: "This run still names more than one role or both an agent and a role. Choose one or split it before launch. No child was started.",
            diagnostics: [],
        };
    }
    const selector = agent ? { agentId: agent } : { roleId: roles[0]! };
    const resolved = resolveSelection(snapshot, selector);
    // An agent whose role did not resolve could get it from a broken file in any source, including
    // one ranked below the agent, so every load failure is named.
    const effective = resolved.effective;
    const missingRole = effective?.kind === "agent" && effective.roleId && !effective.roleSource ? effective.roleId : undefined;
    const loadFailures = catalogLoadFailures(snapshot, missingRole ? [] : [effective?.source?.scope, effective?.roleSource?.scope]);
    const couldChange = missingRole ? `could define ${missingRole}, which ${agent} needs,` : `could replace ${agent ?? roles[0]},`;
    const loadMessage = loadFailures.length === 0 ? "" : `The agent catalog failed to load: ${loadFailures.map((item) => item.path && !item.message.includes(item.path) ? `${item.path}: ${item.message.trim()}` : item.message.trim()).join(" ")} A definition in that file ${couldChange} so the launch was refused instead of using another definition. Repair or remove the file, then retry. No child was started.`;
    if (!resolved.effective || resolved.status === "clarification-needed" || resolved.status === "not-found" || !resolved.launchable) {
        const message = [resolved.diagnostics.map((item) => item.message).join(" ") || "Catalog selection is not launchable. No child was started.", loadMessage].filter(Boolean).join(" ");
        return { status: "blocked", message, diagnostics: [...resolved.diagnostics, ...loadFailures] };
    }
    if (loadFailures.length > 0) return { status: "blocked", message: loadMessage, diagnostics: loadFailures };
    const config = loadLaunchConfig();
    const decision = resolveModel({
        ...resolutionContext(host, config),
        effective: resolved.effective,
        invocation: {
            ...(typeof job.model === "string" ? { model: job.model } : {}),
            ...(typeof job.thinking === "string" ? { thinking: job.thinking } : {}),
        },
    });
    if (decision.status !== "ready" || decision.launch === null) {
        const message = decision.diagnostics.map((item) => item.message).join(" ") || decision.modelSelection.reason || "Model resolution blocked launch. No child was started.";
        return { status: "blocked", message, diagnostics: decision.diagnostics };
    }
    const launch = launchParameters(decision);
    const displayName = await displayNameFor(resolved.effective, job, host);
    const roleId = resolved.effective.kind === "role" ? resolved.effective.id : resolved.effective.roleId;
    const roleName = roleId ? roleSlug(roleId) : undefined;
    const alias = text(job.alias);
    const record = jsonValue({
        snapshotDigest: snapshot.digest,
        revision: snapshot.revision,
        loadedAt: snapshot.loadedAt,
        kind: resolved.effective.kind,
        id: resolved.effective.id,
        ...(resolved.effective.name ? { name: resolved.effective.name } : {}),
        ...(roleId ? { roleId } : {}),
        ...(roleName ? { roleName } : {}),
        ...(alias ? { alias } : {}),
        displayName,
        identity: {
            label: displayName,
            kind: resolved.effective.kind,
            id: resolved.effective.id,
            ...(resolved.effective.name ? { name: resolved.effective.name } : {}),
            ...(roleId ? { roleId } : {}),
            ...(roleName ? { roleName } : {}),
            ...(alias ? { alias } : {}),
        },
        instructionMode: resolved.effective.instructionMode,
        ...(origin(resolved.effective.source) ? { source: origin(resolved.effective.source) } : {}),
        ...(origin(resolved.effective.roleSource) ? { roleSource: origin(resolved.effective.roleSource) } : {}),
        effective: {
            model: field(resolved.effective.model),
            effort: field(resolved.effective.effort),
            tier: field(resolved.effective.tier),
        },
        modelSelection: decision.modelSelection,
        effortSelection: decision.effortSelection,
        capabilities: {
            grantedByCatalog: false as const,
            note: resolved.effective.capabilities.note,
        },
    });
    return {
        status: "ready",
        assign: {
            prompt: composePrompt(resolved.effective.instructions, job.prompt),
            name: displayName,
            ...(launch.model ? { model: launch.model } : { model: undefined }),
            ...(launch.thinking ? { thinking: launch.thinking } : { thinking: undefined }),
            catalog: record,
            catalogResolved: true,
        },
    };
}

function plainThinkingMap(map: unknown): Record<string, string | null> | null {
    if (!map || typeof map !== "object") return null;
    const out: Record<string, string | null> = {};
    for (const key of Object.keys(map).sort()) {
        const value = (map as Record<string, unknown>)[key];
        out[key] = typeof value === "string" || value === null ? value : null;
    }
    return out;
}

function readAvailability(registry: ModelRegistryView): { key: string; models?: ReturnType<ModelRegistryView["getAvailable"]> } {
    try {
        const models = registry.getAvailable();
        if (!Array.isArray(models)) return { key: "not-a-list" };
        const rows = models.map((model) => ({
            provider: model?.provider ?? null,
            id: model?.id ?? null,
            reasoning: model?.reasoning ?? null,
            thinkingLevelMap: plainThinkingMap(model?.thinkingLevelMap),
        }));
        rows.sort((left, right) => `${left.provider}/${left.id}`.localeCompare(`${right.provider}/${right.id}`));
        return { key: JSON.stringify(rows), models };
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return { key: `unreadable:${detail}` };
    }
}

function resolutionContext(host: CatalogHost, config: SubagentConfig): ModelResolutionContext {
    return {
        registry: host.registry,
        tiers: host.tiers ?? tiersForLaunch(config),
        foregroundModel: host.foregroundModel,
        configuredDefaultModel: host.configuredDefaultModel !== undefined ? host.configuredDefaultModel : config.defaultModel,
        ...(host.userRoot ? { userRoot: host.userRoot } : {}),
    };
}

function enrichmentFrom(attachment: CatalogResolutionAttachment): LaunchEnrichment {
    const decision = attachment.decision;
    const knownLaunch = attachment.schemaLaunchable === false || attachment.availability === "catalog-blocked" || Boolean(decision);
    return {
        availability: decision?.status === "ready" ? "available" : "unavailable",
        requestedModel: decision?.modelSelection.requested ?? null,
        actualModel: decision?.status === "ready" ? decision.modelSelection.actual : null,
        requestedEffort: decision?.effortSelection.requested ?? null,
        actualEffort: decision?.status === "ready" ? decision.effortSelection.actual : null,
        modelReason: decision?.modelSelection.reason ?? attachment.diagnostics.find((item) => item.blocking)?.message,
        effortReason: decision?.effortSelection.reason,
        launchable: knownLaunch ? attachment.launchable : false,
        capabilities: {
            grantedByCatalog: false,
            note: attachment.capabilities.note,
            enforcedExistingControls: LEGACY_CAPABILITY_CONTROLS,
        },
    };
}

async function clarifyMixed(
    mixed: readonly { job: CatalogJobFields; index: number; agent?: string; roles: string[] }[],
    ui: { hasUI: boolean; select?: CatalogHost["select"] },
): Promise<{ status: "resolved"; jobs: CatalogJobFields[] } | ClarificationNeeded> {
    const perJob = mixed.map((item) => ({ item, choices: mixedChoices(item) }));
    const described = perJob.map(({ item }) => `run ${item.index + 1} names ${[item.agent, ...item.roles].filter(Boolean).join(" and ")}`).join("; ");
    const message = `${described}. A run has one base role, not multiple parents. Choose one role or split the work into separate runs. Nothing was launched or written.`;
    if (!ui.hasUI || !ui.select) {
        const choices = perJob.flatMap(({ item, choices: jobChoices }) => mixed.length === 1
            ? jobChoices
            : jobChoices.map((choice) => `run ${item.index + 1}: ${choice}`));
        return clarification(`${message} UI is unavailable, so the choice was not made. Re-run in the TUI or RPC UI and choose one role or split. No launch and no write.`, choices);
    }
    const resolved: CatalogJobFields[] = [];
    for (const { item, choices } of perJob) {
        const selected = await ui.select(
            mixed.length === 1 ? "This request assigns more than one role" : `Run ${item.index + 1} assigns more than one role`,
            choices,
        );
        if (!selected) return clarification("The role choice was dismissed. Nothing was launched or written.", choices);
        const applied = applyMixedChoice(item, selected, choices);
        if (applied.status !== "resolved") return applied;
        resolved.push(...applied.jobs);
    }
    return { status: "resolved", jobs: resolved };
}

function mixedChoices(item: { agent?: string; roles: readonly string[] }): string[] {
    return [
        ...(item.agent ? [`Choose agent ${item.agent}`] : []),
        ...item.roles.map((roleId) => `Choose ${roleId}`),
        `Split into ${item.roles.length + (item.agent ? 1 : 0)} runs`,
    ];
}

function applyMixedChoice(
    item: { job: CatalogJobFields; agent?: string; roles: readonly string[] },
    selected: string,
    choices: readonly string[],
): { status: "resolved"; jobs: CatalogJobFields[] } | ClarificationNeeded {
    if (selected.startsWith("Split into ")) {
        const expected = `Split into ${item.roles.length + (item.agent ? 1 : 0)} runs`;
        if (selected !== expected) {
            return clarification(`Unknown choice ${JSON.stringify(selected)}. Nothing was launched or written.`, choices);
        }
        const pieces = [
            ...(item.agent ? [{ agent: item.agent }] : []),
            ...item.roles.map((roleId) => ({ role: roleId })),
        ];
        return {
            status: "resolved",
            jobs: pieces.map((piece, pieceIndex) => withSelector(item.job, { ...piece, splitIndex: pieceIndex })),
        };
    }
    if (selected.startsWith("Choose agent ")) {
        const agent = selected.slice("Choose agent ".length);
        if (!item.agent || agent !== item.agent) {
            return clarification(`Unknown choice ${JSON.stringify(selected)}. Nothing was launched or written.`, choices);
        }
        return { status: "resolved", jobs: [withSelector(item.job, { agent })] };
    }
    if (selected.startsWith("Choose ")) {
        const roleId = selected.slice("Choose ".length);
        if (!item.roles.includes(roleId)) {
            return clarification(`Unknown choice ${JSON.stringify(selected)}. Nothing was launched or written.`, choices);
        }
        return { status: "resolved", jobs: [withSelector(item.job, { role: roleId })] };
    }
    return clarification(`Unknown choice ${JSON.stringify(selected)}. Nothing was launched or written.`, choices);
}

async function displayNameFor(effective: EffectiveDefinition, job: CatalogJobFields, host: CatalogHost): Promise<string> {
    if (effective.kind === "agent") {
        const defined = effective.name?.trim();
        if (!defined) {
            throw new Error(`Named agent ${effective.id} has no defined name. No child was started.`);
        }
        return defined;
    }
    const alias = text(job.alias) ?? text(job.name);
    return allocateDirectRoleLabel({
        roleId: effective.id,
        roleName: roleSlug(effective.id),
        ...(alias ? { alias } : {}),
        ...(host.registryDir ? { registryDir: host.registryDir } : {}),
    });
}

async function allocateDirectRoleLabel(input: { roleId: string; roleName: string; alias?: string; registryDir?: string }): Promise<string> {
    // Static import. A dynamic import raced Pi's parallel tool execution and
    // could observe an uninitialized registry binding (`baseDir`).
    const label = allocateCatalogLabel({
        roleId: input.roleId,
        roleName: input.roleName,
        ...(input.alias ? { alias: input.alias } : {}),
        ...(input.registryDir ? { registryDir: input.registryDir } : {}),
    });
    if (typeof label !== "string" || label.trim() === "") {
        throw new Error("allocateCatalogLabel returned no display label. No child was started.");
    }
    return label;
}

export function roleSlug(roleId: string): string {
    return shortRoleName(roleId).trim().toLowerCase();
}

function composePrompt(instructions: string, task: string): string {
    const body = instructions.trim();
    if (!body) return task;
    return `${body}\n\n---\n\n${task}`;
}

function agentIdOf(job: { agent?: unknown }): string | undefined {
    return typeof job.agent === "string" && job.agent.trim() !== "" ? canonicalAgentId(job.agent) : undefined;
}

/**
 * Drop optional string fields whose value is empty or whitespace-only, so they
 * read as omitted. Some models emit every schema field and fill unused string
 * fields with ""; rejecting those as "present but blank" made such models
 * unable to launch any child (session 01a18443: 1482 identical rejections).
 * `keep` names required fields (such as `prompt`) that are validated separately.
 * Arrays are left untouched: a role array with a blank entry still fails.
 */
export function omitBlankOptionalStrings<T extends object>(input: T, keep?: readonly string[]): T;
export function omitBlankOptionalStrings<T extends object>(input: T | undefined, keep?: readonly string[]): T | undefined;
export function omitBlankOptionalStrings<T extends object>(input: T | undefined, keep: readonly string[] = []): T | undefined {
    if (!input || typeof input !== "object" || Array.isArray(input)) return input;
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
        if (!keep.includes(key) && typeof value === "string" && value.trim() === "") continue;
        out[key] = value;
    }
    return out as T;
}

/**
 * Error text for a selector that is present but blank. Callers first apply
 * omitBlankOptionalStrings, so in practice this catches an empty role array or
 * a role array with a blank entry (`role: ["developer", " "]`). Absent or null means no
 * selector and returns undefined. `where` names the field's owner, such as
 * `shared` or `jobs[1]`.
 */
export function blankCatalogSelector(input: { agent?: unknown; role?: unknown } | undefined, where?: string): string | undefined {
    if (!input) return undefined;
    const field = (name: string) => (where ? `${where}.${name}` : name);
    const blank = (value: unknown) => typeof value !== "string" || value.trim() === "";
    if (input.agent !== undefined && input.agent !== null && blank(input.agent)) {
        return `${field("agent")} is blank. Pass a named agent id such as agent.payments, or omit agent. No child was started.`;
    }
    const role = input.role;
    if (role === undefined || role === null) return undefined;
    if (Array.isArray(role) ? role.length === 0 || role.some(blank) : blank(role)) {
        return `${field("role")} is blank. Pass a role name such as developer, or omit role. No child was started.`;
    }
    return undefined;
}

function roleIdsOf(job: { role?: unknown; roleIds?: unknown }): string[] {
    const values: unknown[] = [];
    if (Array.isArray(job.roleIds)) values.push(...job.roleIds);
    if (Array.isArray(job.role)) values.push(...job.role);
    else if (typeof job.role === "string") values.push(job.role);
    const ids: string[] = [];
    for (const value of values) {
        if (typeof value !== "string") continue;
        // A bare name (`developer`) and the prefixed id (`role.developer`) are
        // the same role. The canonical id always starts with `role.`, so a
        // role field never reaches an `agent.*` named agent.
        const id = canonicalRoleId(value);
        if (id && !ids.includes(id)) ids.push(id);
    }
    return ids;
}

function withSelector(job: CatalogJobFields, selector: { agent?: string; role?: string; splitIndex?: number }): CatalogJobFields {
    const next: CatalogJobFields = { ...job, catalogJobIndex: originalIndex(job) };
    delete next.agent;
    delete next.role;
    delete next.roleIds;
    if (selector.agent) next.agent = selector.agent;
    if (selector.role) next.role = selector.role;
    if (selector.splitIndex !== undefined) next.catalogSplitIndex = selector.splitIndex;
    if (selector.splitIndex !== undefined && typeof next.alias === "string") {
        next.alias = `${next.alias}-${selector.splitIndex + 1}`;
    }
    return next;
}

function originalIndex(job: CatalogJobFields): number {
    return typeof job.catalogJobIndex === "number" ? job.catalogJobIndex : 0;
}

function sortKey(job: CatalogJobFields): number {
    const split = typeof job.catalogSplitIndex === "number" ? job.catalogSplitIndex : 0;
    return originalIndex(job) * 100 + split;
}

function stripBookkeeping(job: CatalogJobFields): CatalogJobFields {
    const next = { ...job };
    delete next.catalogSplitIndex;
    delete next.catalogJobIndex;
    return next;
}

function clarification(message: string, choices: readonly string[]): ClarificationNeeded {
    return { status: "clarification-needed", launched: false, wrote: false, message, choices: [...choices] };
}

function text(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function field(value: { value: string | null; source: string; explicit: boolean }): { value: string | null; source: string; explicit: boolean } {
    return { value: value.value, source: value.source, explicit: value.explicit };
}

function origin(value: EffectiveDefinition["source"]): CatalogRunRecord["source"] {
    if (!value) return undefined;
    return { scope: value.scope, path: value.path, contentDigest: value.contentDigest, id: value.id };
}

function jsonValue<T>(value: T): T {
    return JSON.parse(JSON.stringify(value)) as T;
}
