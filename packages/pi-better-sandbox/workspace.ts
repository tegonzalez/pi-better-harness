/**
 * Workspace binding for owner verification.
 *
 * A workspace is (working folder, agent dir, filesystem policy). These pure
 * helpers describe it and render the `/sandbox` workspace and `/sandbox check`
 * output. The decisions themselves come from the controller, which asks the same
 * evaluators the in-process tools and the kernel mount plan use.
 */

export type WorkspaceInfo = {
    /** Canonical working folder the session captured (also the writable project root). */
    cwd: string | undefined;
    /** The agent dir in force (PI_CODING_AGENT_DIR or pi's default). */
    agentDir: string;
    /** `active` only while the frozen plan is in force for the Main profile. */
    confinement: "active" | "not-in-force" | "failed" | "unconfigured";
    policyPath?: string;
    policyHash?: string;
    planHash?: string;
    /** Why the confinement is not active, when it is not. */
    note?: string;
};

export type AccessVerdict = { allowed: boolean; reason: string };

export type PathCheck = {
    /** The path as given. */
    input: string;
    /** Canonical (realpath'd) path the decision was taken on. */
    path: string;
    read: AccessVerdict;
    write: AccessVerdict;
    exec: AccessVerdict;
    /** Set when the sandbox is not enforcing, so the verdicts describe nothing. */
    note?: string;
};

export function formatWorkspace(info: WorkspaceInfo): string {
    const lines = [
        "Workspace:",
        `  cwd:        ${info.cwd ?? "(not captured yet)"}`,
        `  agent dir:  ${info.agentDir}`,
        `  policy:     ${info.policyPath ?? "(none configured)"}`,
        `  policyHash: ${info.policyHash ?? "-"}`,
        `  planHash:   ${info.planHash ?? "-"}`,
        `  confinement: ${info.confinement}${info.note ? ` — ${info.note}` : ""}`,
    ];
    return lines.join("\n");
}

const verdict = (v: AccessVerdict): string => `${v.allowed ? "ALLOWED" : "DENIED "} ${v.reason}`;

export function formatPathCheck(check: PathCheck): string {
    return [
        `Path: ${check.input}${check.path === check.input ? "" : ` -> ${check.path}`}`,
        `  read:  ${verdict(check.read)}`,
        `  write: ${verdict(check.write)}`,
        `  exec:  ${verdict(check.exec)}`,
        ...(check.note ? [`  note:  ${check.note}`] : []),
    ].join("\n");
}
