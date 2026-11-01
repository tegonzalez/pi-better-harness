---
doc-graph: "When there is an intention to amend this document, first Adhere to [dc-doc-known-issues]; otherwise, do not modify."
---

# Known issues

## Purpose

This register records eight finite residuals in the accepted current behavior of confined launches, their resource limits and the tests that verify them. Each entry names the document that owns the behavior and an objective condition that retires the entry.

## Orientation

- Audience: maintainers who plan changes to confined launches, resource limits, remote-subagent session limits and their tests.
- Scope: the Linux bubblewrap confined launch of the pi-better-sandbox package, its `resources` and `hardening` policy keys, the remote-subagent session scope, and the test suites that verify them.
- Non-goals: the register defines no behavior, sequences no repair and authorizes no Change. A candidate change named in an entry's detail is an unadmitted observation.

## Terminology

| Term              | Meaning                                                                                                                                                                 |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| confined launch   | A bubblewrap launch that pi-better-sandbox builds while read confinement is active: Linux, a configured read-confinement policy and a profile with Outside project off. |
| command scope     | The transient systemd user scope (`systemd-run --user --scope`) that starts around one confined launch when the sandbox policy sets `resources.command`.                |
| session scope     | The one transient systemd user scope in which a remote subagent's pi and its children run when the remote target sets `resources.session`.                              |
| sibling scope     | A scope that systemd places beside, not inside, the scope that started the nested `systemd-run --user --scope`.                                                         |
| user manager      | The user's systemd instance that owns user scopes and applies their limits through its delegated cgroup controllers.                                                    |
| stop              | The remote-subagent operation (`subagent_stop`) that signals every process of the remote run's session, TERM and then KILL.                                             |
| real-systemd case | A test case that starts an actual user scope and reads the limits through the kernel's cgroup files.                                                                    |

## Register

| id    | datetime             | kind              | restatement                                                                                                                                                                                                                                        | owner                                                                                                                                      | seed     | disposition                                                              | retirement                                                                                                                                                       |
| ----- | -------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| KI-01 | 2026-11-01T05:31:56Z | deferred-surface  | A stop that signals a remote run's session leaves a running confined launch's sandbox init and command alive, because confined launches use `--unshare-pid --new-session` and not `--die-with-parent`.                                             | [remote-subagents.md, Session limits](../packages/pi-better-subagents/docs/remote-subagents.md#session-limits)                             | unseeded | Open; documented as a known limit; no change selected.                   | A stop of a run ends every confined launch started inside it, shown by a test, and the owner's known-limit paragraph is removed.                                 |
| KI-02 | 2026-11-01T05:31:56Z | accepted-tradeoff | When the remote pi's sandbox policy sets `resources.command`, each confined launch runs in a sibling user scope of the session scope, so its command limits bound it and the session limits do not.                                                | [pi-better-sandbox README, Resource limits](../packages/pi-better-sandbox/README.md#resource-limits)                                       | unseeded | Accepted; documented in the README and in the remote-subagents document. | A confined launch started inside a session scope is bounded by the session limits, shown by a real-scope test, and both owners drop the sibling-scope statement. |
| KI-03 | 2026-11-01T05:31:56Z | verification-gap  | The real-systemd cases of the command and session limits skip when no user manager or delegated controller is available, and `PI_SANDBOX_REQUIRE_BACKEND` covers only sandbox backends, so a run that sets it can pass without exercising a limit. | [development-and-release.md, Sandbox confinement lanes](development-and-release.md#sandbox-confinement-lanes)                              | unseeded | Open; no change selected.                                                | A run that requires limit proof fails instead of skipping when the user manager or a controller is missing, and the owner states how a run requires it.          |
| KI-04 | 2026-11-01T05:31:56Z | accepted-tradeoff | The session scope carries only the configured properties and sets no stop timeout, so after `runtimeMaxSec` a remote pi that ignores TERM lives until the user manager's default stop timeout.                                                     | [remote-subagents.md, Session limits](../packages/pi-better-subagents/docs/remote-subagents.md#session-limits)                             | unseeded | Accepted; documented in the remote-subagents document.                   | A session scope ends a TERM-ignoring pi within a stated bound after `runtimeMaxSec`, shown by a real-scope test, and the owner states that bound.                |
| KI-05 | 2026-11-01T05:31:56Z | verification-gap  | Task file operations (`task-sandbox/files.ts`) have no seam for a probe that observes an inherited descriptor, so `hardening.fds` is not shown for that spawn site.                                                                                | [pi-better-sandbox README, Hardening of every confined launch](../packages/pi-better-sandbox/README.md#hardening-of-every-confined-launch) | unseeded | Open; no change selected.                                                | A test shows a descriptor left open by the spawner is unusable in the file-operation worker, or the worker no longer spawns through a confined launch.           |
| KI-06 | 2026-11-01T05:31:56Z | verification-gap  | The fail-closed refusal on a CPU architecture the keyring filter does not cover is tested only where the measure's state is computed, not through a launch, the audit entry or the views.                                                          | [pi-better-sandbox README, Hardening of every confined launch](../packages/pi-better-sandbox/README.md#hardening-of-every-confined-launch) | unseeded | Open; no change selected.                                                | A test through the controller refuses the launch on an unsupported architecture and shows the inactive audit entry with its reason.                              |
| KI-07 | 2026-11-01T05:31:56Z | verification-gap  | The fail-closed refusal for a missing delegated cgroup controller is not exercised against a host that lacks one; only the no-user-manager cause is tested, and only the check script's text is unit-tested.                                       | [pi-better-sandbox README, Resource limits](../packages/pi-better-sandbox/README.md#resource-limits)                                       | unseeded | Open; no change selected.                                                | A test refuses a command-limit launch and a session-limit launch when a needed controller is absent, with a reason that names the controller.                    |
| KI-08 | 2026-11-01T05:31:56Z | verification-gap  | On a Node runtime that closes every descriptor not named in `stdio` itself, the per-launcher descriptor cases for foreground, task, background and subagent launches have no working control, so they do not prove `hardening.fds` per launcher.   | [pi-better-sandbox README, Hardening of every confined launch](../packages/pi-better-sandbox/README.md#hardening-of-every-confined-launch) | unseeded | Open; no change selected.                                                | Each launcher type has a case that fails when `hardening.fds` is switched off, or the owner narrows its per-launcher descriptor claim.                           |

### KI-01 Running confined launch survives stop

- Fact: confined launches are built with `--clearenv --unshare-pid --new-session` and no confined launch passes `--die-with-parent` (`buildLinuxPermissionCommand` in `packages/sandbox-core/index.ts`). The stop signals the members of the run's session.
- Fact: the owner records a local reproduction with a stand-in pi. The stop ended pi and the outer bubblewrap, while the inner bubblewrap and its command kept running in their own scope: the command scope when `resources.command` was set, the session scope otherwise. They end when the command finishes or when a `runtimeMaxSec` ends the scope they are in.
- Assumption: a stop that signals a process group reaches the same processes, because `--new-session` also starts a new process group. No test or owner text exercises that path.
- Question: whether a real remote pi ends its running confined launches when it receives TERM is untested.
- Candidate change (unadmitted, untried): pass `--die-with-parent` on confined launches. Builder tests for the non-confined launch assert that flag absent so that detached children stay durable (`packages/sandbox-core/index.test.ts`, `packages/pi-better-subagents/tests/sandbox_profile.test.mjs`), so absorbing it must resolve that.
- Affected documents: the Stop and Session limits sections of the remote-subagents document and the Resource limits section of the pi-better-sandbox README.

### KI-02 Confined launches in sibling scopes

- Fact: a nested `systemd-run --user --scope` does not stay in the scope that started it, so a launch with its own command scope is bounded by `resources.command` and not by the session scope's memory, task or CPU limits, and the session `runtimeMaxSec` does not end it. Without `resources.command` in that policy the launch runs in the session scope.
- Fact: the session limits then no longer cap the total of the run. The remote pi and the children that are not scoped launches still share them.
- Evidence: no suite starts a confined launch inside a session scope; the real-scope session cases use a pi stand-in and no bubblewrap (`packages/pi-better-subagents/tests/remote_session_limits_run.test.mjs`).
- Candidate change (unadmitted): a session slice that contains the command scopes.
- Affected documents: the Resource limits section of the pi-better-sandbox README and the Session limits section of the remote-subagents document.

### KI-03 Limit cases skip without systemd

- Fact: the real-systemd cases skip when no user manager or delegated controller is available (`systemdSkip` in `packages/pi-better-sandbox/test/support/limits-support.ts`, the real systemd user scope suite in `packages/sandbox-core/resources.impl.test.ts`, the session limit run cases in `packages/pi-better-subagents/tests/remote_session_limits_run.test.mjs`).
- Fact: `PI_SANDBOX_REQUIRE_BACKEND` names the sandbox backend a run must prove and turns a missing backend into a failure. A user manager is not a sandbox backend, so a run that sets the variable passes with every real-systemd case skipped.
- Candidate change (unadmitted): extend the variable's convention to the user manager, or add a separate required-systemd switch.
- Affected documents: the Sandbox confinement lanes section of the development-and-release document.

### KI-04 Session scope has no stop timeout

- Fact: the session scope is built with `stopGrace: false` so that it carries exactly the configured properties (`resourceScopeArguments` in `packages/sandbox-core/index.ts`, its use in `packages/pi-better-subagents/remote.ts`). A command scope with `runtimeMaxSec` adds `TimeoutStopSec=5`.
- Fact: after `runtimeMaxSec` systemd stops the session scope with TERM and then KILL after the user manager's stop timeout, so a TERM-ignoring pi lives until that default.
- Candidate change (unadmitted, untried): a stop timeout property on the session scope.
- Affected documents: the Session limits section of the remote-subagents document.

### KI-05 File operations have no descriptor probe

- Fact: task file operations run a fixed worker program with JSON on stdin. No seam lets a test put a probe inside it, and `/proc` is absent inside, so an inherited-descriptor leak cannot be observed from outside; nothing is claimed for that spawn site (`packages/pi-better-sandbox/test/hardening-fds.test.ts`).
- Affected documents: the Hardening of every confined launch section of the pi-better-sandbox README (the `fds` measure).

### KI-06 Unsupported-architecture refusal is tested at state level only

- Fact: a launch with the keyring measure on and an uncovered CPU architecture is refused by `hardenLaunch` in `packages/sandbox-core/index.ts`. The only case is the state computation with an architecture seam (`packages/sandbox-core/hardening.impl.test.ts`); the launch-level refusal and the visibility cases simulate a bubblewrap that lacks a flag.
- Affected documents: the Hardening of every confined launch and Fail-closed behaviour sections of the pi-better-sandbox README.

### KI-07 Missing-controller refusal is untested on a host that lacks one

- Fact: the launch checks inside the scope that the control file of each configured limit exists (`resourceScopeCheckScript` in `packages/sandbox-core/index.ts`). Unit tests match the script's text; the real-systemd cases require a user manager that delegates cpu, memory and pids; the session stand-in simulates a missing user manager only (`packages/pi-better-subagents/tests/remote_session_limits.test.mjs`).
- Affected documents: the Resource limits section of the pi-better-sandbox README and the When the limits cannot be applied section of the remote-subagents document.

### KI-08 Per-launcher descriptor cases lack a control

- Fact: the suite records that the runtime closes every descriptor not named in `stdio`, so a launcher that spawns bubblewrap directly cannot leak an inherited descriptor with or without the measure. The per-launcher cases only guard against a launcher passing descriptors on purpose; the evidence that can fail is the builder-level case and the leaky-outer-shell case (`packages/pi-better-sandbox/test/hardening-fds.test.ts`). The runtime that shows this behavior is Node 26.
- Affected documents: the Hardening of every confined launch section of the pi-better-sandbox README (the `fds` measure).

## Boundaries

- Each entry's behavior statements belong to the document its owner cell links; this register restates a residual and never redefines current behavior.
- Candidate changes in an entry's detail select no work, order no repair and declare no readiness.
- Desired future evolution belongs to the roadmap, and implementation holes outside this register's admission belong to gap documents.
