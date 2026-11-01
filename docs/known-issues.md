---
doc-graph: "When there is an intention to amend this document, first Adhere to [dc-doc-known-issues]; otherwise, do not modify."
---

# Known issues

## Purpose

This register records eight finite residuals in the accepted current behavior of confined launches, their resource limits and the tests that verify them. Each entry names the document that owns the behavior and an objective condition that retires the entry.

## Orientation

- Audience: maintainers who plan changes to confined launches, resource limits, remote-subagent session limits and their tests.
- Scope: the Linux bubblewrap confined launch of the pi-better-sandbox package, its `resources` and `hardening` policy keys, the remote-subagent session scope, and the test suites that verify them.
- Non-goals: the register defines no behavior, sequences no repair and authorizes no Change.

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

| id    | datetime             | kind             | restatement                                                                                                                                           | owner                                                                                                                                      | seed     | disposition                                             | retirement                                                                                                                            |
| ----- | -------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| KI-01 | 2026-11-01T05:31:56Z | verification-gap | The owner documents that a stop leaves a running confined launch alive, shown only by a stand-in-pi reproduction.                                     | [remote-subagents.md, Session limits](../packages/pi-better-subagents/docs/remote-subagents.md#session-limits)                             | unseeded | Open; documented in remote-subagents.md.                | A test with a real remote pi shows what a stop does to a running confined launch, and the owner states it.                            |
| KI-02 | 2026-11-01T05:31:56Z | verification-gap | The owners document that a launch with its own command scope runs beside the session scope, and no case runs one inside a session scope.              | [pi-better-sandbox README, Resource limits](../packages/pi-better-sandbox/README.md#resource-limits)                                       | unseeded | Open; documented in the README and remote-subagents.md. | A real-scope case runs a confined launch with `resources.command` in a session scope and shows what bounds it.                        |
| KI-03 | 2026-11-01T05:31:56Z | verification-gap | Real-systemd limit cases skip without a user manager or controller, and `PI_SANDBOX_REQUIRE_BACKEND` does not turn that skip into a failure.          | [development-and-release.md, Sandbox confinement lanes](development-and-release.md#sandbox-confinement-lanes)                              | unseeded | Open; documented in the limit test headers.             | A run that requires limit proof fails on a missing user manager or controller, and the owner states how.                              |
| KI-04 | 2026-11-01T05:31:56Z | verification-gap | The session scope sets no stop timeout, and no real-scope case uses a pi that ignores TERM after `runtimeMaxSec`.                                     | [remote-subagents.md, Session limits](../packages/pi-better-subagents/docs/remote-subagents.md#session-limits)                             | unseeded | Open; documented in remote-subagents.md.                | A real-scope case shows when a TERM-ignoring pi ends after `runtimeMaxSec`, and the owner states it.                                  |
| KI-05 | 2026-11-01T05:31:56Z | verification-gap | No seam lets a probe observe an inherited descriptor in task file operations, so `hardening.fds` is not shown there.                                  | [pi-better-sandbox README, Hardening of every confined launch](../packages/pi-better-sandbox/README.md#hardening-of-every-confined-launch) | unseeded | Open; documented in the hardening-fds test header.      | A test shows a left-open descriptor is unusable in the file-operation worker, or the worker stops spawning through a confined launch. |
| KI-06 | 2026-11-01T05:31:56Z | verification-gap | The refusal on a CPU architecture the keyring filter does not cover is tested at state level, not through a launch, audit entry or view.              | [pi-better-sandbox README, Hardening of every confined launch](../packages/pi-better-sandbox/README.md#hardening-of-every-confined-launch) | unseeded | Open.                                                   | A controller-level test refuses the launch and shows the inactive audit entry with its reason.                                        |
| KI-07 | 2026-11-01T05:31:56Z | verification-gap | The refusal for a missing delegated cgroup controller is not exercised on a host that lacks one.                                                      | [pi-better-sandbox README, Resource limits](../packages/pi-better-sandbox/README.md#resource-limits)                                       | unseeded | Open; documented in the resources-command test header.  | A test refuses a command-limit and a session-limit launch when a controller is absent, naming it.                                     |
| KI-08 | 2026-11-01T05:31:56Z | verification-gap | The per-launcher descriptor cases have no working control on the Node their test header describes, so they do not prove `hardening.fds` per launcher. | [pi-better-sandbox README, Hardening of every confined launch](../packages/pi-better-sandbox/README.md#hardening-of-every-confined-launch) | unseeded | Open; documented in the hardening-fds test header.      | Each launcher type has a case that fails with `hardening.fds` off, or the owner narrows its per-launcher claim.                       |

### KI-01 Stop reach of running confined launches

- Fact: a confined launch is built with `--clearenv --unshare-pid --new-session` and without `--die-with-parent` (`buildLinuxPermissionCommand` in `packages/sandbox-core/index.ts`, which contains no `--die-with-parent`).
- Fact: the stop script lists the members of the run's session with `ps -eo pid=,sid=,stat=` and signals each member by pid, TERM and then KILL (`buildStopScript` in `packages/pi-better-subagents/remote.ts`).
- Fact: the owner records a local reproduction with a stand-in pi. The stop ended pi and the outer bubblewrap, while the inner bubblewrap and its command kept running in their own scope: the command scope when `resources.command` was set, the session scope otherwise. They end when the command finishes or when a `runtimeMaxSec` ends the scope they are in.
- Fact: builder tests for launches built without read confinement assert that `--die-with-parent` is absent, with the message "detached children must remain durable" (`packages/sandbox-core/index.test.ts`, `packages/pi-better-subagents/tests/sandbox_profile.test.mjs`).
- Question: whether a real remote pi ends its running confined launches when it receives TERM; the owner states that the reproduction does not show it.
- Affected documents: the Stop and Session limits sections of the remote-subagents document and the Resource limits section of the pi-better-sandbox README.

### KI-02 Sibling-scope bound of confined launches

- Fact: the owners document that with `resources.command` in the remote pi's sandbox policy each confined launch starts its own `systemd-run --user --scope`, which systemd places beside the session scope. That launch is bounded by `resources.command` and not by the session scope's memory, task or CPU limits, and the session `runtimeMaxSec` does not end it. Without `resources.command` the launch runs in the session scope.
- Fact: the owners document that the session limits then no longer cap the total of the run; the remote pi and the children that are not scoped launches still share them.
- Evidence: the header of the real-scope session suite states that no case there uses bubblewrap (`packages/pi-better-subagents/tests/remote_session_limits_run.test.mjs`), and the pi-better-sandbox limit suites (`resources-command.test.ts`, `bubblewrap-limits.test.ts`) mention no session scope.
- Affected documents: the Resource limits section of the pi-better-sandbox README and the Session limits section of the remote-subagents document.

### KI-03 Limit-case skips without systemd

- Fact: the real-systemd cases skip when no user manager or delegated controller is available (`systemdSkip` in `packages/pi-better-sandbox/test/support/limits-support.ts`, the real systemd user scope suite in `packages/sandbox-core/resources.impl.test.ts`, the session limit run cases in `packages/pi-better-subagents/tests/remote_session_limits_run.test.mjs`).
- Fact: `PI_SANDBOX_REQUIRE_BACKEND` names the sandbox backend a run must prove and turns a missing backend into a failure. The test headers state that a user manager is not a sandbox backend and its skip stays a skip, so a run that sets the variable passes with every real-systemd case skipped.
- Affected documents: the Sandbox confinement lanes section of the development-and-release document.

### KI-04 Stop timeout of the session scope

- Fact: the session scope is built with `stopGrace: false` so that it carries exactly the configured properties (`resourceScopeArguments` in `packages/sandbox-core/index.ts`, its use in `packages/pi-better-subagents/remote.ts`). A command scope with `runtimeMaxSec` adds `TimeoutStopSec=5`.
- Fact: the owner documents that `runtimeMaxSec` makes systemd stop the scope with TERM and then KILL after the user manager's stop timeout.
- Evidence: the pi stand-in of the real-scope `RuntimeMaxSec` case installs no TERM handler (`packages/pi-better-subagents/tests/fixtures/remote/fake-pi.mjs`), and no case uses a pi that ignores TERM.
- Affected documents: the Session limits section of the remote-subagents document.

### KI-05 Descriptor probe for file operations

- Fact: task file operations run a fixed worker program with JSON on stdin. No seam lets a test put a probe inside it, and `/proc` is absent inside, so an inherited-descriptor leak cannot be observed from outside; nothing is claimed for that spawn site (`packages/pi-better-sandbox/test/hardening-fds.test.ts`).
- Affected documents: the Hardening of every confined launch section of the pi-better-sandbox README (the `fds` measure).

### KI-06 Launch-level refusal on unsupported architectures

- Fact: a launch with the keyring measure on and an uncovered CPU architecture is refused by `hardenLaunch` in `packages/sandbox-core/index.ts`. The only case is the state computation with an architecture seam (`packages/sandbox-core/hardening.impl.test.ts`); the launch-level refusal and the visibility cases simulate a bubblewrap that lacks a flag.
- Affected documents: the Hardening of every confined launch and Fail-closed behaviour sections of the pi-better-sandbox README.

### KI-07 Missing-controller refusal evidence

- Fact: the launch checks inside the scope that the control file of each configured limit exists (`resourceScopeCheckScript` in `packages/sandbox-core/index.ts`). Unit tests match the script's text; the real-systemd cases require a user manager that delegates cpu, memory and pids; the session stand-in simulates a missing user manager only (`packages/pi-better-subagents/tests/remote_session_limits.test.mjs`).
- Fact: the header of `packages/pi-better-sandbox/test/resources-command.test.ts` states that the missing-controller half of the fail-closed clause has no portable seam and is not covered there.
- Affected documents: the Resource limits section of the pi-better-sandbox README and the When the limits cannot be applied section of the remote-subagents document.

### KI-08 Controls of the per-launcher descriptor cases

- Fact: the test header observes that on this Node, Node's own `child_process` closes every descriptor not named in `stdio`, so a launcher that spawns bubblewrap directly cannot leak an inherited descriptor with or without the measure. The per-launcher cases therefore have no working control and only guard against a launcher passing descriptors on purpose; the falsifiable evidence is the builder-level case and the leaky-outer-shell case (`packages/pi-better-sandbox/test/hardening-fds.test.ts`).
- Question: whether the per-launcher cases have a working control on other runtimes the packages support (`engines.node` is `>=22.0.0`); no source establishes it.
- Affected documents: the Hardening of every confined launch section of the pi-better-sandbox README (the `fds` measure).

## Boundaries

- Each entry's behavior statements belong to the document its owner cell links; this register restates a residual and never redefines current behavior.
- The register selects no work, orders no repair and declares no readiness.
- Desired future evolution belongs to the roadmap, and implementation holes outside this register's admission belong to gap documents.
