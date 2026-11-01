# Remote subagents

A subagent run can execute on another machine over SSH. It is still an ordinary run: it has a
navigator row, a live log, incidents, stall detection, deadlines and ceilings, a callback,
`subagent_result` / `subagent_output`, and token and cache usage. Only the place the child process
lives changes.

Everything about the remote side is **configuration**. The extension contains no host names, user
names, paths, or models; the names below are placeholders.

## Configuration

Targets live in the subagents settings (`config.json`, the same file as `maxConcurrent`) under
`remoteTargets`. A run selects a target by name, either with the `remote` option of
`subagent_spawn` / `subagent_spawn_batch` (also per job or under `shared`), or through
`remoteAgents`, which maps a named agent id to a target name. An explicit `remote` wins. An unknown
name fails the launch closed before anything starts.

```json
{
  "remoteTargets": {
    "build-box": {
      "host": "my-ssh-alias",
      "cwd": "~/work/project",
      "root": ".pi-better-subagents/runs",
      "pi": { "command": "pi", "args": [], "login": true },
      "env": { "EXAMPLE_VAR": "value" },
      "sandbox": {
        "profile": "example-profile",
        "args": ["--example-sandbox-flag", "{profile}"],
        "env": { "EXAMPLE_SANDBOX_PROFILE": "{profile}" },
        "verifyCommand": "test -x /path/to/sandbox-backend"
      },
      "resources": { "session": { "memoryMax": "4G", "tasksMax": 512, "runtimeMaxSec": 7200 } },
      "abortWaitMs": 3000,
      "termGraceSeconds": 5
    }
  },
  "remoteAgents": { "agent.example": "build-box" }
}
```

Schema (validated on use; unknown fields are rejected):

| Field | Required | Meaning |
| --- | --- | --- |
| `host` | yes | SSH `Host` alias. User, port, keys and jump hosts come from your ssh configuration; `user` and `port` may be set here. |
| `cwd` | no | Remote working directory (`~/` expands remotely). Default: the remote login directory. |
| `cwdRoots` | no | Allowed working-folder roots (absolute or `~/…`; not `/` or `~`). Declaring them lets a spawn pass its own `cwd` (see below). The remote launch script resolves the working folder and every root with `pwd -P` and refuses to start pi (`cwd-denied`) unless the folder is inside a root; this check also covers `cwd` and the login directory. |
| `agentDir` | no | Agent dir for the remote pi: exported as `PI_CODING_AGENT_DIR` through the same env payload as `env` (absolute or `~/…`). Setting `PI_CODING_AGENT_DIR` in `env`/`sandbox.env` as well is rejected. |
| `root` | no | Where run directories live. Relative means under the remote `$HOME`. Default `.pi-better-subagents/runs`. |
| `pi.command` | yes | Remote pi executable: a name on the remote `PATH` or an absolute path. |
| `pi.args` | no | Fixed arguments placed before the generated ones. |
| `pi.login` | no | Start through the remote user's login shell (`"$SHELL" -lc`) so profile-provided `PATH` applies. |
| `env` | no | Environment exported for the remote pi. |
| `sandbox.profile` | **yes** | The remote sandbox profile. A target without one is invalid: a remote run is never unconfined by omission. |
| `sandbox.args` / `sandbox.env` | **one of them** | Remote pi arguments / environment that carry the profile to the remote sandbox. `{profile}` is substituted. At least one must reference `{profile}`; a target with no way to pass the profile is rejected. |
| `sandbox.verifyCommand` | no | Extra remote shell command that must exit 0 before launch (backend present, policy installed, ...). It is a convenience pre-check, not the verification. |
| `sandbox.entryType` | no | `customType` of the remote sandbox's launch audit entry. Default `pi-better-sandbox-read-confinement`. |
| `sandbox.entryProfile` | no | `profile` value the audit entry must carry (default: `sandbox.profile`). The pi-better-sandbox entry reports its permission profile, `"main"`, so set `"entryProfile": "main"` for it. |
| `sandbox.policyHash` | no | Expected `policyHash` (64-hex sha256) of the remote sandbox policy. When set, an audit entry with any other hash fails closed (`sandbox-unverified`, no prompt); when omitted the hash is only recorded, so any active remote policy is accepted. Pin it when the remote policy must not change unnoticed. |
| `sandbox.verifyTimeoutMs` | no | How long the bridge waits for that entry (default 30000). |
| `resources.session` | no | Limits for the whole remote pi process and everything it starts, applied with one systemd user scope. Keys, forms and failure behaviour: [Session limits](#session-limits). Any other key under `resources` is rejected. |
| `abortWaitMs` | no | How long stop waits for the RPC abort to be acknowledged (default 3000). |
| `termGraceSeconds` | no | Seconds between remote TERM and KILL on stop (default 5). |

The extension does not implement sandboxing. It passes the profile through, the remote pi applies
its own sandbox, and the bridge **verifies** that it did (next section). Model, thinking, tool allowlist/denylist and `approve` from the launch are
passed as the usual `pi` flags. Local extensions and the local task sandbox do not apply to a
remote run; extensions backing requested tools must be installed on the remote host.

## Session limits

An optional `resources.session` object bounds the whole remote pi process and every child it starts. The
values are yours to choose; the numbers in the example above are placeholders. Every key is optional, and
a key that is not set limits nothing:

| Key | Type and unit | systemd property |
| --- | --- | --- |
| `memoryMax` | Size string: a decimal integer with an optional `K`, `M`, `G` or `T` suffix (powers of 1024), for example `"4G"` | `MemoryMax=` |
| `memorySwapMax` | Size string, as above (`"0"` allowed) | `MemorySwapMax=` |
| `tasksMax` | Positive integer: processes and threads | `TasksMax=` |
| `cpuQuota` | Positive integer: percent of one CPU (`200` is two CPUs) | `CPUQuota=` |
| `runtimeMaxSec` | Positive integer: seconds | `RuntimeMaxSec=` |

Any other key, form or value (a JSON number for a size, `"64MB"`, `0`, a fraction, an unknown key) is
refused when the target is loaded. The keys and parser are the ones of the sandbox policy's
`resources.command` (see the pi-better-sandbox README), with the same forms.

When at least one key is set, the remote launch script starts pi through
`systemd-run --user --scope -p <property>=<value> ...` under `setsid`:

```
exec setsid -w systemd-run --user --scope ... -p MemoryMax=... -- sh -c '<scope check>' ... sh -c 'echo $$ > "$0/pid"; exec "$@"' "$RD" pi ...
```

- **One scope for the run.** The process that becomes pi, and every child, grandchild and detached sleeper,
  runs in that one transient scope, so the bound is shared (the sum of all of them, not per process). Two
  exceptions are described below: a confined launch that has its own `resources.command` scope, and anything that
  leaves the scope. The scope is created by the launch itself and ends when its last process ends.
- **setsid, pid file and stop are unchanged.** `systemd-run --scope` registers the calling process in the scope
  and then replaces itself with the command, so the pid in `<root>/<run id>/pid` is still the session leader that
  became pi, and the stop script (TERM, then KILL of every member of that session) still reaches everything the
  run started and leaves no process behind, with one exception: a confined launch that is running when the run
  is stopped (see "Confined launches inside the remote pi" below). When the last process of a scope dies the
  scope is gone. As before, a process that starts yet another session itself is out of the stop script's reach; it
  stays inside its scope's bounds, and `runtimeMaxSec` ends it with that scope.
- **Confined launches inside the remote pi.** What bounds a confined launch (one the remote pi's sandbox runs
  through bubblewrap) depends on the remote pi's own sandbox policy:
  - **`resources.command` not set in that policy:** the launch starts no scope of its own. It is an ordinary child
    of the remote pi, runs in the session scope and is bounded by the session limits like any other child.
  - **`resources.command` set in that policy:** each confined launch starts its own
    `systemd-run --user --scope`. systemd creates that scope beside the session scope (a sibling under the user
    manager's default slice), not inside it; a nested `systemd-run --user --scope` does not stay in the scope that
    started it. The launch is then bounded by its own `resources.command` limits and **not** by the session
    scope's memory, task or CPU limits, and the session `runtimeMaxSec` does not end it. The session bound is
    shared only by the remote pi and by the children that are not scoped launches, so `resources.session` no
    longer caps the total of the run (each launch has its own `resources.command` bound instead).
  - **Known limit: stop does not reach a running confined launch.** The stop script signals the members of
    the run's session. bubblewrap runs the sandboxed command under its own `--unshare-pid --new-session`, and the
    launch does not use `--die-with-parent`, so the sandbox's init process and the command under it are in a
    session of their own. In a local reproduction with a stand-in pi (no ssh), `subagent_stop`'s script ended
    pi and the outer bubblewrap process and printed `gone`, while the inner bubblewrap and its command kept
    running (their parent became a process outside the run), and their scope stayed: the launch's own scope when
    `resources.command` was set, the session scope when it was not. A confined launch still running when a
    run is stopped can therefore outlive the stop, together with its scope, until the command ends on its
    own or a `runtimeMaxSec` ends the scope it is in (the session's, or the policy's `resources.command` one).
    With neither set, nothing ends it but the command itself. That reproduction did not signal the children from
    the pi stand-in, so it does not show whether the real remote pi ends its running confined launches when it is
    stopped; the stop script itself does not signal it.
- **`runtimeMaxSec`** makes systemd stop the scope (SIGTERM, then SIGKILL after the user manager's stop
  timeout) when the time is up, which ends pi and everything in that scope; the bridge then records the exit as for any
  remote pi that ends. A confined launch in its own `resources.command` scope is not in it.
- **The scope carries only the configured properties.** The memory limit is a hard cap: a scope that exceeds
  `memoryMax` has its processes killed by the kernel's OOM killer, not paused.

### When the limits cannot be applied

A configured limit is never applied "if possible". Before staging the environment, the launch script checks,
and refuses (exit code 100, a `session-limits-unavailable` incident, pi is not started and no prompt is sent)
when any of these fails:

1. `systemd-run` is missing on the remote host.
2. The user's systemd **user manager** is not reachable: neither `$XDG_RUNTIME_DIR/bus` nor
   `$XDG_RUNTIME_DIR/systemd/private` exists and `DBUS_SESSION_BUS_ADDRESS` is not set
   (`XDG_RUNTIME_DIR` defaults to `/run/user/<uid>`). Over ssh the user manager exists only while the user
   has **lingering** enabled (`loginctl enable-linger <user>`, an administrator action on the remote host) or
   has an active login session. The reason names which applies (`lingering is enabled`, or `lingering is not
   enabled, so the user manager exists only while a login session is active`; `lingering and login-session
   state could not be read` when `loginctl` is unavailable). The launch log carries the same note for a
   successful start.
3. A probe scope with the configured properties cannot be started (for example the manager rejects a
   property), or a controller a limit needs (`memory` for `memoryMax` and `memorySwapMax`, `pids` for
   `tasksMax`, `cpu` for `cpuQuota`) is not delegated to the user manager: systemd silently ignores a property
   whose controller is missing, so the scope's cgroup is checked for the control files. `runtimeMaxSec` needs
   no controller.

The same check runs again inside the real scope immediately before pi starts. There is no unscoped fallback.
A target without `resources.session` (or with an empty one) generates the same launch script as before and
needs no systemd on the remote host.

### What the run shows

The run record (`meta.remote.sessionLimits`) holds the configured keys and values as written, and
`subagent_result` adds one line after the `Remote workspace` line, for example:

```
Remote session limits (build-box): one systemd user scope · memoryMax=4G · tasksMax=512 · runtimeMaxSec=7200
```

Runs without session limits show neither.

## Parent sandbox: a remote spawn is network use

With pi-better-sandbox active, a `subagent_spawn` / `subagent_spawn_batch` that runs remotely (`remote`,
`resume`, or an agent mapped in `remoteAgents`) opens an SSH connection from the unconfined extension and runs
the child with network on the target. It is therefore **refused while the parent's Network access is Off**, with
the message "Sandbox: Network access is Off. A remote, resumed or remoteAgents-mapped subagent ...". Turn Network
access on in `/sandbox` or spawn a local subagent. The guard resolves `remoteAgents` with the same resolver as the spawn
path (bundled `config.json`, then the saved `subagents` setting, or the un-migrated legacy config file). If the `subagents` settings cannot be read, a spawn that names
an agent is refused (it cannot be proved local).

## Workspace: working folder, agent dir, policy

A workspace is (working folder, agent dir, filesystem policy). With `pi-better-sandbox` the policy location can live in
the agent dir's settings (`piBetterHarness.sandboxReadConfinement.policyFile`), so the same workspace is usable by a
monitored remote subagent and by the owner's own pi started in that working folder with `PI_CODING_AGENT_DIR=<agent-dir>`.

- **Fixed working folder:** set `cwd` (unchanged behavior). A spawn `cwd` is rejected.
- **Per-spawn working folder:** set `cwdRoots`; `subagent_spawn` / `subagent_spawn_batch` (per job or `shared`) then accept
  `cwd`, which replaces the target's `cwd` for that spawn. The remote host resolves it with `pwd -P` and requires it to lie
  inside one of the (also resolved) roots, so symlinks, `..` and prefix tricks cannot escape; otherwise pi is never started
  (`cwd-denied`, exit 99). A missing folder is `cwd-missing`. Each spawn is its own run with its own remote session; `resume`
  keeps the earlier run's working folder (a different `cwd` is refused). The run records the folder in `remote.cwd`.
- **Agent dir:** set `agentDir` so the remote children use the workspace's agent dir (settings, models, policy location).
- **Compare with your own session:** `subagent_result` shows a `Remote workspace (<target>): cwd … · agent dir … ·
  policyHash … · planHash …` line (the verified values from the sandbox launch entry). Run pi in the same working folder with
  the same agent dir and use `/sandbox workspace` (see "Verify a workspace interactively" in the pi-better-sandbox README) to
  compare, and `/sandbox check <path>` and `!` probes to see what the worker can read and write.

## Sandbox verification (the prompt is never sent on trust)

After starting `pi --mode rpc` the bridge calls RPC `get_entries` and requires the sandbox launch
audit entry (a `custom` session entry of `sandbox.entryType`) written by **this** pi process, with
`data.active === true`, `data.profile` equal to `sandbox.entryProfile` (default the target's profile), and non-empty `data.policyHash`
and `data.planHash`. Entries older than the remote's own start stamp (a resumed session carries earlier
processes' entries) never count. Only then is the prompt sent. Otherwise (no entry within
`verifyTimeoutMs`, inactive, other profile, no hashes) the run fails closed: a `sandbox-unverified`
incident is recorded, the remote session is stopped and verified gone, and no prompt is sent. If that
stop cannot be verified the run is not finalized (`remote-unstopped`) and `subagent_stop` retries it.

The verified `profile`, `policyHash` and `planHash` are recorded in the run metadata
(`remote.sandbox`), in `remote-sandbox.json` in the run directory, and as a `remote_sandbox_verified`
event in the run log. Contract with the sandbox extension: entry fields `active`, `profile`,
`policyHash`, `planHash` (a remote pi without that sandbox fails this check by design).

## Environment and secrets

`env` and `sandbox.env` values are never put on a command line. The bridge writes them to the launch
script's stdin; the script stages them in a `0600` file on the remote that is sourced and removed
before pi starts. Locally the payload is a `0600` file deleted as soon as the bridge has sent it, and
neither the bridge configuration nor the run metadata contains values. They still end up in the remote
pi's environment (visible to that user, and to its children), so: **do not put secrets in `target.env`**;
use the remote host's own credential mechanisms.

## Unsupported options

A remote run honours `model`, `thinking`, `tools`, `exclude_tools`, `approve`, `callback`, timing, `name`.
`sandbox`, `sandbox_dir`, `cwd` (unless the target declares `cwdRoots`; otherwise set the target's `cwd`), `git_clone_workspace`, `allow_nested` and
`clean` are rejected with an error when a remote target applies, instead of being ignored.

## Resume

`subagent_spawn` with `resume: <run id>` (remote runs only; there is no local resume) starts a **new run**
whose remote pi continues the kept session of the earlier run (`pi --continue` on its session directory)
on the same target; the prompt is the follow-up message. The earlier remote process must be stopped
(the launch verifies it and fails otherwise), the sandbox is verified again for the new process, and the
new run records `remote.resumedFrom`. An unknown or missing session fails the launch (`session-missing`).

## Naming a target from an agent definition

Not supported, on purpose. Agent definitions (`pi-agent/v1`) are portable catalog data (model, effort,
tier) and may live in a project; host-control values, including where a child runs, stay out of the
catalog (see `agent-catalog.md`, host execution controls). The name-only indirection is `remoteAgents` in
the host-owned settings (`agent id -> target name`), which already resolves a catalog agent to a target
without the definition carrying anything.

## How it works

1. The launch opens (or reuses) one SSH ControlMaster per target (`ssh-core`, `BatchMode=yes`, no
   TTY). If the master cannot be established the launch fails closed.
2. A small local bridge process (`remote-bridge.mjs`) is started as the run's child. It runs
   `pi --mode rpc` on the host through that connection, with a run-scoped session directory
   (`<root>/<run id>/session`), and writes the RPC session events to the run log in the same shape
   as `--mode json`. Because the log is the normal log, the navigator, health, stall detection,
   timing, callbacks and result tools work unchanged.
3. At the end the bridge asks the remote pi for `get_session_stats` and records it, so the run's
   token, cache-read and cost figures are the remote session's own totals.
4. Steering. A steer request file (`steer.json`, the existing child-steer path; the deadline steer
   uses it) is delivered with RPC `steer`, or `follow_up` when the request has `"mode":
   "follow_up"`, followed by a `.delivered` receipt.
5. The remote host must be **Linux**: the launch and stop scripts need `setsid` and `ps -eo pid=,sid=,stat=` (session
   ids). Other systems are not supported. The remote pi runs in its own session (`setsid` is **required**: the launch fails with a
   `setsid-missing` incident without it), with the session id recorded in `<root>/<run id>/pid`. The session file stays in the run directory after the run so it can be
   found by run id.

## Stop

`subagent_stop` (and the navigator Close action) does, in order:

1. RPC `abort` through the bridge, and waits for its acknowledgement (bounded by `abortWaitMs`);
2. terminates **every process of the remote session** (TERM, then KILL after `termGraceSeconds`) and
   verifies that none remain. Detached children in their own process groups share the session and are
   covered; a process that starts yet another session itself is out of reach and is a documented limit.
   The stop refuses (and reports) when the recorded pid is alive but not a session leader, or when `ps`
   cannot report sessions: it never guesses;
3. stops the bridge and records `killed`.

With `resources.session`, pi and its children run in one systemd user scope (see [Session limits](#session-limits));
the same stop applies unchanged and the scope ends with its last process.

The stop is asynchronous: the tool, shutdown, timing stops and the navigator never block the event loop
(the navigator reports the row as stopping and dismisses it when the stop is verified). A run whose
remote work is known to be over (agent settled, or failed before any remote work) is stopped without
ssh. If the remote stop cannot be verified (ssh down, process survives) the run keeps its status, an
incident is recorded, and the stop reports the reason so it can be retried. Stop also works on a run
whose bridge is gone.

A bridge that dies abnormally (SIGKILL, OOM, no failure marker) is never finalized while the remote may
still run: the remote stop is run and verified first, and if it cannot be verified the run stays
unfinalized (health marks it orphaned) with a `bridge-died` incident.

## Failures

| Situation | Result |
| --- | --- |
| ssh cannot connect | Launch fails closed (no run). If it fails after launch, the run fails with an `ssh-failed` incident. |
| Remote pi not found | Run fails with a `pi-missing` incident. |
| `sandbox.verifyCommand` fails or remote pi rejects the sandbox flags | Run fails with a `sandbox-unavailable` incident (or `remote-exit`); the prompt is never sent. |
| `setsid` missing on the remote | Run fails with a `setsid-missing` incident; pi is not started. |
| Remote sandbox launch entry missing, inactive, other profile or without hashes | Run fails with a `sandbox-unverified` incident; the remote is stopped; the prompt is never sent. |
| Session to resume missing | Run fails with a `session-missing` incident. |
| Remote cwd missing | Run fails with a `cwd-missing` incident. |
| Working folder outside the target's `cwdRoots` | Run fails with a `cwd-denied` incident; pi is never started. |
| `resources.session` set but `systemd-run`, the user manager (no lingering and no login session) or a needed controller is missing | Run fails with a `session-limits-unavailable` incident naming the reason; pi is never started and there is no unscoped fallback. |
| Verification fails and the remote stop cannot be verified | The marker is `remote-unstopped` (written *before* the stop is attempted, replaced by `sandbox-unverified` only after a verified stop), so a bridge killed meanwhile never reads as "surely gone"; `subagent_stop` retries. |
| SSH channel drops after the prompt was sent (even before the first event) | Same as mid-run: `channel-lost`, not finalized. Only a drop *before* the prompt is `ssh-failed`. |
| SSH channel drops mid-run | A `channel-lost` incident is recorded and the run is not finalized: normal health reconciliation marks it orphaned/lost. `subagent_stop` still kills the remote process. |

## Tests

Unit tests (`tests/remote_subagents.test.mjs`) run the real bridge and scripts over a fake `ssh`
(`tests/fixtures/remote`; the fake pi can report no, inactive, wrong-profile, stale or hash-less sandbox
entries, and detach a grandchild). `tests/remote_subagents_live.test.mjs` runs against a real host and
is skipped unless `PI_REMOTE_TEST_HOST` and `PI_REMOTE_TEST_SANDBOX_PROFILE` are set (see the file
header for the other variables); it also verifies the sandbox entry. It touches only its own run-scoped remote directories and leaves
nothing running. `tests/remote_session_limits*.test.mjs` cover `resources.session`: the parser, the generated
script (against a stand-in `systemd-run`), and, when a user manager with the cpu, memory and pids controllers
is available, real small scopes whose cleanup the tests verify.
