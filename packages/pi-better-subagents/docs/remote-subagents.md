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
| `abortWaitMs` | no | How long stop waits for the RPC abort to be acknowledged (default 3000). |
| `termGraceSeconds` | no | Seconds between remote TERM and KILL on stop (default 5). |

The extension does not implement sandboxing. It passes the profile through, the remote pi applies
its own sandbox, and the bridge **verifies** that it did (next section). Model, thinking, tool allowlist/denylist and `approve` from the launch are
passed as the usual `pi` flags. Local extensions and the local task sandbox do not apply to a
remote run; extensions backing requested tools must be installed on the remote host.

## Parent sandbox: a remote spawn is network use

With pi-better-sandbox active, a `subagent_spawn` / `subagent_spawn_batch` that runs remotely (`remote`,
`resume`, or an agent mapped in `remoteAgents`) opens an SSH connection from the unconfined extension and runs
the child with network on the target. It is therefore **refused while the parent's Network access is Off**, with
the message "Sandbox: Network access is Off. A remote, resumed or remoteAgents-mapped subagent ...". Turn Network
access on in `/sandbox` or spawn a local subagent. If the `subagents` settings cannot be read, a spawn that names
an agent is refused (it cannot be proved local).

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
`sandbox`, `sandbox_dir`, `cwd` (set the target's `cwd`), `git_clone_workspace`, `allow_nested` and
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
| Verification fails and the remote stop cannot be verified | The marker is `remote-unstopped` (written *before* the stop is attempted, replaced by `sandbox-unverified` only after a verified stop), so a bridge killed meanwhile never reads as "surely gone"; `subagent_stop` retries. |
| SSH channel drops after the prompt was sent (even before the first event) | Same as mid-run: `channel-lost`, not finalized. Only a drop *before* the prompt is `ssh-failed`. |
| SSH channel drops mid-run | A `channel-lost` incident is recorded and the run is not finalized: normal health reconciliation marks it orphaned/lost. `subagent_stop` still kills the remote process. |

## Tests

Unit tests (`tests/remote_subagents.test.mjs`) run the real bridge and scripts over a fake `ssh`
(`tests/fixtures/remote`; the fake pi can report no, inactive, wrong-profile, stale or hash-less sandbox
entries, and detach a grandchild). `tests/remote_subagents_live.test.mjs` runs against a real host and
is skipped unless `PI_REMOTE_TEST_HOST` and `PI_REMOTE_TEST_SANDBOX_PROFILE` are set (see the file
header for the other variables); it also verifies the sandbox entry. It touches only its own run-scoped remote directories and leaves
nothing running.
