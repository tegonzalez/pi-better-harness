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
| `sandbox.args` / `sandbox.env` | no | Extra remote pi arguments and environment that carry the profile to the remote sandbox. `{profile}` is substituted. |
| `sandbox.verifyCommand` | no | Remote shell command that must exit 0 before launch (backend present, policy installed, ...). |
| `abortWaitMs` | no | How long stop waits for the RPC abort to be acknowledged (default 3000). |
| `termGraceSeconds` | no | Seconds between remote TERM and KILL on stop (default 5). |

The extension does not implement sandboxing. It passes the profile through, and the remote pi
applies its own sandbox. Model, thinking, tool allowlist/denylist and `approve` from the launch are
passed as the usual `pi` flags. Local extensions and the local task sandbox do not apply to a
remote run; extensions backing requested tools must be installed on the remote host.

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
5. The remote pi runs in its own session/process group where `setsid` exists, with its pid recorded
   in `<root>/<run id>/pid`. The session file stays in the run directory after the run so it can be
   found by run id.

## Stop

`subagent_stop` (and the navigator Close action) does, in order:

1. RPC `abort` through the bridge, and waits for its acknowledgement (bounded by `abortWaitMs`);
2. terminates the remote process group (TERM, then KILL after `termGraceSeconds`), only when the
   recorded pid still belongs to this run, and verifies it is gone;
3. stops the bridge and records `killed`.

If the remote stop cannot be verified (ssh down, process survives) the run keeps its status, an
incident is recorded, and the stop reports the reason so it can be retried. Stop also works on a
run whose bridge is gone.

## Failures

| Situation | Result |
| --- | --- |
| ssh cannot connect | Launch fails closed (no run). If it fails after launch, the run fails with an `ssh-failed` incident. |
| Remote pi not found | Run fails with a `pi-missing` incident. |
| `sandbox.verifyCommand` fails or remote pi rejects the sandbox flags | Run fails with a `sandbox-unavailable` incident (or `remote-exit`); the prompt is never sent. |
| Remote cwd missing | Run fails with a `cwd-missing` incident. |
| SSH channel drops mid-run | A `channel-lost` incident is recorded and the run is not finalized: normal health reconciliation marks it orphaned/lost. `subagent_stop` still kills the remote process. |

## Tests

Unit tests (`tests/remote_subagents.test.mjs`) run the real bridge and scripts over a fake `ssh`
(`tests/fixtures/remote`). `tests/remote_subagents_live.test.mjs` runs against a real host and is
skipped unless `PI_REMOTE_TEST_HOST` and `PI_REMOTE_TEST_SANDBOX_PROFILE` are set (see the file
header for the other variables). It touches only its own run-scoped remote directories and leaves
nothing running.
