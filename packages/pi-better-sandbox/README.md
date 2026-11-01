# pi-better-sandbox

Sandbox permissions for Pi's foreground tools, detached subagents, and local background tasks.

![Pi Better Sandbox package preview](https://raw.githubusercontent.com/1aboveio/pi-better-harness/main/docs/images/package-gallery/pi-better-sandbox.png)

It is installed by default with [`pi-better-harness`](https://github.com/1aboveio/pi-better-harness/tree/main/packages/pi-better-harness#readme), and can be installed on its own:

```sh
pi install npm:pi-better-sandbox
```

Either way you keep starting Pi the way you always have — `pi`. There is
no launcher or wrapper command. Main, Subagents, and Background tasks all start
inactive in fresh settings. Saved global profiles and session choices, including
enabled switches, keep their values. Open `/sandbox` to change any column, or use
`/sandbox on` for the current Main session. Edits apply immediately and are
saved to the current session branch. **Ctrl+S** saves all three profiles as
defaults for new sessions.

```text
Sandbox permissions               Main             Subagents         Background tasks

Sandbox                           Off              Off               Off

Project files                     -                -                 -
Outside project                   -                -                 -
Stored credentials                -                -                 -
Run applications                  -                -                 -
Shell scripts                     -                -                 -
Command time limit                -                -                 -
Network access                    -                -                 -
Process access                    -                -                 -

  Subagents · Tools
    Guarded (follows the file rules)
    [x] apply_patch  harness adapter
    Trusted (runs outside the file rules)
    > [x] @juicesharp/rpiv-web-tools  2/2
    > [ ] <other installed package>  0/1

↑↓ Select · ←→ Column/fold · Space Toggle · ctrl+s Save default · Enter Fold · Esc Back
```

**Subagents · Tools** picks the extension tools a confined subagent may use:

- **Guarded** tools go through the same guarded file operations as `write` and
  `edit`, so the rows above govern them. `apply_patch` applies Codex-style
  patches; deletes and moves follow the removal rules, and a patch is checked in
  full before any file changes.
- **Trusted** tools are the other tools your Pi has loaded, listed with their
  package. A ticked one is loaded into the subagent and runs in its Pi process,
  **outside the file rules**. One Space toggles it immediately. It is admitted
  only from the package you ticked. Known network tool names are refused while
  Network access is Off: `web_fetch`, `web_search`, `firecrawl_scrape`, `firecrawl_extract`, `mcp`, `mcpScript`, `remote_bash`,
  `ssh_profile`, `ssh_mux`, and any `mcp__*` name. That is a name list, not a network sandbox.
  A `subagent_spawn` / `subagent_spawn_batch` that runs the child **remotely** (`remote`, `resume`, or an agent mapped
  in `remoteAgents` of the subagents config: bundled `config.json`, the `subagents` setting or the legacy file) is network use too: it opens an SSH connection from the unconfined
  extension and runs the child with network on the target, so it is refused while Network access is Off.

Trusted tools use two levels: a package/provider group, then its individual tools.
Non-MCP tools are grouped by exact owning package; `mcp__<provider>__...` tools
are grouped by provider and owning package together. Groups start collapsed.
File-backed extensions explicitly marked `builtin` by Pi display as `built-in`,
not their package path (which can be `.`). This is a display label only: saved
choices and admission still use the original owning package. An unmarked `.`
package is not built-in, and an unavailable saved tool keeps its package label
until Pi reports its provenance again. Core tools with synthetic source paths
remain excluded from trusted candidates.
`>` means collapsed and `v` means expanded. Their checkbox shows `[x]` when
all children are selected, `[-]` when some are selected, and `[ ]` when none
are; the count is selected/total. Right expands a group. Left collapses a group,
or moves from a child to its parent and collapses it. Enter folds the selected
group. Space on a group selects all children when none or only some are selected,
or deselects them all when all are selected. Every toggle applies on one Space;
Ctrl+S saves defaults and reports anything loosened. Only individual tool
entries are saved, never a package/provider wildcard or the open/closed state.

Defaults: `apply_patch`, `web_fetch`, and `web_search` on; everything else off.
The `pi-better-ssh` trusted group offers `ssh_profile`, `remote_bash`, and
`ssh_mux`, all off by default. Expand it with Right and toggle individual tools
with Space, or toggle the group to select all three. Keep Subagents Network
access On. A ticked tool automatically loads its owning extension into new
subagents; no separate extension mapping is needed. Default launches include
ticked tools; an explicit spawn `tools` list must include the SSH tools needed,
and `clean:true` does not load extensions. Ctrl+S saves these choices for new
sessions. Running subagents keep their launch policy.

Trusted SSH tools run outside local file, credential-file, and command rules;
remote effects are not confined either. Only enable them when you trust the
extension and the subagent's access to your SSH configuration and credentials.
Other harness packages remain excluded from trusted candidates.
See [ADR 0009](../../docs/adr/0009-guarded-and-trusted-subagent-tools.md).

Project files and Outside project cycle through four levels:

| Level | Meaning |
| ----- | ------- |
| Off | No access. |
| Read | Read only. |
| Write | Read, create, and overwrite in place; removal is restricted, with the exceptions below. |
| Write & delete | Full access, including removal. This was called "Read / write"; saved settings keep it. |

Stored credentials uses the same labels but offers only **Off**, **Read**, and
**Write & delete**. Subagents default to Write & delete; Main retains Read.
Explicit saved defaults and session profiles are preserved, including Read and
Off. Changing the built-in default does not upgrade existing profiles.

Whatever these rows say, removal is always allowed in **temp**, **hidden
directories and files directly under your home** (`~/.cache`, `~/.gradle`,
`~/.npm`, …), and **git worktree folders** (`.worktrees/`, `*-worktrees/`). The
deny list below still wins there.

**Write blocks rename-based saves.** The kernel treats "rename a temp file over
an existing file" as removing that file. Under Write, git commits and editors or
package managers that save atomically fail outside those disposable places. Pi's
own `write` and `edit` tools write in place and keep working. Choose Write &
delete for a place where that matters. The table shows this hint when you
select the row.

**Outside project = Write** (the Subagents default) lets tasks write across your
home directory and temp, so tool caches just work with no per-tool setup. It
retains fixed protections that are not configurable per tool:

- **Credentials** follow the independent Stored credentials row. The Subagents
  `Write & delete` default permits reading, modifying, and removing the files
  listed below plus `~/Library/Keychains`,
  `~/.claude/.credentials.json`, `~/.claude.json`, `~/.gnupg`,
  `~/.codex/auth.json`, `~/.cargo/credentials(.toml)`, `~/.pgpass`, and
  `~/.config/rclone`, subject to stricter protected-path rules. Set the row to
  Read to deny credential writes or Off to hide them. Writable credentials let
  CLIs such as `gcloud` update database permissions and refresh token state even
  for read-only cloud queries. This also lets tasks alter or delete credentials;
  it is not a read-only authentication capability.
- **Code that runs later** cannot be written, removed, or renamed: shell startup
  files (`.bashrc`, `.zshrc`, `.profile`, and the rest), `~/.config/fish`,
  `~/.gitconfig`, `~/.config/git`, `~/.config/systemd/user`,
  `~/.config/autostart`, `~/.pi` (or `$PI_CODING_AGENT_DIR`), `~/.claude`,
  `~/.agents`, `~/Library/LaunchAgents`, `~/.local/bin`, `~/bin`,
  `~/.git-templates`, `~/.oh-my-zsh/custom`, `~/.gradle/init.d`,
  and `~/.cargo/config(.toml)`. These stay readable, because subagents read skills from them.
  Their parent folders can't be removed or renamed either, so you can clean
  inside `~/.gradle` but not delete `~/.gradle` itself.
- **Harness state** (the subagent and background-task registries, run and
  control directories, and task-runtime provenance) cannot be written, removed,
  or renamed.

Every protected entry is guarded under the literal path under home, every symlink hop
on the way to its target, and the target itself. So a dotfiles manager's links
(stow, chezmoi), including chains of links, can't be swapped or retargeted. A
link whose target is missing protects that target too: it can't be created.

**Git config and hooks under home are not protected**, so git keeps working:
`git init`, `git clone` and `git worktree add` copy hook samples into `.git/hooks`.
A task can therefore plant code that a later git command runs, through any
repository's `.git/hooks` or `.git/config` (`core.hooksPath`, `core.fsmonitor`,
`diff.external`, filters, aliases), submodule hooks in `.git/modules/*/hooks`,
`gitdir:` redirects, or files that `~/.gitconfig` pulls in with `[include]`.
`~/.gitconfig`, `~/.config/git`, and `~/.git-templates` themselves stay protected. Add your own paths to the deny list with `/sandbox deny add <path>`. Under
Write, those paths are also protected from removal and renaming.

Space applies every change immediately, including higher permission levels,
capabilities switched on, and a sandbox switched off. `ctrl+s` saves the
defaults from any row on the first press, and the note names anything that
loosened. Enter only folds tool groups; it never saves defaults. The focused
row has a full-width background and bold text; the selected profile cell
also uses inverse styling. No model
tool can change these settings. Space toggles switches and cycles Command time
limit through 1 min, 5 min, 10 min, 30 min, and No limit. Detail cells under an
Off sandbox display a dimmed `-` and cannot be changed; their values return when
the sandbox is enabled again. When Run applications is Off, Shell scripts and
Command time limit are likewise dimmed and retain their values.

Run applications is the master switch for task command execution. With it On,
Shell scripts Off blocks `bash`, user-entered `!` and `!!` commands, and direct
launches of shell interpreters, including aliases. The guarded `run_application`
tool takes `executable: string`, `args: string[]`, and optional `timeout: number`,
and launches directly inside the OS sandbox without a shell. Applications such
as `pnpm` and `pytest` can still run scripts internally; this setting does not
prevent all descendant shells or guarantee an application finishes.

Direct execution requires Node.js with `process.execve` (22.15+ or 24+) so an
unsupported executable cannot fall back to a shell. Older runtimes refuse the
launch rather than weaken the restriction.

Command time limit is a hard maximum for each command: a model cannot raise it
or bypass it by omitting a timeout, and a smaller requested timeout wins. Cleanup
covers ordinary process-group descendants, not deliberately daemonized processes.
The default is Shell scripts On and No limit; all three Sandbox switches default
Off. To use direct-only Subagents with a 10-minute limit, set Subagents → Sandbox
On, Run applications On, Shell scripts Off, and Command time limit to 10 min,
then press Ctrl+S to save those defaults. New subagent and background launches
capture their policy; running work keeps its launch policy.

### Platforms

| | macOS (Seatbelt) | Linux (Bubblewrap) | Windows |
| - | - | - | - |
| Outside project = Write | Writes across home and temp. Removal and renaming refused outside the disposable places. | Fallback: ordinary top-level home folders (`~/projects`, `~/Documents`, …) and home itself are **read-only**. Dot entries, temp, worktree folders (found within three levels of home), and the workspace are writable, removal included. A directory holding a protected symlink (typically `~/.config` with a stow link such as `~/.config/git`) keeps its existing entries writable but refuses new top-level entries. A protected symlink pointing at nothing can get an empty read-only placeholder that stays on disk; the launch says so, and you remove the placeholder before creating the real target. | No backend: confined launches fail closed. |
| Project files = Write | Enforced. | **Refused at launch** (bind mounts cannot separate removal from writing). Use Write & delete or Read. | No backend. |
| Deny list | Path rules, matched ignoring case on every volume (as Seatbelt does). | Credentials masked by empty mode-000 mounts. Code that runs later is bound read-only. | No backend. |

Linux could separate removal from writing with Landlock (5.19+), but nothing
here can apply it: Node has no binding and `bwrap` does not expose it. Windows
could use NTFS `DELETE` rights with a restricted token or AppContainer, which
would need a native launcher. Both are tracked as follow-ups; see
[ADR 0008](../../docs/adr/0008-write-without-delete.md).

### Recovery snapshot (macOS)

When a confined subagent or background task starts with Outside project =
Write or Write & delete, the harness starts `tmutil localsnapshot` in the
background. That is an APFS local snapshot and needs no administrator rights.
Write can still empty or re-permission files in place, and Write & delete can
remove them. It takes at most one per 15 minutes per Pi process. The run never
waits for it. A failure shows as a warning (subagents) or a task-log line
(background tasks). Set `PI_SANDBOX_RECOVERY_SNAPSHOT=off` to turn it off.

Local snapshots are purgeable, so treat them as a recovery aid, not a backup.
The Seatbelt profile leaves Mach IPC to system daemons open, which is why
`security` and `tmutil` work inside the sandbox. It also means a hostile task
could likely delete these snapshots. Restore from one with Time Machine or
`tmutil restore`.

**Stored credentials currently means known credential files.** It covers SSH,
AWS, GitHub CLI, Google Cloud CLI, Azure, Kubernetes, Docker, npm, netrc, Git
credentials, and Pi's file-based auth. These rules override ordinary file access.
OS vault services such as Keychain and Secret Service, and tokens inherited in
environment variables, are excluded. Write & delete may be needed by a CLI that
refreshes a token or updates its credential database. This row applies
independently of Project files and Outside project.

**Process access** uses **Off** or **Read** (default for fresh profiles).
Main and Subagents control the fixed `process_list` tool. Its Read setting
returns current-user process IDs and names only, with optional
literal name filtering and a bounded result limit. It does not expose command
arguments, environment variables, debugger attachment, signals, termination,
or emulator/ADB operations. Explicit saved values are preserved, and legacy
saved profiles without this setting stay Off until a human enables Read;
subagents snapshot the setting at launch. Background tasks uses this row for
explicit task-status process diagnostics, not `process_list`. Those diagnostics
require current Read in both Main and Background tasks. They check a registered
PID's start identity and can report state, CPU time and wait evidence without
arguments or environment values. They are unavailable under Main confinement;
no unconfined fallback runs. Task confinement remains the policy recorded when
the task launched, independent of current diagnostic permission.

The inventory helper uses a fixed system `pgrep` command under the existing
kernel policy, without a shell or model-controlled arguments. It can work with
Run applications Off because it is a fixed read-only adapter, not
general command execution. No sandbox restrictions are relaxed. The control
governs this adapter only: it does not make arbitrary shell process inspection
impossible when commands are enabled. Windows has no supported inventory backend.
Linux still requires a supported permission profile with visible process metadata;
hidden-root profiles without `/proc` fail rather than gaining a new host mount.

On macOS, `/bin/ps` is setuid and can be refused at execution by Seatbelt even
when process information reads are allowed. Enabling Process access provides
`process_list`; it does not authorize raw `/bin/ps` or an unconfined workaround.

File and shell operations use the kernel: macOS uses Seatbelt (`sandbox-exec`)
and Linux uses Bubblewrap (`bwrap`). `read`, `write`, and `edit` keep Pi's normal
tool behavior and mutation queues, while a fixed worker performs filesystem
syscalls under the selected policy. Canonical checks explain denials; kernel
enforcement also protects against a symlink changing between checking and use.
The confined file worker rejects files over 8 MiB instead of silently truncating
them; larger-file processing can use a confined command when commands are On.

## What is confined, and what is not

Pi is the trusted runtime. It can lock configuration/authentication files,
connect to its provider, and persist sessions. Main and Subagents permissions
apply to task operations. Subagents can start with task Network access or Run
applications Off. The fixed file worker remains available according
to the file permissions even when task commands are Off.

The task executor provides private scratch through `TMPDIR`, `TMP`, and `TEMP`.
Outside Read and Write & delete also retain explicit runtime write exceptions for
`/tmp` (canonical `/private/tmp` on macOS), the current user's macOS temporary
directory, and that user's Security.framework MDS cache. MDS access lets CLI
Keychain retrieval initialize and refresh its cache; it does not restrict the
Keychain API to reads. Other users' caches and arbitrary outside `*.lock` files
are not writable. Credential-file and Pi control-path protections still win.
Outside Off does not expose these host runtime directories.

The currently admitted model-tool implementations are `read`, `write`, `edit`,
`bash`, and guarded `run_application`, plus, for Subagents, the guarded `apply_patch` and the trusted tools
ticked under Subagents · Tools. User-entered `!` and `!!` commands use the same
shell policy. Other model-callable tools require a verified execution adapter
and are refused while that actor's sandbox is enabled; enabling network alone
does not admit them. Subagent launch output identifies requested tools that are
unavailable, with the reason. Main
remains Off by default, so its ordinary orchestration tools remain available
unless the user enables Main confinement.

Pi and installed runtime extensions remain trusted code, including their
initialization, provider hooks, and internal `pi.exec` calls. The tool gate is
not a sandbox around malicious runtime extensions. Loaded runtime code,
configuration, and policy/control files are protected from task writes, even
under broader file grants. Task access to `~/.pi` does not receive a blanket
write allowance or lock-file exception.

Local confinement cannot govern a remote host's filesystem. SSH tools are
available to confined Subagents only when explicitly ticked as trusted under
Subagents · Tools, with Network access On. They run outside local task rules.
Main SSH tools, and unadmitted MCP, scripting, background, and nested-agent
tools, still lack admission adapters and fail closed under an enabled actor
profile. SSH through confined `bash` receives local file, credential, and network
restrictions; remote effects remain outside the local filesystem policy.

Verified first-party Background tools have a separate, versioned admission
adapter. It checks the loaded extension's canonical source and exact current
schema identity before admitting local spawn/watch and explicit registry
operations. Background's column controls the executable, independently of
Main's commands switch. Missing or incompatible adapters fail closed when
Background confinement is enabled, even with Main Off. Remote stop receives no
local-adapter exemption under Main confinement. See [ADR 0017](../../docs/adr/0017-background-adapter-admission.md).

Overriding `write` and `edit` changes nothing you can see: the parameter
schemas, prompt guidance, call rendering, write previews, edit diffs, result
details, mutation queueing, and cancellation are Pi's own. Only the filesystem
operations underneath them are replaced.

## Linux read confinement

On Linux bubblewrap, **Outside project = Off** already hides everything except the
system runtime roots. *Read confinement* is an opt-in refinement of that mode: when a
policy file is configured, the agent can additionally read only

- its project/worktree (writable) and the git dir a worktree `.git` file points to (writable, only when it
  proves it belongs to this worktree **and lies outside every writable root**, the project included; the `.git` file itself
  is read-only; the git-dir write-deny set below applies; alternates are read-only),
- whatever the project reaches through symlinks (read-only, followed transitively),
- the tools the policy approves, with their libraries and interpreters (read-only),
- those tools' approved config paths (read-only) and cache paths (private tmpfs, or a persistent per-agent directory).

Everything else — sibling projects, other users' homes, the stored-credential list —
is not mounted, so it fails with "No such file or directory". `/tmp` stays a private
tmpfs, the network stays `--unshare-net` while Network is Off, and the synthetic root
is remounted read-only so stray writes fail instead of landing in ephemeral storage.
Pi's in-process read/write/edit tools use the same computed allow set: a path is
allowed only when its realpath is inside it. Without a configured policy nothing
changes.

### Configuring the policy

The policy is a JSON file whose location is configuration, never code:

1. `PI_SANDBOX_READ_CONFINEMENT_POLICY=/absolute/path/policy.json`, or
2. the harness setting `sandboxReadConfinement: { "policyFile": "/absolute/path/policy.json" }`, stored under
   `piBetterHarness` in the **agent dir's** `settings.json` (`$PI_CODING_AGENT_DIR`, default `~/.pi/agent`).

Because the setting lives in the agent dir, a plain `PI_CODING_AGENT_DIR=<dir> pi` started in a working folder applies
the same policy with no extra environment. A *workspace* is the triple (working folder, agent dir, policy): the same
binding serves a monitored remote subagent (target `cwd`/`cwdRoots` and `agentDir`) and the owner's own separate pi
(see [Verify a workspace interactively](#verify-a-workspace-interactively)). The policy file must stay outside every
writable root (the existing refusal below), so it cannot live in the working folder.

Unknown keys, wrong types, relative paths and invalid regular expressions are refused
at load time and block launches (fail closed). Path entries are absolute, `~/…`, or
`${VAR}/…` (resolved from the launching environment; an unset variable skips the entry).

| Key | Meaning | Default |
| --- | --- | --- |
| `version` | Must be `1`. | required |
| `limits.maxSymlinks` / `maxDepth` / `maxWalkEntries` / `maxBinds` / `maxWalkMs` | Caps on the symlink closure. Exceeding one fails the launch with an error naming the cap. | 2000 / 8 / 200000 / 500 / 15000 |
| `limits.minPrefixDepth` | `install: "prefix"` is refused when the prefix has fewer path components, or contains/lies in the home, the project or a writable root. | `3` |
| `env.allow[]` | Environment variable names the confined child may inherit, in addition to `PATH`, `HOME`, `LANG`, `LC_ALL`, `TERM`, `TMPDIR`, `TZ`. Everything else is cleared (`--clearenv`). `PATH` is always the synthetic one. | `[]` |
| `readOnly[]` | Generic read-only paths (for example shared folders): absolute, `~/…` or `${VAR}/…`, no wildcards. Each is realpath'd and must pass the deny list (a path inside a denied path, or one that contains a denied path or lies inside or around a writable root or the sandbox's private `/tmp`, is refused and recorded in `denied`, and never counts as an approved location); a missing one is `skipped`. Mounted read-only; symlinks inside are not followed. | `[]` |
| `limits.maxWildcardMatches` | Cap on the matches one wildcard pattern may expand to; exceeding it fails the launch. | `64` |
| `walkSkipDirNames` | Directory names the symlink walk never enters (for example a large dependency tree). | `[]` |
| `deny.paths` | Extra denied paths. A symlink target inside one, or a directory containing one, is skipped and recorded. | `[]` |
| `deny.credentialList` | Include the broad built-in stored-credential locations (keyrings, gpg, rclone, cloud and agent tokens) in the deny list. | `true` |
| `deny.otherHomes` | Deny every account home (passwd database) other than the current user's. | `true` |
| `tools.approved[]` | A name (looked up on the launching `PATH`), or `{ name \| path, config[], cache[], cachePersistent, bind[], install }`. `install: "prefix"` binds the install prefix instead of just the executable; `bind` adds extra read-only paths. | `[]` |
| `tools.approvedPathDirs[]` | Approve every executable in a directory that is on the launching `PATH`. An entry (and a tool `path`) may contain a **single-segment `*`** (for example `<base>/*/bin`; never `**`, no `..`), expanded at launch. Every match must be on the launching `PATH` (directories) and its realpath must lie inside an approved or bound location: a `readOnly` path, a tool `bind`, or a runtime root. Other matches are refused and recorded in `denied`; every match, accepted or not, is listed under `audit.wildcards`. `*` does not match leading-dot names. | `[]` |
| `tools.builtinDefaults` | Apply the generic built-in map (`git` → `~/.gitconfig` and the `config`/`ignore`/`attributes` files below `$XDG_CONFIG_HOME/git` and `~/.config/git`, never the whole directory) to approved tools without their own `config`. Set `false` to remove it. | `true` |
| `secretDetector.useDefaults` / `patterns[]` / `maxScanBytes` / `maxScanFiles` | Config entries whose files match a pattern (private-key headers, common token shapes, `_authToken=`, `password=…`) are refused, not bound. Defaults also match URL userinfo (`://user:pw@`), `Authorization:` headers and short `password=` values. A file larger than `maxScanBytes` is refused, not truncated. `(?i)` prefix = case-insensitive. | defaults on |
| `caches.persistentDir` | Base for `cachePersistent` caches: `<dir>/<agent>/<tool>-<hash>`. | unset (persistent caches skipped) |
| `syntheticPathMount` | Where the PATH directory appears in the sandbox. | `/run/pi-confined/bin` |
| `planTtlMs` | **Removed.** The plan is never recomputed during a session; the key is rejected so stale policies are noticed. | — |

At launch the planner resolves the launching `PATH`, takes the realpath of each approved
tool, follows script shebangs (including `env`) and, for ELF binaries, asks the binary's own
dynamic loader which libraries it needs (`DT_NEEDED`, `RPATH`, `RUNPATH`), and binds only those.
A directory holding symlinks to other symlinks gets matching `--symlink` mounts so chains resolve
exactly as on the host. The `PATH` inside the sandbox contains only the approved tools (plus
interpreters they need, marked in the report); unapproved tools are absent.

### When the plan is computed (frozen at launch)

The plan (symlink walk, `.git` validation, tool resolution) is computed **once, when the
session starts** — the pi process launch for a normal run — and is frozen for the session.
There is no TTL and no re-planning: symlinks or `.git` edits the agent makes later have no
effect until a new session (a new pi launch, `/new`, `/resume`, reload) computes a new plan.
That is also why the agent cannot grant itself access: it can only change the project after
the walk. The plan is published process-wide, so every actor in this process that launches
sandboxed commands with Outside project = Off (foreground bash, task-runtime bash, background
tasks, subagent launches) applies the same frozen mounts, cleared environment and private PID
namespace, or **fails closed**: a failed plan, a plan for another project, a missing plan while a
policy is configured, or a non-Linux backend refuses the launch. A subagent child therefore starts
with only the allowlisted environment; add the variables it needs to `env.allow` knowingly.
The policy file must not lie inside the project, a writable root of **any active profile** (git dirs, the
persistent cache directory, the harness runtime directories, home when a profile has Outside project = Write) or a temp
directory; such a policy is refused. Each controller owns its own published plan: disposing one never clears the plan
another live controller still owns (the most recently published live plan is in force).

**Git dir write-deny set.** For every writable git dir (the in-project `.git`, and a linked worktree's git dir and
common dir) the planner computes one deny set: `hooks/`, `config`, `config.worktree`, `info/attributes`,
`commondir`, `gitdir`, `objects/info/alternates` and `http-alternates`, `modules/*/{hooks,config,…}` (submodule git
dirs, recursively) and every *other* `worktrees/*` entry. Refs, objects, index, logs, packed-refs and `HEAD` of the
agent's own worktree stay writable. The same set is mounted read-only in bubblewrap and enforced by the in-process
`write`/`edit` tools (`readConfinement.denyWrite`). Absent entries are blocked too: the sandbox mounts an empty
read-only node. Every such placeholder is **written at planning time** (never by the sandbox at launch), so the plan hash is
the same before and after the first launch and the placeholders are ordinary readable files: empty files for `config`,
`config.worktree`, `info/attributes`, the alternates files and `gitdir`, an empty directory for an absent `hooks`
(a `/dev/null` mount remains only as the last resort when the host path cannot be written), and `.` for an absent
`commondir` (an empty one breaks git; `.` is what git accepts for a main repository or submodule git dir). They are then
mounted read-only, so they can neither be created nor redirected. Planning creates them with non-following operations: a
symbolic link anywhere inside a git dir's protected paths makes the plan **fail closed** (recorded in `denied`) instead of
being followed or mounted over. At launch an existing
`objects/info/alternates` is validated: each entry must be a git object directory and pass the deny rules, otherwise the
plan **fails closed** (the refusal is recorded in `denied` and in the status entry's `reason`).

**Mount anchors.** A read-only overlay under a writable directory is not enough: the directory could be renamed away and
rebuilt without the overlay. Every directory between a writable region's root and a write-denied entry (or a nested
writable git dir) is therefore bound onto itself, which makes it a mount point: `mv`, `rmdir` and `rm -rf` of it fail
with EBUSY (e.g. the in-project `.git`, `worktrees`, `modules`, `modules/*`, `info`, `objects`, `objects/info`). The set
is computed from the deny list (`plan.denyRemove`), not from a fixed list. The in-process tools refuse to remove or move
those directories, or any directory containing one, the same way. Files a region legitimately keeps writable (HEAD,
index, refs) can still be deleted by `rm -rf`; the overlays and anchors stay.

**The `.git` file of a linked worktree or submodule folder.** The file is mounted read-only (write, unlink and rename fail;
the project root, a mount point, anchors it) and the in-process tools refuse the same, so the redirect cannot change under a
running session. At planning time a `gitdir:` target (and a `commondir`) that lies inside, or around, the project or any other
writable root is refused: the plan **fails closed** and the refusal is recorded in `denied` and the status entry's `reason`.
That closes redirecting git to an agent-made directory; it does not make a host git run inside a writable folder safe (see the
recommendation below). `git worktree repair`/`move` and `git submodule absorbgitdirs` rewrite that file and need a host run.

**Deny entries under a `.git` file.** Nothing can be created below a `.git` file, so a rule such as the packaged
`.git/hooks` is mapped onto the same relative path in the git dir(s) the file resolves to (the worktree's admin dir and the
common dir, or the submodule's git dir), for the kernel mounts and for the in-process tools alike.

**Not guarded.** Nested repositories and new submodules that the agent creates inside the writable project are not
covered: their `config`, `hooks` and `.git` are ordinary writable files, and a host git run there can execute them.

**Recommendation for hosts.** Never run git inside a folder an agent can write. Integrate with
`git fetch <worktree> <branch>` from a trusted repository, and inspect with
`git -c core.hooksPath=/dev/null -c core.fsmonitor=false …` (add `-c protocol.ext.allow=never` as needed).

The sandbox also gets `--clearenv` (only `env.allow` names, taken from the launching process when each
command is built, reach the child; the task runtime's own env passthrough is filtered the same way),
`--unshare-pid` (the child cannot signal host processes; `/proc` is not mounted) and `--new-session`.
Approved tools whose real path is under a writable root are refused (the agent could replace them).

### Audit and machine-readable status

Each status change is appended to the session as a custom entry with
**`customType: "pi-better-sandbox-read-confinement"`** (exported as `READ_CONFINEMENT_ENTRY`). It is written
when the session's permissions are published, so it exists before the first prompt; a remote parent
can read it with RPC `get_entries` and refuse to prompt unless `active` is `true`.

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `active` | `true` only while the frozen plan is in force: Linux bubblewrap, Main profile enabled, Outside project = Off. `false` when a plan failed or is not in force (then `reason` says why). |
| `profile` | `"main"` (the permission profile the plan applies to). |
| `policyHash` | SHA-256 of the parsed policy (whitespace and key order independent). |
| `planHash` | SHA-256 of the audit. |
| `hash`, `audit` | (active only) legacy alias of `planHash`, and the full audit: binds with reasons, denied and skipped entries with reasons, symlink mounts, the synthetic `PATH`, the policy source and hash. |
| `reason` | (inactive only) why the plan is not in force or failed. |

An entry is appended once per change, not per announcement. A session with no configured policy
writes no entry. `/sandbox diagnostics confinement` prints the latest plan. Secret values are never recorded.

### Verify a workspace interactively

The owner can check what a confined worker can read and write from a separate pi in the same working folder.
`!bash` and `!!` commands already run through the sandboxed bash, so they experience the identical confinement.

1. Start pi in the workspace's working folder with the workspace's agent dir (no other setup; the policy location
   comes from that agent dir's settings):

   ```sh
   cd <working-folder>
   PI_CODING_AGENT_DIR=<agent-dir> pi
   ```

   Main must be enabled with Outside project = Off in that agent dir (the same permissions the worker uses).
2. `/sandbox workspace` (also the first block of `/sandbox diagnostics confinement`) shows the working folder, agent
   dir, policy path, `policyHash` and `planHash`, and whether the confinement is `active`.
3. `/sandbox check <path>` reports read, write and exec for a path with the reason (the mount that grants it, or
   "not mounted"). It uses the same evaluator as the in-process tools, whose allow set is the kernel mount plan. Relative
   paths resolve against the working folder; symlinks are decided on their realpath. `/tmp` is the sandbox's private,
   empty tmpfs: writable scratch, and the host's `/tmp` files are not visible.
4. Probe with `!` commands:
   - `!cat <another-project>/file` → `No such file or directory`
   - `!echo x > <outside-the-working-folder>/file` → fails (a `readOnly` folder is readable, not writable)
   - `!curl <host>` or any network use → fails while Network access is Off
5. Compare the hashes with the worker: a remote subagent's `subagent_result` carries a
   `Remote workspace (<target>): cwd … · agent dir … · policyHash … · planHash …` line (also in
   `remote.sandbox` and `remote-sandbox.json` of the run). Equal `policyHash` means the same policy; equal `planHash`
   means the same computed mounts. A `planHash` depends on the state of the working folder, but the placeholders for
   protected entries are written when the plan is computed, so a session's hash is stable from its first launch.

### Example policy (illustrative; adapt to your environment)

```json
{
  "version": 1,
  "limits": { "maxSymlinks": 500, "maxDepth": 6 },
  "walkSkipDirNames": ["node_modules"],
  "deny": { "paths": ["~/private", "${XDG_DATA_HOME}/keyrings"] },
  "tools": {
    "approved": [
      "sh", "cat", "ls", "grep", "git",
      { "name": "mytool", "config": ["~/.config/mytool"], "cache": ["~/.cache/mytool"], "cachePersistent": true, "install": "prefix" }
    ]
  },
  "secretDetector": { "patterns": ["(?i)client[_-]?secret"] },
  "caches": { "persistentDir": "${XDG_STATE_HOME}/pi-agent-caches" }
}
```

### Limits

- The system runtime roots (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`) are bound **whole**, so
  anything installed there is readable, not just approved tools. Approval controls `PATH`
  and what is bound *outside* those roots.
- A confined shell can still run any executable it can read by absolute path, for example one under `/usr`.
- Libraries a tool loads with `dlopen` are not visible to the loader listing; add them with `bind`.
- A symlink created after the plan was computed is not mounted until a new session starts (see "frozen at launch"). A project symlink present at launch to a non-denied path is still followed: use `deny.paths` and `walkSkipDirNames` for what must never be reachable.
- Git dirs are writable except the deny set above; common-dir `objects` stay writable because commits need them.
  A `hooks` directory created on the host after the plan was computed makes the next launch fail (the frozen plan expects a file there); start a new session.
- Planning is synchronous and bounded (`maxWalkEntries`, `maxWalkMs`); it runs at session start.
- Secret detection is pattern-based; it reduces, not eliminates, the chance that a bound config holds a secret.
- The synthetic `PATH` only constrains lookups by name; this mode is a read boundary, not a command allowlist.
- bubblewrap is a mount/namespace boundary, not a resource or syscall policy: it sets no CPU, memory, disk, process-count
  or time limits, and it shares the IPC namespace, kernel keyring, hostname and clock with the host. See
  [What bubblewrap can and cannot limit](#what-bubblewrap-can-and-cannot-limit) for the full table and mitigations.

### What bubblewrap can and cannot limit

Measured, not assumed: `test/bubblewrap-limits.test.ts` launches real bubblewrap commands built by the package's own
planner and argv builder (Main profile, Outside project = Off, Network Off, commands On, read confinement active; two
extra launches with Network On and with a policy that adds a `readOnly` folder and an approved tool with `config`) and
asserts each *Limited* row. *Not limited* rows are asserted as documented expectations so this table cannot go stale.
Tested with bubblewrap 0.12 using unprivileged user namespaces. "Limited" means the kernel refuses the operation
inside the sandbox; the table lists what remains and what to add **outside** bubblewrap. The mitigations are
recommendations only; none is implemented by this package.

| Area | Result | Mechanism / observed | Recommended mitigation outside bubblewrap |
| --- | --- | --- | --- |
| Read a file outside the allow set | **Limited** | Not mounted: `ENOENT`. Reachable only through project symlinks (followed at launch), `readOnly`, approved tool `bind`/`config`. | Keep `deny.paths` and `walkSkipDirNames` for anything a symlink must never reach. |
| Write outside writable roots | **Limited** | `/usr` and the synthetic root are read-only (`EROFS`); other paths do not exist. Symlink-reachable and `readOnly` folders are read-only. | None needed. |
| Private `/tmp` | **Limited** | Fresh tmpfs; host `/tmp` entries are invisible and sandbox writes never reach the host. | Size cap: see Resources. |
| Exec by absolute path | **Not limited** | Any binary readable under the bound runtime roots (`/usr`, `/bin`, ...) runs, as does any executable in a writable root or read-only mount (no `noexec`). | Command allowlisting needs a separate layer (seccomp filter, or wrapper that execs only approved binaries). |
| Exec by name (`PATH`) | **Limited** | Synthetic `PATH` holds only approved tools; other names fail `ENOENT`/exit 127. It is a lookup convenience, not a boundary. | Do not rely on it for security. |
| Network, Network Off | **Limited** | `--unshare-net`: own namespace with only its own loopback. TCP/UDP to host loopback and LAN, DNS, and *abstract* unix sockets (host D-Bus, X11) are unreachable. Covers tools with their own network stack, since it is the namespace, not a library. | None needed. |
| Network, Network On | **Not limited** | Full host network namespace: loopback services, LAN, abstract unix sockets, raw egress. Names do not resolve because `/etc` is not mounted (IP literals work); a `readOnly` mount of resolver files would enable DNS. | Egress filtering belongs to the host (nftables/cgroup-matched rules, network namespace with a proxy). Prefer Network Off. |
| Filesystem unix sockets (daemons, D-Bus session bus, ssh-agent) | **Partially** | A socket path that is not mounted is `ENOENT`, and the usual locating variables are cleared. A socket under any mounted path, including the project and `readOnly` mounts (read-only does not stop `connect`), is connectable even with Network Off. | Never mount or keep sockets inside the project or in `readOnly` folders; run daemons outside those paths. |
| Process visibility and signals | **Limited** | `--unshare-pid`, no `/proc`: host pids are `ESRCH` for `kill`; `ptrace` of host pids is `ESRCH`. | None needed. |
| `ptrace` inside | **Not limited** | Only processes inside the sandbox are reachable (host pids are not). | seccomp can deny it if wanted. |
| Devices | **Limited** | `--dev`: minimal set (`null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx`, `pts`, `shm`, std fds). GPU (`kfd`, `dri`), DRM, disks, `fuse`, `kvm`, `mem` are absent. | None needed. |
| Controlling tty | **Limited** | `--new-session`: `/dev/tty` open fails `ENXIO`. | None needed. |
| setuid, capabilities | **Limited** | Same uid, `no_new_privs` set, effective capabilities empty. | None needed. |
| New user namespaces inside | **Not limited** | `unshare(CLONE_NEWUSER)` succeeds; it grants nothing on the host but exposes kernel attack surface. | seccomp denying `unshare`/`clone` namespace flags, or the host sysctl that disables unprivileged user namespaces for the launcher's descendants. |
| IPC (SysV shm, POSIX mq) | **Not limited** | No `--unshare-ipc`: host segments and queues are attachable by id/name subject to normal permissions. | Launch with an IPC namespace (`unshare --ipc`, systemd `PrivateIPC=`). |
| Kernel keyring (`keyctl`) | **Not limited** | Keys of the calling user are readable by id as permissions allow. | seccomp denying `keyctl`/`add_key`/`request_key`; or a separate uid or session keyring per launch. |
| Resources: CPU, memory, processes, wall time | **Not limited** | No cgroups, no rlimits set: limits are inherited from the launcher unchanged. A fork bomb or busy loop affects the host; the pid namespace does not cap counts. | `systemd-run --user -p MemoryMax= -p CPUQuota= -p TasksMax=` (cgroups), `ulimit`/`prlimit`, and a timeout on every launch. |
| Resources: disk | **Not limited** | Writable roots are the host filesystem (project, git dirs, caches); private `/tmp` is a tmpfs with the kernel default size. | Filesystem quotas or a size-capped scratch mount; a `tmpfs` size option for private `/tmp`; `RLIMIT_FSIZE`. |
| Time, hostname, uid | **Not limited** | No time/UTS namespace; uid is the caller's. | Observable only; `unshare --uts` hides the hostname if wanted. |
| Environment | **Limited** | `--clearenv`: only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TERM`, `TMPDIR`, `TZ` and `env.allow` names. Anything in `env.allow` is deliberately visible. | Keep `env.allow` minimal. |
| Inherited file descriptors | **Not limited** | bubblewrap does not close descriptors above 2: an fd the launcher leaves open is usable (even a file outside the allow set). | Launcher must open children with close-on-exec and an explicit fd table (`stdio` only). |
| Clipboard, X11, Wayland | **Limited** | Filesystem sockets are not mounted, the host `/tmp` is hidden, abstract sockets (X11) need Network On, and the display variables are cleared. With Network On an abstract X11 socket is reachable. | Keep Network Off for untrusted work; use a separate display/session for sandboxed GUI work. |
| Approved tool's config | **Partially** | Every file in an approved config path is readable by the whole sandbox, not just by the tool. The secret detector refuses a config entry whose files match a pattern (the entry is not bound). | List single files rather than directories; keep secrets out of approved config. |

Notes:

- *Fail-safe reading*: for unlisted paths the observable error is `ENOENT`, so a refused path cannot be told apart from a
  missing one.
- *Foreign mount points*: bubblewrap cannot withdraw access it did not remove; anything you add with `readOnly`, `bind`,
  `config`, the project or a symlink is fully reachable, including executables and sockets there.
- *Resource limits* are the largest gap. Wrap the launcher in a cgroup (for example a transient `systemd-run` scope or
  service) and a timeout; this is a host decision, not a package setting.
- Probes and the observed values behind this table are re-checked by the test file; set
  `PI_SANDBOX_LIMITS_DUMP=1` to print them.

## Local Permission Diagnostics

Opt in with `/sandbox diagnostics on`. Saved in global `settings.json`, this
collects redacted local observations from foreground guards, guarded file
operations, and background launch preflight, plus redacted worker reports.
Collection is off by default and never changes permissions or uploads data.

- `/sandbox diagnostics status`: show collection state and retained evidence.
- `/sandbox diagnostics summary`: group denials and observed recoveries.
- `/sandbox diagnostics export`: write a redacted local JSON export for sharing.
- `/sandbox diagnostics off`: stop collection without deleting retained evidence.

The bounded journal lives under `<agent-dir>/diagnostics/sandbox`: at most 2,000
observations, 1 MiB, and 30 days. Records contain resource categories, package
version, platform/backend, and installation-keyed fingerprints, not raw commands,
paths, file contents, or output. Export excludes the fingerprint key.

Confirmed policy refusals are separate from `EACCES`/`EPERM` observations, which
do not prove the sandbox caused the failure. Confined workers relay fixed,
redacted reports to their parent, which records them as `agent-reported`; workers
never receive write access to the global journal. Worker retry correlations stay
within the reporting worker. Arbitrary shell output and nonzero exits are not
classified. Recovery is an observed success, not authorization for broader
permissions or remote access. Summaries disclose journal gaps and retention
losses; collection failures that prevent a write may not persist.

Storage contention is bounded and never overrides a writer's lock by age. If an
abruptly terminated collector leaves `events.jsonl.lock`, collection warns and
stops writing. Stop every collector before manually removing that empty lock
directory. Existing evidence is retained; enforcement is unaffected.

## Commands

```text
/sandbox                     open the permission table (text status outside TUI)
/sandbox on                  enable protection for operations started from now on
/sandbox off                 turn protection off for this session (interactive confirmation)
/sandbox default on          persist opt-in and enable it now
/sandbox default off         persist opt-out (interactive confirmation)
/sandbox deny list           show the write-denied paths
/sandbox deny add <path>     stop allowing writes to a path
/sandbox deny remove <path>  allow writes to a path again
/sandbox deny reset          drop your changes and restore the packaged defaults
/sandbox rules               open the write-denied paths editor
/sandbox workspace           show the working folder, agent dir, policy path, policyHash and planHash
/sandbox check <path>        read / write / exec decision and reason for a path (same evaluator as the tools)
```

Sandbox status is not displayed in the footer. Use `/sandbox` to inspect the
permission table, or the text status report outside the TUI. Explicitly enabled
sessions still warn when protection cannot be applied. Status reports describe
what the runtime actually resolved, including the backend and executable, never
what was merely configured.

`/sandbox off` and `/sandbox default off` need interactive confirmation and are
refused outright when there is no interactive UI. There is no tool for changing
sandbox state or its rules, so the model cannot change confinement or edit the
paths it is confined away from.

## Write-denied paths

Three paths are denied out of the box — `.git/hooks`, `.env`, and `.env.local`,
relative to whichever project you are in. They live in the package's source, so
installing writes no settings file anywhere.

Rules are paths, not patterns. Write one of three ways:

| You type            | It means                                            |
| ------------------- | --------------------------------------------------- |
| `build/artifacts`   | that path inside **every** project you open          |
| `~/.aws`            | that path under your home directory                  |
| `/etc/hosts`        | exactly that path                                     |

A relative rule is stored as a template and resolved against each project, which
is why one global rule set is enough — there is no per-project database. Lists
and the editor always show the canonical absolute path a rule currently resolves
to. A directory denies its whole subtree; a file denies that exact file, whether
or not it exists yet.

`/sandbox rules` opens a compact keyboard-driven editor over the same rules:
arrow keys to move, enter to remove the highlighted rule, or pick *Add* to type
a new one and *Restore the packaged defaults* to start over. The slash commands
and the editor are two front ends over one validation and persistence module, so
they cannot disagree.

Changes take effect for shell commands and file mutations started after them.
A command already running keeps the rules it launched with.

### Where your rules live

Your changes are written to `~/.pi/agent/settings.json` (under
`$PI_CODING_AGENT_DIR` when you set one), in the `piBetterHarness` namespace:

```json
{
  "piBetterHarness": {
    "sandboxDenyRules": {
      "version": 1,
      "denyWrite": [".env", ".env.local", ".git/hooks", "build/artifacts"]
    }
  }
}
```

The override key appears the first time you add or remove a rule, or when an
existing legacy override is migrated; installation alone writes nothing.
`/sandbox deny reset` sets `sandboxDenyRules` to `null` and puts the defaults
shipped by the installed package version back in force. The sentinel prevents a
retained legacy file from being imported again and does not store a stale copy
of the packaged defaults. Other Pi and harness settings remain unchanged.

If the file cannot be read, the packaged defaults stay in force, the problem is
reported, and rule changes are refused until you fix the override or reset it —
a typo is never quietly turned into a lost rule set. If the whole `settings.json`
file is invalid JSON, repair it by hand first; a deny reset cannot discard other
settings to repair the file.

### What is refused, and why

- **Empty entries and patterns** (`*.pem`, `src/**/x`) — rules are concrete
  paths; a pattern would silently match nothing.
- **Duplicates**, however they are spelled: `.env`, `./.env`, the absolute path,
  or a symlink pointing at the same file all resolve to one canonical path.
- **Overlaps**, in both directions. A path already inside a denied directory
  would change nothing; a directory that would swallow a narrower rule names
  that rule so you can remove it deliberately instead of losing it silently.
- **A rule that contains the project root** — `.`, `..`, `/`, or `~` when your
  project lives under home. Denying it would make every write in the project
  fail. `/sandbox off` is the thing you actually want there.

A global rule that turns out to contain the root of a *different* project stays
in your rule set but is held out in that project, with a message saying so.

### Upgrading

Sandbox defaults now share global `settings.json` under `piBetterHarness`:
`sandbox` stores version 1 activation preferences, `sandboxPermissions` stores
version 1 permission profiles, and `sandboxDenyRules` stores the rule override.
On first read of a missing key, the corresponding validated legacy file in
`extensions/` is imported: `pi-better-sandbox-preferences.json`,
`pi-better-sandbox-permissions.json`, or `pi-better-sandbox.json`. Legacy files
are left untouched. An existing global key always wins, including the deny-rule
`null` sentinel; invalid global values are reported, not replaced by legacy data.
Updates use locked atomic replacement and preserve unrelated Pi settings and
other harness keys.

Fresh configurations now start all three sandbox switches Off. Saved enabled
profiles stay enabled, and session choices still restore on resume, fork, reload,
and tree navigation. No saved permissions are reset by the new activation default.
Standalone subagents also default to unconfined without published settings;
`sandbox:true` still requests kernel confinement, and `sandbox:false` cannot
bypass a human-enabled Subagents profile.

A version 1 global or session permission record without `background` inherits a
copy of its existing Main profile, including its switch and every permission.
Migration preserves the existing behavior and does not link future edits.
Saving defaults or a session edit writes the separate `background` profile.
An explicitly malformed Background tasks profile fails closed; it is never
replaced by Main or fresh defaults.

A saved permission profile keeps its values: a saved `read-write` is now shown as Write & delete, and a saved
Subagents Outside project = Read stays Read. Only a fresh configuration, or
**Ctrl+S** after you choose Write, uses the new Subagents default. To
adopt it, open `/sandbox`, set Subagents → Outside project to Write, and save.

`~/.pi/agent/sandbox.json` (`filesystem.allowWrite`, `allowRead`,
`network.allowedDomains`) is the format of Pi's example sandbox extension. This
package never reads it, and it has no effect on the harness.

## Lifecycle

All three sandbox switches are inactive in fresh settings. Permission edits, including
Sandbox switches and `/sandbox on|off`, auto-persist as Pi custom entries on the
current session branch, not as global defaults. Resume, fork, reload and session
tree navigation restore the latest policy on the active branch. A branch with
no permission entry and a new session inherit saved global settings. Invalid
persisted session policy fails closed rather than falling back to defaults.
Ctrl+S writes all three profiles to `piBetterHarness.sandboxPermissions` in global
`settings.json`. When no saved profile exists, the Main switch inherits the
activation preference from `piBetterHarness.sandbox`, including migrated legacy
activation preferences. Background tasks initially inherits that Main profile.
`/sandbox default on|off` remains available and updates only Main's saved switch.
After migration, Main changes never change Background tasks. Enable Background
tasks while Main is Off to confine new local background launches independently.
Running tasks keep their launch policy. The Subagents column and Tools section
remain independent and unchanged.
Failed default saves leave the current session's edits intact. Write-deny rules
retain their global persistence in `piBetterHarness.sandboxDenyRules` through
`/sandbox deny` and `/sandbox rules`. Session entries and runtime control-plane
protections are unchanged.

Toggles apply to operations launched after the change. A command already running
keeps the policy it launched with.

## Fail-closed behaviour

While the sandbox is explicitly or persistently enabled and a backend cannot be
applied, protected commands and file mutations are **blocked** rather than run
unprotected:

- No backend on this platform (`unavailable`).
- A launch directory too broad to confine — `/` or your home directory
  (`failed`). Relaunch Pi from the directory you are actually working in, or
  turn the sandbox off on purpose.
- A backend that was selected but failed to start. It is never retried directly.

## Paths, symlinks and denied files

The launch directory is canonicalized at session start, so reaching a project
through a symlink does not widen what is writable. Denied entries are
canonicalized the same way: a directory denies its whole subtree, a file denies
that exact file, and an alias pointing at a denied file is denied too.

## Platform support

| Platform | Backend                     | Requirement                  |
| -------- | --------------------------- | ---------------------------- |
| macOS    | Seatbelt (`sandbox-exec`)   | ships with the OS            |
| Linux    | Bubblewrap (`bwrap`)        | install `bubblewrap`         |
| Other    | none                        | protected commands are blocked |

A detached subagent gets a private session/temp directory for Pi's runtime
state. This directory stays writable even with Outside project set to Read or
Off; other runs' state and the parent's launch metadata are not included.
Read access to system executable and library directories, device I/O, and root
directory metadata/listing remains available so a process can start. On macOS,
the allowance excludes the broad `/System/Volumes` tree.

Linux currently refuses combinations it cannot safely mount: hiding the
project or credential files inside a visible whole-filesystem bind, writing
credential stores under a read-only outside root, a writable outside root
(Write & delete) with protected paths, and Project files = Write. These launch errors preserve the selected restrictions.
The macOS permission combinations are covered by real-kernel tests; Linux
mount behavior requires a Linux runner with Bubblewrap and user namespaces.

### macOS setuid executable limitation

Seatbelt-sandboxed processes cannot execute setuid/setgid binaries, even with
an `(allow default)` profile. On the verified host, `/bin/ps` and `/usr/bin/top`
are setuid-root binaries. A shell attempting to run `/bin/ps` reports
`Operation not permitted` and exits 126. This is an OS-level execution
restriction, not a harness command deny rule, a filesystem permission failure,
or evidence that Run applications is Off.

Read-only reproduction (verified on 2026-10-04):

```sh
ls -l /bin/ps /usr/bin/top
/usr/bin/sandbox-exec -p '(version 1) (allow default)' \
  /bin/bash -c '/bin/ps -p $$ -o pid,ppid,comm'
```

The second command fails with `/bin/bash: /bin/ps: Operation not permitted`
and exit 126; the same `ps` query outside Seatbelt succeeds. Launching `ps`
directly through `sandbox-exec` instead reports `execvp()` failure and exit 71.
Changing the requested output fields or adding a profile allowance for `ps`
does not remove this limitation.

When process inspection is a prerequisite for safe work, do not interpret the
denial as an empty process list. Hold the dependent operation until an
authorized coordinator or environment custodian supplies a fresh snapshot
and explicit ownership handoff from outside the task sandbox. Prefer
`pid,ppid,pgid,lstart,comm` over full command arguments, which may expose
secrets. Do not disable the sandbox or modify/copy privileged executables to
work around the denial. A trusted process-inspection adapter would require
separate implementation; this package does not currently provide one.

See the [session evidence](../../docs/sandbox-session-validation.md#macos-process-inspection-follow-up)
and [documented setuid/setgid limitation](https://github.com/navikt/cplt/blob/main/docs/known-impacts.md).

## For other extensions

The effective policy is published as a frozen snapshot on Pi's extension event
bus. It carries policy and status only — never a way to run anything.

The top-level fields still describe Main. The additive `background` field
contains the independently computed local Background tasks launch policy:

```ts
type BackgroundSandboxPolicy = {
  state: "enabled" | "disabled" | "unavailable" | "failed";
  writableRoot: string | undefined;
  denyWrite: readonly string[];
  reason: string;
  permissions?: Readonly<SandboxPermissionProfile>;
};
```

`permissions` has the same shape as the existing foreground profile: `enabled`,
`projectFiles`, `outsideProject`, `storedCredentials`, `commands`, `shell`,
`commandTimeoutSeconds`, `network`, and `processAccess`. The additive `shell`
and `commandTimeoutSeconds` fields default to `true` and `null` for legacy
profiles; the settings envelope remains version 1. It is present after settings load. `background`, its
`denyWrite` array, and its permission object are frozen copies. Background
checks the backend, project root, and runtime-path safety independently of Main;
Main Off does not suppress a requested Background sandbox. `inactive` is
published as `disabled`. Invalid loaded policy fails both profiles closed.

The existing `pi-better-sandbox:policy-request` channel republishes both profiles.
Consumers should snapshot `policy.background` at launch. Consumers must support the new restrictions before applying them. Incompatible
older subagent or background consumers are rejected when a restrictive policy
would otherwise be dropped.

```ts
import {
  FOREGROUND_SANDBOX_POLICY_CHANNEL,
  FOREGROUND_SANDBOX_POLICY_REQUEST_CHANNEL,
  type ForegroundSandboxPolicyEvent,
} from "pi-better-sandbox";

pi.events.on(FOREGROUND_SANDBOX_POLICY_CHANNEL, (policy) => {
  // Snapshot it at launch time; a running operation keeps its launch policy.
});

// Loaded late and missed the last publication? Ask for the current one.
pi.events.emit(FOREGROUND_SANDBOX_POLICY_REQUEST_CHANNEL, undefined);
```
