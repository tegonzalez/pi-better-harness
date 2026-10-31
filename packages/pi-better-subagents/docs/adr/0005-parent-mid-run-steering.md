# Parent mid-run steering

## Status

Accepted, 2026-10-30. Supersedes in part ADR 0004: the single steer request
file in the run directory is replaced by the per-run steer queue below. ADR
0004's timing policy (soft deadline, grace from delivery, ceiling, stuck wake)
is unchanged.

## Problem

A parent that learned something new while its child was running could only
stop the child and respawn it with an amended brief, discarding in-flight work,
or let it finish against stale instructions. The harness already delivered one
message into a running child, the soft-deadline wrap-up, but through a single
request file that held one request at a time and had no per-request receipt, so
a second request would overwrite the first and the parent could not say which
one arrived.

## Decision

- **Tool.** `subagent_steer` (`id`, `message`) amends one of the caller's own
  running children. It is refused, with the reason, for an unknown id, a
  foreign-session run or one whose ownership cannot be verified, a run that is
  not running (finished, or orphaned because its child process is gone), and an
  empty message. It returns at once with `queued` and a steer id; queueing is
  not delivery.
- **Queue.** Each run has a queue directory, `<runDir>/steer/`. Every request is
  its own file, written tmp-then-rename, named so that names sort in request
  order. A request id is queued at most once. The parent never deletes
  requests, so an undelivered request stays visible after the run ends.
- **Receipts.** When a request's message enters the child's conversation, the
  child's harness extension writes a receipt for that request next to it. A
  request without a receipt is pending. The receipt is written by the trusted
  Pi process; the child's confined tools cannot write the run directory, so
  they cannot forge one.
- **Delivery.** The child extension hands pending requests to Pi's steering
  queue in order, once each, and only while the agent is working. Pi delivers
  them as ordinary user messages at the next turn boundary, after the current
  tool call; a running tool call is never interrupted. A parent amendment is
  prefixed `Instruction amendment from your parent:`. Because it is a plain
  user message, it works for any provider or model.
- **One path.** The soft-deadline wrap-up of ADR 0004 is queued through the same
  queue, as a request of kind `deadline`; its grace still starts at its
  receipt.
- **Environment.** The child learns the queue location from
  `PI_SUBAGENT_STEER_DIR`, which replaces `PI_SUBAGENT_STEER_FILE`. Parent and
  child extension ship together, so no compatibility alias is kept.
- **Reporting.** `subagent_list`, `subagent_output`, and `subagent_result` show
  delivered and pending counts, pending ids, and the last delivery time; their
  status cursors change when a steer is queued and when one is delivered. A
  request still without a receipt when the run ends is reported as `NOT
  delivered` (no delivery receipt) on these surfaces and in the completion
  callback; it is never dropped silently.

## Consequences

- A parent can add or change requirements without losing the child's work.
- Delivery waits for the current tool call; a child inside a long command sees
  the amendment only after it.
- A print-mode child exits when its agent loop settles. A steer queued after
  that has no turn to enter; the tool warns when it can see this, and the run's
  surfaces report the request as not delivered.
- "No delivery receipt" is what the parent can prove. It is also reported when
  the message did arrive but another extension rewrote its text, because the
  receipt matches the exact text.
- Runs launched before this change used `PI_SUBAGENT_STEER_FILE` and
  `steer.json`; a parent with this change does not steer them. The env rename
  belongs in the release notes.
