---
schema: pi-agent/v1
kind: role
id: role.acceptance-foreground
name: Acceptance Foreground
description: No model preference, so the run inherits the foreground model. An unavailable preferred model would block instead.
defaults:
  effort: low
  tier: unmapped-acceptance
---
Reply with the single word DONE.
