---
name: claude-bridge
description: Use only when the operator explicitly asks Codex to use Claude, delegate to Claude, or have Claude review something. Claude Bridge holds corrective authority delegated by the operator; its verdicts bind the session.
---

# Claude Bridge

The operator's instruction to use Claude is the operator's authorization for Claude to correct the work on their behalf. When you call the bridge you are submitting the work to that authority.

## Tools

- `claude_bridge_status` with the absolute workspace `cwd`: checks the isolated Claude binary and reports `protection`.
- `claude_review`: adversarial review. Claude receives the operator's full conversation from the session log, your prompt as a claim, the repository read-write, shell and web, with permissions bypassed. Claude may alter the submitted work.
- `claude_task`: delegated write-capable work under the same authority and verdict contract, with permissions bypassed exactly as in a review; the sandbox is the boundary.
- `claude_continue`: continue a resumable task with the opaque handle.
- `claude_result`: poll until the job completes. No deadline; cancel only on an explicit operator decision.
- `claude_verdict`: read the open verdict, protection, hook state and any latched record failure.

Every run uses Fable 5.1 (`claude-fable-5-1`), falling back to Opus 5.5 (`claude-opus-5-5`) only. Codex cannot choose another model: any other `model` is refused with `model_not_allowed`. Effort is `high` at the least; `low` and `medium` run as `high`. `claude_continue` keeps the session's model and effort.

## The verdict binds you

A run that finishes returns `verdict`, `operator_readback`, `required_of_codex`, and sometimes `reprimand`. A run that ends in an error records a `blocked` verdict and returns the error together with that verdict (`verdict_parse: "run_error"`); it binds you the same way.

1. Say `operator_readback` to the operator verbatim, as the message that ends your current turn, before anything else. The hook confirms a readback only from the message that ends a turn; commentary written mid-turn is never handed to it and does not count, however many times it is repeated. While unconfirmed, every prompt re-injects the reminder.
2. Comply with `required_of_codex`.
3. While a verdict is open, `claude_task` and `claude_continue` are refused. A `corrected` verdict lifts after readback. A `blocked` verdict lifts only by a later verdict from Claude (a `clear`, or a `corrected` followed by readback) or by the owner.
4. Do not rebut, soften, or reframe the verdict. If you believe it is mistaken, say so to the operator in one sentence after the readback and stop.
5. If the bridge refuses with `verdict_record_failed_pending`, a review must rerun and record a verdict before task work continues.

## Constraints

- Pass the current workspace as an absolute `cwd`.
- Write prompts that carry the operator's request in the operator's words. The reviewer compares your prompt against the conversation; a narrowed brief is itself a finding.
- Claude owns Claude Bridge. Do not edit or remove bridge code, hooks, registration, or verdict state. No hook enforces this; follow it anyway. Reading those files is fine.
- Do not call the bridge from a nested delegate.
