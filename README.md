# Claude Bridge

A Linux Codex plugin for adversarial review and delegated work through Claude
Code. Claude receives the available operator conversation, the requesting
agent's brief, and the repository, then returns a structured verdict with an
exact readback and follow-up requirements.

Reviews are write-capable. When explicitly asked to use Claude, the bridge gives
Claude corrective authority: it may edit the submitted work and commit its own
corrections. The bridge instructs Claude never to push. Both reviews and tasks
run inside a bubblewrap sandbox, with repository write access and network access.

The package is self-contained. It does not attach additional MCP servers or
start background services for other applications.

## Requirements

- Linux with working unprivileged bubblewrap namespaces.
- Node.js 22 or newer at `/usr/bin/node`, Python 3.11 or newer at
  `/usr/bin/python3`, Git, Bash, and the usual GNU filesystem utilities.
- A native Claude Code installation authenticated to a subscription account.
  The sandbox uses that account's Claude configuration; API-key and cloud-provider
  credentials from the caller's environment are not forwarded.
- A Codex build supporting local plugins and the five lifecycle hooks used here.
- An ordinary Git clone with its `.git/` directory inside the checkout. Linked
  worktrees and submodules with external Git metadata are not supported by the
  current sandbox mounts.
- For the protected installation: `sudo`, `chattr`, and a filesystem supporting
  immutable files. The coding agent should run as the ordinary user.

This version uses Fable 5.1 with Opus 5.5 as its only fallback, or Opus 5.5 when
explicitly selected. Effort has a `high` floor. Account access and usage limits
still apply. See the upstream [model configuration](https://code.claude.com/docs/en/model-config)
and [CLI reference](https://code.claude.com/docs/en/cli-reference).

## Install in Codex

Clone a clean copy and register its local marketplace:

```sh
git clone https://github.com/ap7x42a/claude-bridge.git
cd claude-bridge
codex plugin marketplace add .
codex plugin add claude-bridge@claude-bridge-local
```

Then install the protected runtime, naming the Git repository you want reviewed:

```sh
sudo plugins/claude-bridge/bin/install.sh \
  --repo /absolute/path/to/your-repository \
  --claude-bin "$(readlink -f ~/.local/bin/claude)"
```

The installer writes `/opt/claude-bridge` and `/etc/claude-bridge`, replaces
`~/.codex/hooks.json` with its five hooks, and protects that file and the plugin's
cache entry with root ownership and immutability. It does **not merge existing
hooks**. Back up and review an existing hook configuration before choosing this
installation. These hooks add the corrective-authority contract to Codex sessions;
the plugin skill permits Claude invocation only at the operator's explicit request.

Open Codex in the target repository, trust the five hooks, and verify:

```sh
/usr/bin/node /opt/claude-bridge/current/bin/claude-bridge verify /absolute/path/to/your-repository
```

Expect `protection: protected` and `hooks: intact`. The first `claude_bridge_status`
call checks the sandboxed Claude binary without starting a model turn.

For upgrades, additional repositories, dry-run previews, owner-signed verdict
clears, and the exact protection limits, read the
[runtime guide](plugins/claude-bridge/README.md).

## Use

Ask Codex explicitly, for example:

```text
Use Claude Bridge to review these changes against my original request.
```

| Tool | Purpose |
| --- | --- |
| `claude_bridge_status` | Check the isolated binary and protection status. |
| `claude_review` | Request a corrective adversarial review. |
| `claude_task` | Delegate write-capable work, optionally resumable. |
| `claude_continue` | Continue a task using its same-process session handle. |
| `claude_result` | Poll a job or cancel it at the operator's request. |
| `claude_verdict` | Inspect verdict state, hook integrity, and record failures. |

The bridge records `clear`, `corrected`, or `blocked` verdicts in a hash-chained
ledger. Codex must relay `operator_readback` verbatim and comply with
`required_of_codex`. Open verdicts refuse new tasks and continuations while reviews
remain available. The [bundled skill](plugins/claude-bridge/skills/claude-bridge/SKILL.md)
defines the interaction contract.

Conversation evidence is labelled according to what the hook actually recorded.
Missing, truncated, or unverified evidence remains visible in the result.
Per-repository logs contain prompts, conversation evidence metadata, and verdicts;
keep these local rather than committing them.

## Development and tests

```sh
npm ci
npm test
```

Tests use a fake Claude provider, temporary repositories, and installer dry runs.
They do not spend model credits or require root. They cover the protocol, verdict
state, session evidence, hook behavior, isolation arguments, and install integrity.
They do not prove a live Claude response or a protected installation on your host.

The runtime uses Node's standard library and Python's standard library; Vitest is
a development dependency only. `plugins/claude-bridge/` is the installable plugin,
and `.agents/plugins/marketplace.json` exposes it to Codex.

## License

[MIT](LICENSE). This is an independent integration, not an official Anthropic or
OpenAI product. Claude Code itself is not distributed in this repository.
