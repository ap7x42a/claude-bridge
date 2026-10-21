// tests/unit/ops/claude-bridge/manifest.test.mjs
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('plugin manifest and words', () => {
  it('declares 0.5.0 and launches the protected server', async () => {
    const pluginText = await readFile('plugins/claude-bridge/.codex-plugin/plugin.json', 'utf8');
    const plugin = JSON.parse(pluginText);
    expect(plugin.version).toBe('0.5.0');
    expect(plugin.description).toMatch(/corrective authority/);
    expect(plugin.interface.defaultPrompt).toEqual(['Ask Claude Code for an adversarial review of the current changes.']);
    expect(pluginText).not.toMatch(/read-only/);
    const mcp = JSON.parse(await readFile('plugins/claude-bridge/.mcp.json', 'utf8'));
    expect(mcp.mcpServers.claude_bridge.command).toBe('/usr/bin/node');
    expect(mcp.mcpServers.claude_bridge.args).toEqual(['/opt/claude-bridge/current/mcp/server.mjs', '--stdio']);
    const server = await readFile('plugins/claude-bridge/mcp/server.mjs', 'utf8');
    expect(server).toContain('const SERVER_VERSION = "0.5.0"');
  });
  it('runs every installed program with an absolute, root-owned interpreter', async () => {
    const firstLine = async (path) => (await readFile(path, 'utf8')).split('\n')[0];
    expect(await firstLine('plugins/claude-bridge/bin/claude-bridge')).toBe('#!/usr/bin/node');
    expect(await firstLine('plugins/claude-bridge/mcp/server.mjs')).toBe('#!/usr/bin/node');
    expect(await firstLine('plugins/claude-bridge/mcp/state-cli.mjs')).toBe('#!/usr/bin/node');
    expect(await firstLine('plugins/claude-bridge/bin/install.sh')).toBe('#!/bin/bash');
    const cli = await readFile('plugins/claude-bridge/bin/claude-bridge', 'utf8');
    expect(cli).toContain('spawnSync("/usr/bin/getent"');
    expect(cli).not.toMatch(/spawnSync\("getent"/);
    const readme = await readFile('plugins/claude-bridge/README.md', 'utf8');
    expect(readme).not.toMatch(/^(?:sudo )?node /m);
    expect(readme).toContain('/usr/bin/node /opt/claude-bridge/current/bin/claude-bridge verify <repo>');
    expect(readme).toContain('sudo /usr/bin/node /opt/claude-bridge/current/bin/claude-bridge clear');
  });
  it('documents the fixed behaviour, not the pending fixes it replaced', async () => {
    const readme = await readFile('plugins/claude-bridge/README.md', 'utf8');
    const skill = await readFile('plugins/claude-bridge/skills/claude-bridge/SKILL.md', 'utf8');
    for (const text of [readme, skill]) {
      expect(text).not.toMatch(/pending fix/i);
      expect(text).not.toMatch(/records no verdict/);
    }
    for (const code of ['claude_error', 'error_max_turns', 'model_unavailable', 'nonzero_exit', 'stdout_limit', 'cancelled', 'malformed_json', 'invalid_envelope', 'spawn_failed']) {
      expect(readme).toContain(`\`${code}\``);
    }
    expect(readme).toContain('`verdict_parse: "run_error"`');
    expect(readme).toContain('--setting-sources ""');
    expect(readme).not.toContain('--safe-mode');
    expect(readme).toContain('forged owner clear in chain');
    expect(readme).toContain('owner clears: unverified (no public key)');
    expect(readme).toContain("chain, `head.json` and `open.json` together is not detected");
    expect(skill).toMatch(/run that ends in an error records a `blocked` verdict/);
    // The residuals the enforcement does not cover are named.
    expect(readme).toContain('another cache version or config path');
    expect(readme).toContain('reconfigure its own MCP servers in `~/.codex/config.toml`');
    expect(readme).toContain('an unregistered repository gets no turns ledger');
    expect(readme).toContain('another `CODEX_HOME` runs without the root-owned hooks');
    // Round-3: the staged install and the config-layer residual are documented.
    expect(readme).toContain('a refused install leaves the previous install live');
    expect(readme).toContain('installed_tree_');
    expect(readme).toContain('-c features.codex_hooks=false');
    expect(readme).toContain('state-cli.mjs context');
  });
  it('documents the model clamp: Fable 5.1, Opus 5.5 as the only fallback, effort high at the least', async () => {
    const readme = await readFile('plugins/claude-bridge/README.md', 'utf8');
    const skill = await readFile('plugins/claude-bridge/skills/claude-bridge/SKILL.md', 'utf8');
    for (const text of [readme, skill]) {
      expect(text).toContain('Codex cannot choose another model');
      expect(text).toContain('`model_not_allowed`');
      expect(text).not.toMatch(/Default model (?:`claude-opus-5`|Opus 5\.)/);
    }
    expect(readme).toContain('Every run, review or task, uses `claude-fable-5-1` (alias `fable`), falling back to `claude-opus-5-5` (alias `opus`) only');
    expect(readme).toContain('`low` and `medium` run as `high`, and the result then carries `effort_requested` beside `effort`');
    expect(readme).toContain('No variable chooses the model or the effort');
    expect(skill).toContain('Every run uses Fable 5.1 (`claude-fable-5-1`), falling back to Opus 5.5 (`claude-opus-5-5`) only.');
  });
  it('documents the authority in the bundled skill', async () => {
    const skill = await readFile('plugins/claude-bridge/skills/claude-bridge/SKILL.md', 'utf8');
    expect(skill).toMatch(/operator_readback/);
    expect(skill).toMatch(/corrective authority/);
    expect(skill).not.toMatch(/read-only/);
    expect(skill).toContain('5. If the bridge refuses with `verdict_record_failed_pending`, a review must rerun and record a verdict before task work continues.');
    expect(skill).toContain('A `blocked` verdict lifts only by a later verdict from Claude (a `clear`, or a `corrected` followed by readback) or by the owner.');

  });
});
