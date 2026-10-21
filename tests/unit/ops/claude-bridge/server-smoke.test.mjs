import { cp, mkdir, symlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SERVER_PATH, createFixture, startServer, parsedToolPayload } from './harness.mjs';

describe('Claude Bridge server smoke', () => {
  let fixture;
  beforeEach(async () => { fixture = await createFixture(); });
  afterEach(async () => { await fixture.cleanup(); });

  it('initializes with the authority instructions and lists the bridge tools', async () => {
    const client = await startServer(fixture);
    const init = await client.request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'claude-bridge-test', version: '1.0.0' } });
    expect(init.result.instructions).toBe('Use Claude Bridge only after an explicit operator request to invoke Claude. Claude holds corrective authority delegated by the operator: reviews may alter the submitted work; a run that finishes carries a binding verdict and a run that errors records a blocked verdict; task and continuation calls are refused while a verdict is open or a record failure is latched. Read operator_readback to the operator verbatim. Poll claude_result until completion.');
    const list = await client.request('tools/list');
    const names = list.result.tools.map((tool) => tool.name).sort();
    expect(names).toEqual(['claude_bridge_status', 'claude_continue', 'claude_result', 'claude_review', 'claude_task', 'claude_verdict']);
    const review = list.result.tools.find((tool) => tool.name === 'claude_review');
    expect(review.annotations).toEqual({ readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });
    // Codex can choose only Fable 5.1 or Opus 5.5, and effort high or above.
    for (const name of ['claude_review', 'claude_task']) {
      const { properties } = list.result.tools.find((tool) => tool.name === name).inputSchema;
      expect(properties.model.enum, name).toEqual(['claude-fable-5-1', 'claude-opus-5-5']);
      expect(properties.model.default, name).toBe('claude-fable-5-1');
      expect(properties.effort.enum, name).toEqual(['high', 'xhigh', 'max']);
      expect(properties.effort.default, name).toBe('high');
    }
    expect(JSON.stringify(list.result)).not.toMatch(/haiku|sonnet/i);
    expect(JSON.stringify(init.result)).not.toMatch(/haiku|sonnet/i);
  });

  it('starts when launched through a linked directory, as /opt/claude-bridge/current is', async () => {
    const versioned = join(fixture.fixtureRoot, 'install', '0.5.0');
    await mkdir(versioned, { recursive: true });
    await cp(dirname(SERVER_PATH), join(versioned, 'mcp'), { recursive: true });
    await symlink(versioned, join(fixture.fixtureRoot, 'install', 'current'));
    const client = await startServer(fixture, {}, ['--stdio'], join(fixture.fixtureRoot, 'install', 'current', 'mcp', 'server.mjs'));
    const list = await client.request('tools/list');
    expect(list.result.tools.map((tool) => tool.name)).toContain('claude_review');
  });

  it('reports status through the fake provider', async () => {
    const client = await startServer(fixture);
    const response = await client.callTool('claude_bridge_status', { cwd: fixture.workspace });
    const payload = parsedToolPayload(response);
    expect(payload.ok).toBe(true);
    expect(payload.version).toContain('Claude Code');
    expect(payload.protection).toBe('unprotected');
  });
});
