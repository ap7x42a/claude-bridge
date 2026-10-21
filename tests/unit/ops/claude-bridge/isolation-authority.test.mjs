// tests/unit/ops/claude-bridge/isolation-authority.test.mjs
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, rm, symlink, writeFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { prepareBridgeIsolationLayout, wrapIsolatedCommand, cleanupIsolationLayout, resolveClaudeBin } from '../../../../plugins/claude-bridge/mcp/isolation.mjs';

describe('isolation for the adversarial profile', () => {
  let root; let repo; let layout; let bwrap;
  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'bridge-iso-')));
    repo = join(root, 'repo');
    await mkdir(repo, { recursive: true });
    await writeFile(join(repo, '.env'), 'SECRET=1\n');
    bwrap = join(root, 'bwrap'); await writeFile(bwrap, '#!/bin/sh\nexit 0\n');
    layout = prepareBridgeIsolationLayout({ repoRoot: repo, sessionKey: 'test', includeProviderCredentials: false, env: { ...process.env } });
  });
  afterEach(async () => { cleanupIsolationLayout(layout); await rm(root, { recursive: true, force: true }); });

  function argvFor(options) {
    return wrapIsolatedCommand({ repoRoot: repo, isolationLayout: layout, bwrapBin: bwrap, command: { provider: 'claude', bin: '/usr/bin/env', argv: ['true'], stdin: '', env: {} }, ...options }).argv;
  }
  function pairs(argv, flag) {
    const out = []; argv.forEach((v, i) => { if (v === flag) out.push([argv[i + 1], argv[i + 2]]); }); return out;
  }

  it('keeps the repository writable, the environment masked, and the network available', () => {
    const argv = argvFor({ repositoryAccess: 'read-write' });
    expect(pairs(argv, '--bind')).toContainEqual([repo, repo]);
    expect(pairs(argv, '--ro-bind')).toContainEqual(['/dev/null', join(repo, '.env')]);
    expect(argv).not.toContain('--unshare-net');
  });

  it('masks additional private files after mounting the repository', async () => {
    const privateFile = join(repo, 'private-notes.txt');
    await writeFile(privateFile, 'private');
    const argv = argvFor({ repositoryAccess: 'read-write', extraBuilderPrivatePaths: ['private-notes.txt'] });
    const bindIndex = argv.findIndex((v, i) => v === '--bind' && argv[i + 1] === repo);
    const maskIndex = argv.findIndex((v, i) => v === '--ro-bind' && argv[i + 1] === '/dev/null' && argv[i + 2] === privateFile);
    expect(bindIndex).toBeGreaterThan(-1);
    expect(maskIndex).toBeGreaterThan(bindIndex);
  });

  it('refuses a private path with symlinked ancestry', async () => {
    const outside = join(root, 'outside');
    await mkdir(outside);
    await writeFile(join(outside, 'private.txt'), 'private');
    await symlink(outside, join(repo, 'linked'));
    expect(() => argvFor({ repositoryAccess: 'read-write', extraBuilderPrivatePaths: ['linked/private.txt'] }))
      .toThrow('symlinked ancestry');
  });

  it('runs the pinned Claude binary from /opt/claude-bridge and ignores CLAUDE_BRIDGE_CLAUDE_BIN there', async () => {
    const fake = join(root, 'claude');
    await writeFile(fake, '#!/bin/sh\n');
    const env = { CLAUDE_BRIDGE_CLAUDE_BIN: fake, PATH: root, HOME: root };
    const pinned = resolveClaudeBin(env, { bridge: true, serverPath: '/opt/claude-bridge/0.5.0/mcp/server.mjs' });
    expect(pinned.bin).toBe('/opt/claude-bridge/current/claude/claude');
    // Whether the pinned file exists depends on this host having the install; the override is ignored either way.
    expect(pinned.resolved).toBe(existsSync('/opt/claude-bridge/current/claude/claude'));
    // A checkout run keeps the override.
    expect(resolveClaudeBin(env, { bridge: true, serverPath: join(root, 'mcp', 'server.mjs') })).toEqual({ bin: fake, resolved: true });
    expect(resolveClaudeBin(env, { bridge: true })).toEqual({ bin: fake, resolved: true });
  });
});
