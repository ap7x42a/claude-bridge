// tests/unit/ops/claude-bridge/support-modules.test.mjs
import { chmod, mkdtemp, rm, mkdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildBridgeSystemPrompt } from '../../../../plugins/claude-bridge/mcp/system-prompt.mjs';
import { userInfo } from 'node:os';
import {
  EXPECTED_HOOKS, effectiveRoots, expectedHookCommand, hooksIntact, installedOwnerPublicKey, installedOwnerPublicKeyPath,
  isRegisteredRepo, protectionStatus, runtimeDefaults, codexCacheLaunchConfigOk,
} from '../../../../plugins/claude-bridge/mcp/protection.mjs';
import { trustBypassConfig } from './harness.mjs';
import { repoKey } from '../../../../plugins/claude-bridge/mcp/verdict.mjs';

// The registration hooks.template.json renders, written out literally so the tests do not derive it from EXPECTED_HOOKS.
const templateHooks = (command) => ({
  hooks: {
    SessionStart: [{ matcher: 'startup|resume|clear|compact', hooks: [{ type: 'command', command, timeout: 10 }] }],
    UserPromptSubmit: [{ hooks: [{ type: 'command', command, timeout: 10 }] }],
    PreToolUse: [{ hooks: [{ type: 'command', command, timeout: 10 }] }],
    PostToolUse: [{ hooks: [{ type: 'command', command, timeout: 10 }] }],
    Stop: [{ hooks: [{ type: 'command', command, timeout: 15 }] }],
  },
});
const STATE_KEYS = ['session_start', 'user_prompt_submit', 'pre_tool_use', 'post_tool_use', 'stop'];

// The form Codex writes: sha256: and 64 hex digits.
const HASH = `sha256:${'0123456789abcdef'.repeat(4)}`;

describe('bridge system prompt', () => {
  it('names the evidence, the authority, the tools and the verdict', () => {
    const text = buildBridgeSystemPrompt({ profile: 'review', session: { match: 'prompt' }, protection: { status: 'protected' }, evidenceMount: '/tmp/claude/evidence' });
    expect(text).toContain('/tmp/claude/evidence/conversation.md');
    expect(text).toContain("operator's own messages are the acceptance criterion");
    expect(text).toContain("agent's brief is a claim");
    expect(text).toContain('corrective authority');
    expect(text).toContain('bridge-verdict:');
    expect(text).toContain('Never push');
    expect(text).toContain('operator_readback');
    expect(text).not.toContain('read-only');
    expect(text).toContain('Messages marked verified were recorded by the Codex hook in some turn for this repository, not necessarily at this place in the log; unverified messages come only from the session file, which the agent can write.');
  });
  it('gives a task the same tool line as a review: both run with permissions bypassed', () => {
    const prompt = (profile) => buildBridgeSystemPrompt({ profile, session: { match: 'prompt' }, protection: { status: 'protected' }, evidenceMount: '/tmp/claude/evidence' });
    const tools = '- Tools: the full default tool set, shell, web fetch and web search, and any method that reaches the network such as curl.';
    expect(prompt('task')).toContain(tools);
    expect(prompt('review')).toContain(tools);
    expect(prompt('task')).not.toContain('permission mode allows');
    expect(prompt('review')).not.toContain('permission mode allows');
  });
  it('leaves the unprotected sentence in the readback to the server alone', () => {
    const text = buildBridgeSystemPrompt({ profile: 'review', session: { match: 'prompt' }, protection: { status: 'unprotected' }, evidenceMount: '/tmp/claude/evidence' });
    expect(text).toContain('This bridge is running unprotected');
    expect(text).not.toContain('say so in the report');
    expect(text).toContain('The bridge itself adds a sentence saying so to operator_readback; do not add one.');
  });

  it('says when the hook recorded no turns, or its ledger is broken, so nothing is verified', () => {
    const text = (ledger) => buildBridgeSystemPrompt({ profile: 'review', session: { match: 'prompt' }, protection: { status: 'protected' }, evidenceMount: '/tmp/claude/evidence', ledger });
    expect(text({ status: 'empty', records: 0, owner_prompts: 0 })).toContain('The Codex hook recorded no turns for this repository');
    expect(text({ status: 'broken', records: 3, owner_prompts: 1 })).toContain("The hook's turns ledger failed its integrity check");
    expect(text({ status: 'ok', records: 3, owner_prompts: 1 })).not.toMatch(/recorded no turns|integrity check/);
  });
  it('tells the reviewer when the conversation could not be located', () => {
    const text = buildBridgeSystemPrompt({ profile: 'task', session: { match: 'none' }, protection: { status: 'unprotected' }, evidenceMount: '/tmp/claude/evidence' });
    expect(text).toContain('- /tmp/claude/evidence/conversation.md: the operator and agent conversation. The Codex session log could not be located; conversation.md holds only a placeholder. Say so under evidence_coverage.');
    expect(text).not.toContain('no conversation file is present');
    expect(text).toContain('unprotected');
  });
  it('says the log was located but unreadable when extraction failed', () => {
    const text = buildBridgeSystemPrompt({ profile: 'review', session: { match: 'prompt', path: '/x.jsonl', read_error: true }, protection: { status: 'protected' }, evidenceMount: '/tmp/claude/evidence' });
    expect(text).toContain('The Codex session log was located but could not be read; see conversation.md.');
    expect(text).not.toContain('taken from the Codex session log');
  });
  it('never renders an undefined match when the session or its match is missing', () => {
    for (const session of [undefined, null, {}, { match: '' }]) {
      const text = buildBridgeSystemPrompt({ profile: 'review', session, protection: { status: 'protected' }, evidenceMount: '/tmp/claude/evidence' });
      expect(text).toContain('could not be located');
      expect(text).not.toContain('undefined');
      expect(text).not.toContain('(match:');
    }
  });
});

describe('protection status', () => {
  let root; let env;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'bridge-protect-'));
    env = { CLAUDE_BRIDGE_PROTECTED_ROOT: join(root, 'opt'), CLAUDE_BRIDGE_ETC_DIR: join(root, 'etc'), HOME: root, CODEX_HOME: join(root, '.codex') };
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  it('is unprotected when the server runs outside the protected root', () => {
    const status = protectionStatus({ serverPath: join(root, 'repo', 'server.mjs'), env });
    expect(status.status).toBe('unprotected');
    expect(status.reasons[0]).toMatch(/outside/);
  });
  it('is unprotected when the file under the root is not root-owned or not immutable', async () => {
    await mkdir(join(root, 'opt', 'current', 'mcp'), { recursive: true });
    await writeFile(join(root, 'opt', 'current', 'mcp', 'server.mjs'), '');
    const status = protectionStatus({ serverPath: join(root, 'opt', 'current', 'mcp', 'server.mjs'), env });
    expect(status.status).toBe('unprotected');
    expect(status.reasons.join(' ')).toMatch(/owned by uid|immutable/);
  });
  it.skipIf(process.getuid?.() === 0)('is unprotected when the pinned Claude binary or a directory above it is writable, or it is missing', async () => {
    const serverPath = join(root, 'opt', 'current', 'mcp', 'server.mjs');
    await mkdir(join(root, 'opt', 'current', 'mcp'), { recursive: true });
    await writeFile(serverPath, '');
    const reasons = () => protectionStatus({ serverPath, env }).reasons;
    expect(reasons()).toContain('Claude binary is missing');
    await mkdir(join(root, 'opt', 'current', 'claude'));
    await writeFile(join(root, 'opt', 'current', 'claude', 'claude'), '#!/bin/sh\n', { mode: 0o555 });
    // Nothing on the way up to the directory holding the protected root is writable by this uid.
    const locked = [join(root, 'opt', 'current', 'claude'), join(root, 'opt', 'current'), join(root, 'opt'), root];
    try {
      for (const dir of locked) await chmod(dir, 0o555);
      expect(reasons()).not.toContain('Claude binary is owner-writable');
      expect(reasons()).not.toContain('Claude binary is missing');
      await chmod(join(root, 'opt', 'current', 'claude'), 0o777);
      expect(reasons()).toContain('Claude binary is owner-writable');
      await chmod(join(root, 'opt', 'current', 'claude'), 0o555);
      await chmod(root, 0o755);
      expect(reasons()).toContain('Claude binary is owner-writable');
    } finally {
      for (const dir of locked.reverse()) await chmod(dir, 0o755);
    }
    // A bridge outside the protected root runs no pinned copy, so the check does not apply.
    expect(protectionStatus({ serverPath: join(root, 'repo', 'server.mjs'), env }).reasons.join(' ')).not.toMatch(/Claude binary/);
  });
  it('accepts the Codex cache launch config only when it is root-owned, not group- or world-writable, and the installed bytes', async () => {
    const opt = join(root, 'opt');
    const codex = join(root, '.codex');
    const launch = '{"mcpServers":{"claude_bridge":{"command":"/usr/bin/node"}}}\n';
    await mkdir(join(opt, 'current', '.codex-plugin'), { recursive: true });
    await writeFile(join(opt, 'current', '.codex-plugin', 'plugin.json'), JSON.stringify({ version: '0.5.0' }));
    await writeFile(join(opt, 'current', '.mcp.json'), launch);
    const cacheDir = join(codex, 'plugins', 'cache', 'claude-bridge-local', 'claude-bridge', '0.5.0');
    const cached = join(cacheDir, '.mcp.json');
    const uid = process.getuid();
    const ok = (rootUid = uid) => codexCacheLaunchConfigOk({ codexHome: codex, protectedRoot: opt, rootUid });
    expect(ok()).toBe(false);
    await mkdir(cacheDir, { recursive: true });
    await writeFile(cached, launch, { mode: 0o644 });
    await chmod(cached, 0o644);
    // This file stands for the root-owned one by naming this uid as root.
    expect(ok()).toBe(true);
    expect(ok(0)).toBe(uid === 0);
    await chmod(cached, 0o664);
    expect(ok()).toBe(false);
    await chmod(cached, 0o644);
    await writeFile(cached, launch.replace('/usr/bin/node', '/tmp/node'));
    expect(ok()).toBe(false);
    await rm(cached);
    await writeFile(join(root, 'elsewhere.json'), launch);
    await symlink(join(root, 'elsewhere.json'), cached);
    expect(ok()).toBe(false);
  });
  it('is unprotected when the installed bridge runs with loader variables set', () => {
    const installed = '/opt/claude-bridge/0.5.0/mcp/server.mjs';
    for (const key of ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'NODE_OPTIONS']) {
      expect(protectionStatus({ serverPath: installed, env: { [key]: '/x' } }).reasons, key).toContain('loader variables set');
      expect(protectionStatus({ serverPath: installed, env: { [key]: '' } }).reasons, key).not.toContain('loader variables set');
      // A checkout run is unprotected anyway and reports only its own reasons.
      expect(protectionStatus({ serverPath: join(root, 'repo', 'server.mjs'), env: { ...env, [key]: '/x' } }).reasons, key).not.toContain('loader variables set');
    }
  });
  it('reads repo registration from the etc dir', async () => {
    const repo = join(root, 'repo'); await mkdir(repo);
    expect(isRegisteredRepo(repo, env)).toBe(false);
    await mkdir(join(root, 'etc', 'repos'), { recursive: true });
    await writeFile(join(root, 'etc', 'repos', repoKey(repo)), repo + '\n');
    expect(isRegisteredRepo(repo, env)).toBe(true);
  });
  it('runs the hook with an isolated interpreter, one space between each part', () => {
    expect(expectedHookCommand({ CLAUDE_BRIDGE_PROTECTED_ROOT: '/srv/bridge' })).toBe('/usr/bin/python3 -I /srv/bridge/current/hooks/bridge_hook.py');
    expect(expectedHookCommand({})).toBe('/usr/bin/python3 -I /opt/claude-bridge/current/hooks/bridge_hook.py');
  });
  it('ignores the root overrides when the bridge runs from /opt/claude-bridge', async () => {
    const installed = '/opt/claude-bridge/0.5.0/mcp/server.mjs';
    expect(effectiveRoots({ serverPath: installed, env })).toEqual({ protectedRoot: '/opt/claude-bridge', etcDir: '/etc/claude-bridge', protected: true });
    expect(effectiveRoots({ serverPath: '/opt/claude-bridge-other/mcp/server.mjs', env })).toEqual({ protectedRoot: join(root, 'opt'), etcDir: join(root, 'etc'), protected: false });
    expect(effectiveRoots({ serverPath: join(root, 'repo', 'server.mjs'), env })).toEqual({ protectedRoot: join(root, 'opt'), etcDir: join(root, 'etc'), protected: false });
    expect(effectiveRoots({ serverPath: '/opt/claude-bridge/../evil/server.mjs', env }).protected).toBe(false);
    expect(expectedHookCommand(env, { serverPath: installed })).toBe('/usr/bin/python3 -I /opt/claude-bridge/current/hooks/bridge_hook.py');
    expect(expectedHookCommand(env)).toBe(`/usr/bin/python3 -I ${join(root, 'opt', 'current', 'hooks', 'bridge_hook.py')}`);
    // A registration under the overridden etc dir does not count for the installed bridge.
    const repo = join(root, 'repo'); await mkdir(repo);
    await mkdir(join(root, 'etc', 'repos'), { recursive: true });
    await writeFile(join(root, 'etc', 'repos', repoKey(repo)), repo + '\n');
    expect(isRegisteredRepo(repo, env)).toBe(true);
    expect(isRegisteredRepo(repo, env, { serverPath: join(root, 'repo', 'server.mjs') })).toBe(true);
    expect(isRegisteredRepo(repo, env, { serverPath: installed })).toBe(false);
    // The installed bridge reads hooks.json from the passwd home, never from the overridden CODEX_HOME.
    await mkdir(join(root, '.codex'), { recursive: true });
    await writeFile(join(root, '.codex', 'hooks.json'), JSON.stringify(templateHooks(expectedHookCommand(env))));
    expect(hooksIntact(env, { serverPath: join(root, 'repo', 'server.mjs') }).reasons[0]).toBe('SessionStart hook is not yet trusted in Codex');
    const installedHooks = hooksIntact(env, { serverPath: installed });
    // The installed check reads the real host, so its answer must equal the one with no overrides at all.
    expect(installedHooks).toEqual(hooksIntact({}, { serverPath: installed }));
    expect(installedHooks.reasons.join(' ')).not.toContain(root);
    expect(protectionStatus({ serverPath: installed, env }).reasons.join(' ')).not.toMatch(/outside/);
  });
  // Every knob an installed program must ignore, pointed somewhere else.
  const knobs = () => ({
    HOME: join(root, 'home'), CODEX_HOME: join(root, 'codex'), CLAUDE_BRIDGE_STATE_DIR: join(root, 'state'),
    CLAUDE_BRIDGE_SESSIONS_ROOT: join(root, 'sessions'), CLAUDE_BRIDGE_PROTECTED_ROOT: join(root, 'opt'), CLAUDE_BRIDGE_ETC_DIR: join(root, 'etc'),
    CLAUDE_BRIDGE_CLAUDE_BIN: join(root, 'claude'), CLAUDE_BRIDGE_BIN: join(root, 'claude2'),
    CLAUDE_BRIDGE_BWRAP_BIN: join(root, 'bwrap'),
    CLAUDE_BRIDGE_TEST_MODE: '1', CLAUDE_BRIDGE_TEST_FORCE_PROTECTED: '1', CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS: '100',
    CLAUDE_BRIDGE_TEST_FORCE_ROOT: '1', CLAUDE_BRIDGE_STATE_CLI: join(root, 'cli.mjs'), CLAUDE_BRIDGE_ALLOWED_ROOTS: root,
  });
  it('takes every location and knob from the environment outside /opt/claude-bridge', () => {
    const env = knobs();
    const defaults = runtimeDefaults({ selfPath: join(root, 'opt', 'current', 'mcp', 'server.mjs'), env });
    expect(defaults).toMatchObject({
      installed: false, home: join(root, 'home'), codexHome: join(root, 'codex'), stateRoot: join(root, 'state'), sessionsRoot: join(root, 'sessions'),
      protectedRoot: join(root, 'opt'), etcDir: join(root, 'etc'), claudeBin: join(root, 'claude'), bwrapBin: join(root, 'bwrap'),
      testMode: true,
    });
    expect(defaults.env).toBe(env);
    const bare = runtimeDefaults({ selfPath: join(root, 'server.mjs'), env: { HOME: join(root, 'home') } });
    expect(bare).toMatchObject({
      codexHome: join(root, 'home', '.codex'), stateRoot: join(root, 'home', '.local', 'state', 'claude-bridge'), sessionsRoot: join(root, 'home', '.codex', 'sessions'),
      protectedRoot: '/opt/claude-bridge', etcDir: '/etc/claude-bridge', claudeBin: null, bwrapBin: '/usr/bin/bwrap', testMode: false,
    });
  });
  it('ignores every location and knob in the environment when it runs from /opt/claude-bridge', () => {
    const env = knobs();
    const home = userInfo().homedir;
    for (const selfPath of ['/opt/claude-bridge/0.5.0/mcp/server.mjs', '/opt/claude-bridge/current/bin/claude-bridge', '/opt/claude-bridge/current/mcp/state-cli.mjs']) {
      const defaults = runtimeDefaults({ selfPath, env });
      expect(defaults).toMatchObject({
        installed: true, home, codexHome: join(home, '.codex'), stateRoot: join(home, '.local', 'state', 'claude-bridge'), sessionsRoot: join(home, '.codex', 'sessions'),
        protectedRoot: '/opt/claude-bridge', etcDir: '/etc/claude-bridge', claudeBin: '/opt/claude-bridge/current/claude/claude', bwrapBin: '/usr/bin/bwrap',
        testMode: false,
      });
      // The environment every module then reads carries the literal values and no test knob.
      expect(defaults.env).toMatchObject({
        HOME: home, CODEX_HOME: join(home, '.codex'), CLAUDE_BRIDGE_STATE_DIR: join(home, '.local', 'state', 'claude-bridge'),
        CLAUDE_BRIDGE_SESSIONS_ROOT: join(home, '.codex', 'sessions'), CLAUDE_BRIDGE_PROTECTED_ROOT: '/opt/claude-bridge', CLAUDE_BRIDGE_ETC_DIR: '/etc/claude-bridge',
        CLAUDE_BRIDGE_CLAUDE_BIN: '/opt/claude-bridge/current/claude/claude', CLAUDE_BRIDGE_BWRAP_BIN: '/usr/bin/bwrap',
        CLAUDE_BRIDGE_ALLOWED_ROOTS: root,
      });
      for (const key of ['CLAUDE_BRIDGE_BIN', 'CLAUDE_BRIDGE_TEST_MODE', 'CLAUDE_BRIDGE_TEST_FORCE_PROTECTED', 'CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS', 'CLAUDE_BRIDGE_TEST_FORCE_ROOT', 'CLAUDE_BRIDGE_STATE_CLI']) {
        expect(defaults.env, key).not.toHaveProperty(key);
      }
      expect(env.CLAUDE_BRIDGE_TEST_MODE).toBe('1');
    }
    expect(runtimeDefaults({ selfPath: '/opt/claude-bridge-other/mcp/server.mjs', env }).installed).toBe(false);
    expect(runtimeDefaults({ selfPath: '/opt/claude-bridge/../evil/server.mjs', env }).installed).toBe(false);
  });
  it('finds the installed owner public key, and reports its absence as a protection reason', async () => {
    const serverPath = join(root, 'opt', 'current', 'mcp', 'server.mjs');
    expect(installedOwnerPublicKey({ serverPath, env })).toBeNull();
    expect(installedOwnerPublicKeyPath({ serverPath, env })).toBeNull();
    expect(protectionStatus({ serverPath, env }).reasons).toContain('no owner public key; owner clears unverified');
    expect(protectionStatus({ serverPath: join(root, 'repo', 'server.mjs'), env }).reasons).toContain('no owner public key; owner clears unverified');
    await mkdir(join(root, 'etc'), { recursive: true });
    await writeFile(join(root, 'etc', 'owner.pub'), 'etc key\n');
    expect(installedOwnerPublicKey({ serverPath, env })).toBe('etc key\n');
    expect(installedOwnerPublicKeyPath({ serverPath, env })).toBe(join(root, 'etc', 'owner.pub'));
    expect(protectionStatus({ serverPath, env }).reasons).not.toContain('no owner public key; owner clears unverified');
    await mkdir(join(root, 'opt', 'current'), { recursive: true });
    await writeFile(join(root, 'opt', 'current', 'owner.pub'), 'installed key\n');
    expect(installedOwnerPublicKey({ serverPath, env })).toBe('installed key\n');
    expect(installedOwnerPublicKeyPath({ serverPath, env })).toBe(join(root, 'opt', 'current', 'owner.pub'));
    // Run from /opt/claude-bridge, the overridden roots are not read.
    expect(['etc key\n', 'installed key\n']).not.toContain(installedOwnerPublicKey({ serverPath: '/opt/claude-bridge/0.5.0/mcp/server.mjs', env }));
  });
  it('pins the expected hook shape to the hooks.template.json values', () => {
    expect(EXPECTED_HOOKS).toEqual({
      SessionStart: { matcher: 'startup|resume|clear|compact', timeout: 10 },
      UserPromptSubmit: { timeout: 10 },
      PreToolUse: { timeout: 10 },
      PostToolUse: { timeout: 10 },
      Stop: { timeout: 15 },
    });
    expect(Object.isFrozen(EXPECTED_HOOKS) && Object.values(EXPECTED_HOOKS).every(Object.isFrozen)).toBe(true);
  });
  it('checks the hook registration and the Codex trust state of our own hook', async () => {
    expect(hooksIntact(env).intact).toBe(false);
    await mkdir(join(root, '.codex'), { recursive: true });
    const hooksPath = join(root, '.codex', 'hooks.json');
    const configPath = join(root, '.codex', 'config.toml');
    await writeFile(hooksPath, JSON.stringify(templateHooks(expectedHookCommand(env))));
    const table = (key, extra = '') => `[hooks.state."${hooksPath}:${key}"]\ntrusted_hash = "${HASH}"\n${extra}`;
    const config = (tables) => ['[hooks.state]\n', ...tables].join('\n');

    await writeFile(configPath, '[hooks.state]\n');
    const untrusted = hooksIntact(env);
    expect(untrusted.intact).toBe(false);
    expect(untrusted.reasons).toEqual(['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'].map((event) => `${event} hook is not yet trusted in Codex`));

    await writeFile(configPath, config(STATE_KEYS.filter((key) => key !== 'stop').map((key) => table(`${key}:0:0`))));
    expect(hooksIntact(env).reasons).toEqual(['Stop hook is not yet trusted in Codex']);

    await writeFile(configPath, config(STATE_KEYS.map((key) => table(`${key}:0:0`))));
    expect(hooksIntact(env)).toEqual({ intact: true, reasons: [] });

    await writeFile(configPath, config(STATE_KEYS.map((key) => table(`${key}:0:0`, key === 'stop' ? 'enabled = false\n' : ''))));
    const disabled = hooksIntact(env);
    expect(disabled.intact).toBe(false);
    expect(disabled.reasons).toEqual(['Stop hook is disabled in Codex config']);

    await writeFile(configPath, config([...STATE_KEYS.map((key) => table(`${key}:0:0`)), table('stop:1:0', 'enabled = false\n')]));
    expect(hooksIntact(env)).toEqual({ intact: true, reasons: [] });
  });
  it('reads the trust entry as a TOML parser does: only the hash and at most enabled = true is trusted', async () => {
    await mkdir(join(root, '.codex'), { recursive: true });
    const hooksPath = join(root, '.codex', 'hooks.json');
    await writeFile(hooksPath, JSON.stringify(templateHooks(expectedHookCommand(env))));
    const configPath = join(root, '.codex', 'config.toml');
    const header = (key) => `[hooks.state."${hooksPath}:${key}:0:0"]`;
    const others = STATE_KEYS.filter((key) => key !== 'stop').map((key) => `${header(key)}\ntrusted_hash = "${HASH}"\nenabled = true\n`);
    const withStop = (body, extra = []) => writeFile(configPath, ['[hooks.state]\n', ...extra, ...others, `${header('stop')}\n${body}`].join('\n'));
    const check = async (body, extra) => { await withStop(body, extra); return hooksIntact(env); };
    const unexpected = { intact: false, reasons: ['Stop hook is not intact: unexpected trust state'] };
    const disabled = { intact: false, reasons: ['Stop hook is disabled in Codex config'] };
    expect(await check(`trusted_hash = "${HASH}"\nenabled = true\n\n`)).toEqual({ intact: true, reasons: [] });
    expect(await check(`trusted_hash = "${'f'.repeat(64)}"\n`)).toEqual({ intact: true, reasons: [] });
    expect(await check(`trusted_hash = "${HASH}" # trusted\n`)).toEqual({ intact: true, reasons: [] });
    // Every spelling TOML reads as enabled = false is disabled.
    for (const body of ['enabled = false', '"enabled" = false', 'enabled=false', 'enabled  =  false', "'enabled' = false"]) {
      expect(await check(`trusted_hash = "${HASH}"\n${body}\n`), body).toEqual(disabled);
    }
    for (const body of [
      `trusted_hash = "sha256:not-hex"\n`,
      `trusted_hash = "sha256:${'a'.repeat(63)}"\n`,
      `trusted_hash = 5\n`,
      `trusted_hash = "${HASH}"\nenabled = "false"\n`,
      `trusted_hash = "${HASH}"\nstatus = "on"\n`,
      `enabled = true\n`,
    ]) expect(await check(body), body).toEqual(unexpected);
    // A repeated key, a repeated table, or a dotted key redefining the table: TOML refuses the file.
    for (const [body, extra] of [
      [`trusted_hash = "${HASH}"\ntrusted_hash = "${HASH}"\n`, []],
      [`trusted_hash = "${HASH}"\nenabled = true\nenabled = true\n`, []],
      [`trusted_hash = "${HASH}"\n\n${header('stop')}\ntrusted_hash = "${HASH}"\n`, []],
      [`trusted_hash = "${HASH}"\n`, [`"${hooksPath}:stop:0:0".enabled = false\n`]],
    ]) {
      const result = await check(body, extra);
      expect(result.intact, body).toBe(false);
      expect(result.reasons.join(' '), body).toMatch(/^cannot parse config\.toml: /);
    }
  });
  it('reads a disabled entry behind an escaped key and a decoy string as disabled', async () => {
    await mkdir(join(root, '.codex'), { recursive: true });
    const hooksPath = join(root, '.codex', 'hooks.json');
    await writeFile(hooksPath, JSON.stringify(templateHooks(expectedHookCommand(env))));
    await writeFile(join(root, '.codex', 'config.toml'), trustBypassConfig(hooksPath));
    expect(hooksIntact(env)).toEqual({ intact: false, reasons: ['Stop hook is disabled in Codex config'] });
  });
  it('reads features.codex_hooks = false as not intact', async () => {
    await mkdir(join(root, '.codex'), { recursive: true });
    const hooksPath = join(root, '.codex', 'hooks.json');
    await writeFile(hooksPath, JSON.stringify(templateHooks(expectedHookCommand(env))));
    const tables = STATE_KEYS.map((key) => `[hooks.state."${hooksPath}:${key}:0:0"]\ntrusted_hash = "${HASH}"\n`);
    await writeFile(join(root, '.codex', 'config.toml'), [...tables].join('\n'));
    expect(hooksIntact(env)).toEqual({ intact: true, reasons: [] });
    await writeFile(join(root, '.codex', 'config.toml'), ['[features]\ncodex_hooks = false\n', ...tables].join('\n'));
    expect(hooksIntact(env)).toEqual({ intact: false, reasons: ['hooks disabled by features.codex_hooks'] });
    await writeFile(join(root, '.codex', 'config.toml'), ['[features]\ncodex_hooks = true\n', ...tables].join('\n'));
    expect(hooksIntact(env)).toEqual({ intact: true, reasons: [] });
  });
  it('matches the trust entry at the group and hook index where our command sits', async () => {
    await mkdir(join(root, '.codex'), { recursive: true });
    const hooksPath = join(root, '.codex', 'hooks.json');
    const foreign = { type: 'command', command: '/usr/bin/true', timeout: 10 };
    const hooks = templateHooks(expectedHookCommand(env));
    hooks.hooks.Stop = [{ hooks: [foreign] }, { hooks: [foreign, hooks.hooks.Stop[0].hooks[0]] }];
    await writeFile(hooksPath, JSON.stringify(hooks));
    const table = (key, extra = '') => `[hooks.state."${hooksPath}:${key}"]\ntrusted_hash = "${HASH}"\n${extra}`;
    const base = STATE_KEYS.filter((key) => key !== 'stop').map((key) => table(`${key}:0:0`));
    await writeFile(join(root, '.codex', 'config.toml'), [...base, table('stop:0:0')].join('\n'));
    expect(hooksIntact(env).reasons).toEqual(['Stop hook is not yet trusted in Codex']);
    await writeFile(join(root, '.codex', 'config.toml'), [...base, table('stop:0:0', 'enabled = false\n'), table('stop:1:1')].join('\n'));
    expect(hooksIntact(env)).toEqual({ intact: true, reasons: [] });
    await writeFile(join(root, '.codex', 'config.toml'), [...base, table('stop:1:1', 'enabled = false\n')].join('\n'));
    expect(hooksIntact(env).reasons).toEqual(['Stop hook is disabled in Codex config']);
  });
  it('rejects our hook registered with any shape other than the template, even when trusted', async () => {
    await mkdir(join(root, '.codex'), { recursive: true });
    const hooksPath = join(root, '.codex', 'hooks.json');
    await writeFile(join(root, '.codex', 'config.toml'), STATE_KEYS.flatMap((key) => [0, 1].map((g) => `[hooks.state."${hooksPath}:${key}:${g}:0"]\ntrusted_hash = "${HASH}"\n`)).join('\n'));
    const command = expectedHookCommand(env);
    const check = async (mutate) => {
      const hooks = templateHooks(command);
      mutate(hooks.hooks);
      await writeFile(hooksPath, JSON.stringify(hooks));
      return hooksIntact(env);
    };
    expect(await check(() => {})).toEqual({ intact: true, reasons: [] });
    const unexpected = (event) => ({ intact: false, reasons: [`${event} hook is registered with an unexpected shape`] });
    expect(await check((h) => { h.Stop[0].hooks[0].timeout = 5; })).toEqual(unexpected('Stop'));
    expect(await check((h) => { h.SessionStart[0].matcher = 'startup'; })).toEqual(unexpected('SessionStart'));
    expect(await check((h) => { delete h.SessionStart[0].matcher; })).toEqual(unexpected('SessionStart'));
    expect(await check((h) => { h.UserPromptSubmit[0].matcher = '*'; })).toEqual(unexpected('UserPromptSubmit'));
    expect(await check((h) => { h.PreToolUse[0].hooks[0].statusMessage = 'x'; })).toEqual(unexpected('PreToolUse'));
    expect(await check((h) => { h.PostToolUse[0].hooks[0].type = 'prompt'; })).toEqual(unexpected('PostToolUse'));
    expect(await check((h) => { h.PostToolUse.push(globalThis.structuredClone(h.PostToolUse[0])); })).toEqual(unexpected('PostToolUse'));
  });
});
