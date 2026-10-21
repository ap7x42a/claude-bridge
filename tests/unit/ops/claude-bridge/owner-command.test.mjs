// tests/unit/ops/claude-bridge/owner-command.test.mjs
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, cp, mkdtemp, mkdir, readdir, rm, symlink, writeFile, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { hooksIntact } from '../../../../plugins/claude-bridge/mcp/protection.mjs';
import { readChain, recordVerdict, readOpen, repoKey, repoStateDir } from '../../../../plugins/claude-bridge/mcp/verdict.mjs';

const CLI = resolve('plugins/claude-bridge/bin/claude-bridge');
const verdict = { verdict: 'blocked', deception_found: true, counter_to_operator_request: true, findings: [], corrective_actions: [], reprimand: null, required_of_codex: ['stop'], operator_readback: 'Claude Bridge verdict: blocked.', report: '', evidence_coverage: { session_conversation: 'none', notes: '' } };

describe('owner command', () => {
  let root; let repo; let env;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'bridge-cli-'));
    repo = join(root, 'repo'); await mkdir(join(repo, '.git'), { recursive: true });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    await mkdir(join(root, 'etc'), { recursive: true });
    await writeFile(join(root, 'etc', 'owner.key'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
    await writeFile(join(root, 'etc', 'owner.pub'), publicKey.export({ type: 'spki', format: 'pem' }));
    env = { ...process.env, HOME: root, CODEX_HOME: join(root, '.codex'), CLAUDE_BRIDGE_STATE_DIR: join(root, 'state'), CLAUDE_BRIDGE_PROTECTED_ROOT: join(root, 'opt'), CLAUDE_BRIDGE_ETC_DIR: join(root, 'etc'), CLAUDE_BRIDGE_OWNER_KEY: join(root, 'etc', 'owner.key') };
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });
  const run = (args, extraEnv = {}) => spawnSync(process.execPath, [CLI, ...args], { env: { ...env, ...extraEnv }, encoding: 'utf8', cwd: repo });
  const record = (extra = {}) => recordVerdict(repo, env, { job_id: 'j', profile: 'review', verdict, session: { match: 'none' }, prompt_sha256: 'p', model: 'm', ...extra });
  const markerPath = () => join(repoStateDir(repo, env), 'record-failure.json');

  it('reports status and verdicts', () => {
    const recorded = record();
    const status = run(['status', repo]);
    expect(status.status, status.stderr).toBe(0);
    expect(status.stderr).toBe('');
    expect(status.stdout).toContain(`state: open (verdict ${recorded.id}, blocked, readback pending)`);
    expect(status.stdout).toMatch(/^chain intact: true; open cache valid: true$/m);
    expect(status.stdout).toMatch(/^protection: unprotected \(server runs outside /m);
    expect(status.stdout).toMatch(/^hooks: not intact \(.*hooks\.json missing or unreadable\)$/m);
    expect(status.stdout).toMatch(/^registered: false$/m);
    expect(status.stdout).toContain(`state dir: ${repoStateDir(repo, env)}`);
    expect(status.stdout).toMatch(/^record failure marker: absent$/m);
    expect(status.stdout).toContain(`owner clears: verified against ${join(root, 'etc', 'owner.pub')}\n`);
    const list = run(['verdicts']);
    expect(list.status, list.stderr).toBe(0);
    expect(list.stdout).toMatch(/^chain intact: true; records: 1$/m);
    expect(list.stdout).toContain(`${recorded.id} review blocked :: Claude Bridge verdict: blocked.`);
  });

  it('verifies owner clears in the chain against the installed key, and says when there is none', async () => {
    const recorded = record();
    const attacker = generateKeyPairSync('ed25519');
    await writeFile(join(root, 'etc', 'attacker.key'), attacker.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    // A writer with its own key pair runs the CLI with the root overrides pointed at that key.
    const forgedEtc = join(root, 'forged-etc');
    await mkdir(forgedEtc, { recursive: true });
    await writeFile(join(forgedEtc, 'owner.pub'), attacker.publicKey.export({ type: 'spki', format: 'pem' }));
    const forged = run(['clear', recorded.id, '--reason', 'forged', repo], { CLAUDE_BRIDGE_ETC_DIR: forgedEtc, CLAUDE_BRIDGE_OWNER_KEY: join(root, 'etc', 'attacker.key') });
    expect(forged.status, forged.stderr).toBe(0);
    expect(forged.stdout).toMatch(/^state: clear$/m);
    // Against the installed key, the forged clear is seen.
    const status = run(['status', repo]).stdout;
    expect(status).toMatch(/^state: tampered \(forged owner clear in chain\)$/m);
    expect(status).toContain(`owner clears: verified against ${join(root, 'etc', 'owner.pub')}\n`);
    await rm(join(root, 'etc', 'owner.pub'));
    const unverified = run(['status', repo]).stdout;
    expect(unverified).toMatch(/^state: clear$/m);
    expect(unverified).toMatch(/^owner clears: unverified \(no public key\)$/m);
    expect(unverified).toMatch(/^protection: unprotected \(.*no owner public key; owner clears unverified\)$/m);
  });

  it('clears a verdict with the owner key, ends a record-failure refusal, and refuses without the key', async () => {
    const recorded = record();
    await writeFile(markerPath(), `${JSON.stringify({ job_id: 'j2', recorded_at: '2026-10-10T00:00:00.000Z', message: 'state lock timeout' })}\n`);
    expect(run(['status', repo]).stdout).toMatch(/^record failure marker: present \(2026-10-10T00:00:00\.000Z\)$/m);

    const denied = spawnSync(process.execPath, [CLI, 'clear', recorded.id, '--reason', 'x', repo], { env: { ...env, CLAUDE_BRIDGE_OWNER_KEY: '' }, encoding: 'utf8' });
    expect(denied.status).not.toBe(0);
    expect(denied.stderr).toMatch(/root|owner key/i);
    expect(readOpen(repo, env)).not.toBeNull();
    expect(existsSync(markerPath())).toBe(true);

    const cleared = run(['clear', recorded.id, '--reason', 'owner decided', repo]);
    expect(cleared.status, cleared.stderr).toBe(0);
    expect(cleared.stdout).toContain(`cleared ${recorded.id} for ${repo}: owner decided`);
    expect(cleared.stdout).toMatch(/^note: a running bridge keeps an in-process latch until it records a verdict or restarts$/m);
    expect(readOpen(repo, env)).toBeNull();
    expect(existsSync(markerPath())).toBe(false);
    expect(readChain(repoStateDir(repo, env)).records.at(-1)).toMatchObject({ type: 'owner_clear', verdict_id: recorded.id, reason: 'owner decided', repo_key: repoKey(repo) });
    const after = run(['status', repo]).stdout;
    expect(after).toMatch(/^state: clear$/m);
    expect(after).toMatch(/^record failure marker: absent$/m);
  });

  it('keeps the verdict and the record-failure marker when the bridge rejects the clear', async () => {
    const recorded = record();
    await writeFile(markerPath(), `${JSON.stringify({ job_id: 'j2', recorded_at: '2026-10-10T00:00:00.000Z', message: 'm' })}\n`);
    const { privateKey } = generateKeyPairSync('ed25519');
    await writeFile(join(root, 'etc', 'other.key'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const rejected = run(['clear', recorded.id, '--reason', 'not the owner', repo], { CLAUDE_BRIDGE_OWNER_KEY: join(root, 'etc', 'other.key') });
    expect(rejected.status).toBe(1);
    expect(rejected.stderr).toMatch(/clear rejected: signature invalid/);
    expect(readOpen(repo, env)).not.toBeNull();
    expect(existsSync(markerPath())).toBe(true);
    expect(readChain(repoStateDir(repo, env)).records.at(-1)).toMatchObject({ type: 'rejected_clear', reason: 'signature invalid' });
  });

  it("lifts a wiped registered repository's reset with an owner clear of '*'", async () => {
    await mkdir(join(root, 'etc', 'repos'), { recursive: true });
    await writeFile(join(root, 'etc', 'repos', repoKey(repo)), `${resolve(repo)}\n`);
    record({ registered: true });
    await rm(repoStateDir(repo, env), { recursive: true, force: true });
    const before = run(['status', repo]).stdout;
    expect(before).toMatch(/^state: tampered \(registered repository has no verdict state; owner clear required\)$/m);
    expect(before).toMatch(/^registered: true$/m);
    const reset = run(['clear', '*', '--reason', 'owner reset', repo]);
    expect(reset.status, reset.stderr).toBe(0);
    expect(readChain(repoStateDir(repo, env)).records.map((r) => r.type)).toEqual(['state_reset_detected', 'owner_clear']);
    expect(run(['status', repo]).stdout).toMatch(/^state: clear$/m);
  });

  it('under root, clear and install refuse without a known owner account', () => {
    const recorded = record();
    const { SUDO_USER: _sudoUser, ...withoutSudo } = env;
    const forcedRoot = { ...withoutSudo, CLAUDE_BRIDGE_TEST_MODE: '1', CLAUDE_BRIDGE_TEST_FORCE_ROOT: '1' };
    for (const args of [['clear', recorded.id, '--reason', 'x', repo], ['install', '--dry-run', '--root', root, '--repo', repo]]) {
      const result = spawnSync(process.execPath, [CLI, ...args], { env: forcedRoot, encoding: 'utf8', cwd: repo });
      expect(result.status, args[0]).toBe(1);
      expect(result.stderr).toContain('run through sudo so the owner account is known');
    }
    expect(readOpen(repo, env)).not.toBeNull();
    expect(existsSync(join(root, 'opt', 'claude-bridge'))).toBe(false);
    // Outside test mode the switch is ignored: the non-root clear goes ahead with the test owner key.
    const { CLAUDE_BRIDGE_TEST_MODE: _mode, ...outsideTestMode } = forcedRoot;
    const ignored = spawnSync(process.execPath, [CLI, 'clear', recorded.id, '--reason', 'x', repo], { env: outsideTestMode, encoding: 'utf8', cwd: repo });
    expect(ignored.status, ignored.stderr).toBe(0);
    expect(readOpen(repo, env)).toBeNull();
  });
});

describe('installer dry run', () => {
  let root; let srcRepo; let claudeBin; let claudeLink; let checkout; let script;
  const CLAUDE_TEXT = '#!/bin/sh\necho fake claude\n';
  // Git in the scratch checkout, with no hook or signing from the caller's configuration.
  const git = (...args) => {
    const result = spawnSync('/usr/bin/git', ['-C', checkout, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', ...args], { encoding: 'utf8' });
    expect(result.status, result.stderr).toBe(0);
    return result.stdout.trim();
  };
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'bridge-install-'));
    // Every install runs from a committed scratch checkout of the plugin, so the installer's clean-tree checks hold
    // whatever state the working copy running the tests is in.
    checkout = join(root, 'checkout');
    await mkdir(join(checkout, 'plugins'), { recursive: true });
    await cp(resolve('plugins/claude-bridge'), join(checkout, 'plugins', 'claude-bridge'), { recursive: true });
    git('init', '-q');
    git('add', '-A');
    git('commit', '-q', '--no-verify', '-m', 'bridge');
    srcRepo = checkout;
    script = join(checkout, 'plugins', 'claude-bridge', 'bin', 'install.sh');
    // Laid out as Claude's native installer does: a versioned file and a link to it. --claude-bin takes the file.
    await mkdir(join(root, 'claude-install', 'versions'), { recursive: true });
    await mkdir(join(root, 'claude-install', 'bin'));
    claudeBin = join(root, 'claude-install', 'versions', '2.1.0');
    await writeFile(claudeBin, CLAUDE_TEXT, { mode: 0o755 });
    claudeLink = join(root, 'claude-install', 'bin', 'claude');
    await symlink(claudeBin, claudeLink);
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });
  // HOME is a path the installer must not write to: with --root every path it writes is under root.
  const install = (installRoot, extra = [], using = script) => spawnSync('/bin/bash', [using, '--dry-run', '--root', installRoot, '--repo', srcRepo, '--claude-bin', claudeBin, ...extra], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
  const versionOf = async (plugin = 'plugins/claude-bridge') => JSON.parse(await readFile(join(plugin, '.codex-plugin', 'plugin.json'), 'utf8')).version;

  // INSTALLED-FROM parsed into a map of its `key: value` lines.
  const installedFrom = async (opt, version) => Object.fromEntries(
    (await readFile(join(opt, version, 'INSTALLED-FROM'), 'utf8')).split('\n').filter(Boolean)
      .map((line) => { const at = line.indexOf(': '); return [line.slice(0, at), line.slice(at + 2)]; }),
  );


  it('lays out the protected install, keys, registration, seeded state, hooks and cache, and is idempotent', async () => {
    const first = install(root);
    expect(first.status, first.stderr).toBe(0);
    const version = await versionOf();
    const opt = join(root, 'opt', 'claude-bridge');
    const etc = join(root, 'etc', 'claude-bridge');
    expect((await stat(join(opt, version, 'mcp', 'server.mjs'))).isFile()).toBe(true);
    expect((await stat(join(opt, version, 'hooks', 'bridge_hook.py'))).isFile()).toBe(true);
    expect((await stat(join(opt, version, 'bin', 'claude-bridge'))).isFile()).toBe(true);
    expect((await stat(join(opt, 'current'))).isDirectory()).toBe(true);
    expect((await stat(join(etc, 'owner.key'))).mode & 0o777).toBe(0o400);
    expect((await readdir(etc)).filter((name) => name.startsWith('.keygen'))).toEqual([]);
    expect(await readFile(join(opt, version, 'owner.pub'), 'utf8')).toBe(await readFile(join(etc, 'owner.pub'), 'utf8'));
    expect((await readFile(join(etc, 'repos', repoKey(srcRepo)), 'utf8')).trim()).toBe(srcRepo);
    // The Claude binary the bridge runs is a copy pinned inside the install, executable.
    const pinned = join(opt, version, 'claude', 'claude');
    expect(await readFile(pinned, 'utf8')).toBe(CLAUDE_TEXT);
    expect((await stat(pinned)).mode & 0o111).toBe(0o111);
    expect(first.stdout).toContain(`pinned Claude binary ${join(root, 'claude-install', 'versions', '2.1.0')}`);
    const installedMcp = JSON.parse(await readFile(join(opt, version, '.mcp.json'), 'utf8'));
    expect(installedMcp.mcpServers.claude_bridge.command).toBe('/usr/bin/node');
    expect(installedMcp.mcpServers.claude_bridge.args[0]).toBe(join(opt, 'current', 'mcp', 'server.mjs'));

    const stateEnv = { CLAUDE_BRIDGE_STATE_DIR: join(root, 'state') };
    expect(first.stdout).toMatch(/^seeded verdict state$/m);
    expect(await readFile(join(repoStateDir(srcRepo, stateEnv), 'verdicts.jsonl'), 'utf8')).toBe('');
    expect(JSON.parse(await readFile(join(repoStateDir(srcRepo, stateEnv), 'head.json'), 'utf8'))).toEqual({ hash: '', count: 0 });

    expect((await readdir(join(root, '.codex'))).filter((name) => name.startsWith('hooks.json.tmp'))).toEqual([]);
    const hooks = JSON.parse(await readFile(join(root, '.codex', 'hooks.json'), 'utf8'));
    expect(hooks.hooks.Stop[0].hooks[0].command).toBe(`/usr/bin/python3 -I ${join(opt, 'current', 'hooks', 'bridge_hook.py')}`);
    // Registered in the exact expected shape for all five events; only Codex trust is missing.
    const intact = hooksIntact({ CODEX_HOME: join(root, '.codex'), CLAUDE_BRIDGE_PROTECTED_ROOT: opt });
    expect(intact.reasons).toEqual(['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop'].map((event) => `${event} hook is not yet trusted in Codex`));
    // Trusted as Codex writes the entries, the rendered registration reads intact through the TOML reader.
    const hooksFile = join(root, '.codex', 'hooks.json');
    const trust = ['session_start', 'user_prompt_submit', 'pre_tool_use', 'post_tool_use', 'stop']
      .map((key) => `[hooks.state."${hooksFile}:${key}:0:0"]\ntrusted_hash = "sha256:${'cd'.repeat(32)}"\nenabled = true\n`);
    await writeFile(join(root, '.codex', 'config.toml'), ['[hooks.state]\n', ...trust].join('\n'));
    expect(hooksIntact({ CODEX_HOME: join(root, '.codex'), CLAUDE_BRIDGE_PROTECTED_ROOT: opt })).toEqual({ intact: true, reasons: [] });
    const cacheDir = join(root, '.codex', 'plugins', 'cache', 'claude-bridge-local', 'claude-bridge', version);
    expect(await readFile(join(cacheDir, '.mcp.json'), 'utf8')).toBe(await readFile(join(opt, version, '.mcp.json'), 'utf8'));
    // The cache copy is locked by default: root-owned and immutable like the install.
    expect(first.stdout).toContain(`dry-run: skipped chown -R root:root ${cacheDir}\n`);
    expect(first.stdout).not.toMatch(/--no-lock-cache/);
    expect(first.stdout).toMatch(/dry-run: skipped chattr/);
    // The staging tree is locked before it is swapped in and before anything is written under ~/.codex.
    const lockAt = first.stdout.search(/dry-run: skipped chown -R root:root .*\/\.staging-/);
    const hooksAt = first.stdout.indexOf(`dry-run: skipped chown -h root:root ${join(root, '.codex', 'hooks.json.tmp.')}`);
    expect(lockAt).toBeGreaterThan(-1);
    expect(hooksAt).toBeGreaterThan(lockAt);
    // The live install is the swapped-in tree.
    expect(first.stdout).toContain(`the live install is ${join(opt, version)}`);
    expect(first.stdout).toContain(`run: /usr/bin/node "${opt}/current/bin/claude-bridge" verify "${srcRepo}"`);
    expect(first.stdout).toContain(`to clear a verdict: sudo /usr/bin/node "${opt}/current/bin/claude-bridge" clear <verdict-id|*> --reason "<why>" "${srcRepo}"`);
    expect(first.stdout).toContain(`after the first install, always run clear from ${opt}/current/bin; upgrade with: sudo ${opt}/current/bin/install.sh --source "${srcRepo}"`);

    // The installed owner command runs from the protected layout and reads the seeded, registered state as clear.
    const installedCli = join(opt, 'current', 'bin', 'claude-bridge');
    const installedEnv = { ...process.env, HOME: root, CODEX_HOME: join(root, '.codex'), CLAUDE_BRIDGE_PROTECTED_ROOT: opt, CLAUDE_BRIDGE_ETC_DIR: etc, ...stateEnv };
    const installed = spawnSync(process.execPath, [installedCli, 'status', srcRepo], { env: installedEnv, encoding: 'utf8', cwd: root });
    expect(installed.status, installed.stderr).toBe(0);
    expect(installed.stderr).toBe('');
    expect(installed.stdout).toMatch(/^state: clear$/m);
    expect(installed.stdout).toMatch(/^registered: true$/m);
    expect(installed.stdout).toMatch(/^protection: unprotected \(server file owned by uid \d+, not root/m);
    expect(installed.stdout).toContain(`owner clears: verified against ${join(opt, 'current', 'owner.pub')}\n`);

    // The installed copy refuses to install over itself, and the install survives.
    const self = spawnSync(process.execPath, [installedCli, 'install', '--dry-run', '--root', root, '--repo', srcRepo], { env: installedEnv, encoding: 'utf8', cwd: root });
    expect(self.status).not.toBe(0);
    expect(self.stderr).toContain('run the installer from a repository checkout, not from the installed copy');
    expect(existsSync(join(opt, 'current', 'mcp', 'server.mjs'))).toBe(true);

    const keyBefore = await readFile(join(etc, 'owner.key'), 'utf8');
    const second = install(root);
    expect(second.status, second.stderr).toBe(0);
    expect(await readFile(join(etc, 'owner.key'), 'utf8')).toBe(keyBefore);
    expect(second.stdout).toMatch(/owner key present, kept/);
    expect(second.stdout).toMatch(/^verdict state present, kept$/m);
    expect(existsSync(join(root, 'home'))).toBe(false);
  });

  it('runs /usr/bin/node and a fixed PATH, whatever node the caller has on PATH', async () => {
    const bin = join(root, 'bin');
    await mkdir(bin);
    const marker = join(root, 'fake-node-ran');
    await writeFile(join(bin, 'node'), `#!/bin/sh\ntouch ${marker}\nexit 1\n`, { mode: 0o755 });
    const result = spawnSync('/bin/bash', [script, '--dry-run', '--root', root, '--repo', srcRepo, '--claude-bin', claudeBin], { env: { ...process.env, HOME: join(root, 'home'), PATH: `${bin}:${process.env.PATH}`, NODE_OPTIONS: `--require ${join(root, 'missing.cjs')}` }, encoding: 'utf8' });
    expect(result.status, result.stderr).toBe(0);
    expect(existsSync(marker)).toBe(false);
  });

  it('pins exactly one regular file: a directory, a link or a missing --claude-bin is refused before anything is written', async () => {
    const versionDir = join(root, 'claude-dir', '2.2.0');
    await mkdir(versionDir, { recursive: true });
    await writeFile(join(versionDir, 'claude'), CLAUDE_TEXT, { mode: 0o755 });
    const cases = [
      [versionDir, 'is not a regular file'],
      [claudeLink, 'is a symbolic link; pass the file it points to'],
      [join(root, 'missing'), 'Claude binary not found'],
    ];
    for (const [index, [target, message]] of cases.entries()) {
      const fresh = join(root, `target-${index}`);
      await mkdir(fresh);
      const refused = spawnSync('/bin/bash', [script, '--dry-run', '--root', fresh, '--repo', srcRepo, '--claude-bin', target], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
      expect(refused.status, target).toBe(1);
      expect(refused.stderr).toContain(message);
      expect(existsSync(join(fresh, 'opt'))).toBe(false);
    }
  });

  it('touches only its own fresh file when it pins the Claude binary', async () => {
    // xtrace shows every command the installer runs, run_root ones included.
    const traced = spawnSync('/bin/bash', ['-x', script, '--dry-run', '--root', root, '--repo', srcRepo, '--claude-bin', claudeBin], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(traced.status, traced.stderr).toBe(0);
    const commands = traced.stderr.split('\n').filter((line) => /^\++ /.test(line)).map((line) => line.replace(/^\++ /, ''));
    const modeChanges = commands.filter((line) => /^(?:run_root |lock_step )?(?:chmod|chown)\b/.test(line));
    // Nothing under the owner's Claude install is ever chown'ed or chmod'ed, and nothing is chown'ed to the owner.
    expect(modeChanges.filter((line) => line.includes(join(root, 'claude-install')))).toEqual([]);
    expect(modeChanges.filter((line) => /chown (?!-R root:root|-h root:root|root:root)/.test(line))).toEqual([]);
    // The only direct chmod on a claude binary is the 755 on the one fresh file root created in the staging tree.
    const claudeChmods = modeChanges.filter((line) => /^chmod 755 .*\/claude\/claude$/.test(line));
    expect(claudeChmods).toHaveLength(1);
    expect(claudeChmods[0]).toMatch(/\/\.staging-[^/]*\/claude\/claude$/);
    expect(commands.filter((line) => /^cp /.test(line) && line.includes('claude-install'))).toEqual([]);
  });

  it('leaves the Codex cache copy owner-writable only with --no-lock-cache, and warns', async () => {
    const result = install(root, ['--no-lock-cache']);
    expect(result.status, result.stderr).toBe(0);
    const cacheDir = join(root, '.codex', 'plugins', 'cache', 'claude-bridge-local', 'claude-bridge', await versionOf());
    expect(existsSync(join(cacheDir, '.mcp.json'))).toBe(true);
    expect(result.stdout).not.toContain(`dry-run: skipped chown -R root:root ${cacheDir}`);
    expect(result.stderr).toContain('warning: --no-lock-cache leaves the Codex cache copy owner-writable');
    expect(result.stderr).toContain('the hook then denies every bridge call');
    // The old flag is the default now and still accepted.
    const locked = install(root, ['--lock-cache']);
    expect(locked.status, locked.stderr).toBe(0);
    expect(locked.stdout).toContain(`dry-run: skipped chown -R root:root ${cacheDir}\n`);
  });

  it('upgrades from the installed copy with --source, refuses a dirty checkout without --allow-dirty, and records the source', async () => {
    const head = git('rev-parse', 'HEAD');
    const tree = git('rev-parse', 'HEAD:plugins/claude-bridge');
    const version = await versionOf();
    // The first install runs from the checkout and records it, with its source commit and tree.
    const first = install(root);
    expect(first.status, first.stderr).toBe(0);
    let from = await installedFrom(join(root, 'opt', 'claude-bridge'), version);
    expect(from).toMatchObject({ source: checkout, source_commit: head, source_tree: tree, clean: 'yes' });
    const installed = join(root, 'opt', 'claude-bridge', 'current', 'bin', 'install.sh');
    expect(install(root, [], installed).stderr).toContain('run the installer from a repository checkout, not from the installed copy');
    const upgrade = install(root, ['--source', checkout], installed);
    expect(upgrade.status, upgrade.stderr).toBe(0);
    expect(upgrade.stdout).toContain(`installing from ${checkout} at ${head} (plugins/claude-bridge tree ${tree})`);
    from = await installedFrom(join(root, 'opt', 'claude-bridge'), version);
    expect(from).toMatchObject({ source_commit: head, source_tree: tree, clean: 'yes' });
    expect(await readFile(join(root, 'opt', 'claude-bridge', version, 'mcp', 'server.mjs'), 'utf8')).toBe(await readFile(join(checkout, 'plugins', 'claude-bridge', 'mcp', 'server.mjs'), 'utf8'));
    // An untracked file under the plugin is refused, unless the owner allows it.
    await writeFile(join(checkout, 'plugins', 'claude-bridge', 'mcp', 'extra.mjs'), '// not committed\n');
    const dirty = install(root, ['--source', checkout], installed);
    expect(dirty.status).toBe(1);
    expect(dirty.stderr).toContain(`refusing to install: ${checkout} has uncommitted, untracked or ignored files in plugins/claude-bridge`);
    expect(dirty.stderr).toContain('?? plugins/claude-bridge/mcp/extra.mjs');
    const allowed = install(root, ['--source', checkout, '--allow-dirty'], installed);
    expect(allowed.status, allowed.stderr).toBe(0);
    // The extra file is not in the committed tree, so the copy is not that tree: clean: no.
    from = await installedFrom(join(root, 'opt', 'claude-bridge'), version);
    expect(from).toMatchObject({ source_commit: head, source_tree: tree, clean: 'no' });
    // A source that is not a checkout of the bridge is refused.
    const bogus = install(root, ['--source', join(root, 'home-nothing')], installed);
    expect(bogus.status).not.toBe(0);
  });

  const canonicalFile = () => join(checkout, 'plugins', 'claude-bridge', 'mcp', 'canonical.mjs');

  it('refuses a first install from a checkout with uncommitted or hidden changes, as it does an upgrade', async () => {
    const original = await readFile(canonicalFile(), 'utf8');
    await writeFile(canonicalFile(), `${original}// an edit\n`);
    let refused = install(join(await mkdtemp(join(root, 'a-')), ''));
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain('has uncommitted, untracked or ignored files in plugins/claude-bridge');
    for (const flag of ['--skip-worktree', '--assume-unchanged']) {
      git('update-index', flag, 'plugins/claude-bridge/mcp/canonical.mjs');
      expect(git('status', '--porcelain', '--', 'plugins/claude-bridge')).toBe('');
      const fresh = await mkdtemp(join(root, 'b-'));
      refused = install(fresh);
      expect(refused.status, flag).toBe(1);
      expect(refused.stderr).toContain('hidden from git status (skip-worktree or assume-unchanged)');
      expect(refused.stderr).toContain('plugins/claude-bridge/mcp/canonical.mjs');
      expect(existsSync(join(fresh, 'opt'))).toBe(false);
      git('update-index', flag.replace('--', '--no-'), 'plugins/claude-bridge/mcp/canonical.mjs');
    }
  });

  it('checks what root copied against the committed tree, and records clean: no and tree: unverified under --allow-dirty', async () => {
    // The checkout writes this file with CRLF line ends: git status is clean, but the bytes are not the blob.
    await writeFile(join(checkout, '.gitattributes'), 'plugins/claude-bridge/mcp/canonical.mjs text eol=crlf\n');
    git('add', '.gitattributes');
    git('commit', '-q', '--no-verify', '-m', 'attributes');
    await rm(canonicalFile());
    git('checkout', '--', 'plugins/claude-bridge/mcp/canonical.mjs');
    expect(await readFile(canonicalFile(), 'utf8')).toContain('\r\n');
    expect(git('status', '--porcelain', '--ignored', '--', 'plugins/claude-bridge')).toBe('');
    const version = await versionOf();
    const opt = join(root, 'opt', 'claude-bridge');
    const refused = install(root);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain('refusing to install: the copied files are not the committed tree plugins/claude-bridge at');
    expect(refused.stderr).toContain('mcp/canonical.mjs');
    expect(refused.stderr).toContain('the staged copy was removed');
    // The staged tree was removed and no install landed.
    expect(existsSync(join(opt, version))).toBe(false);
    expect((await readdir(opt).catch(() => [])).filter((name) => name.startsWith('.staging-'))).toEqual([]);
    const allowed = install(root, ['--allow-dirty']);
    expect(allowed.status, allowed.stderr).toBe(0);
    const head = git('rev-parse', 'HEAD');
    const from = await installedFrom(opt, version);
    expect(from).toMatchObject({ source: checkout, source_commit: head, clean: 'no' });
  });

  it('refuses a first install from a source that is not a Git checkout unless --allow-dirty', async () => {
    const plain = join(root, 'plain');
    await mkdir(join(plain, '.git'), { recursive: true });
    await mkdir(join(plain, 'plugins'));
    await cp(join(checkout, 'plugins', 'claude-bridge'), join(plain, 'plugins', 'claude-bridge'), { recursive: true });
    const target = await mkdtemp(join(root, 't-'));
    const plainScript = join(plain, 'plugins', 'claude-bridge', 'bin', 'install.sh');
    const refused = spawnSync('/bin/bash', [plainScript, '--dry-run', '--root', target, '--repo', plain, '--claude-bin', claudeBin], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain(`cannot read the Git state of ${plain}`);
    expect(existsSync(join(target, 'opt'))).toBe(false);
    const allowed = spawnSync('/bin/bash', [plainScript, '--dry-run', '--root', target, '--repo', plain, '--claude-bin', claudeBin, '--allow-dirty'], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(allowed.status, allowed.stderr).toBe(0);
    const from = await installedFrom(join(target, 'opt', 'claude-bridge'), await versionOf());
    // No readable Git state: source commit and tree are unknown, clean: no; the subtree ids are still root-computed.
    expect(from).toMatchObject({ source: plain, source_commit: 'unknown', source_tree: 'unknown', clean: 'no' });
    expect(from.installed_tree_mcp).toMatch(/^[0-9a-f]{40}$/);
  });

  it('builds in a staging tree and swaps, so a post-copy abort leaves the previous install live', async () => {
    const opt = join(root, 'opt', 'claude-bridge');
    const version = await versionOf();
    const first = install(root);
    expect(first.status, first.stderr).toBe(0);
    const serverBefore = await readFile(join(opt, version, 'mcp', 'server.mjs'), 'utf8');
    // A second install whose copy fails verification after the copy but before the swap: CRLF bytes that git
    // status reads as clean but that are not the committed blob.
    await writeFile(join(checkout, '.gitattributes'), 'plugins/claude-bridge/mcp/canonical.mjs text eol=crlf\n');
    git('add', '.gitattributes');
    git('commit', '-q', '--no-verify', '-m', 'attributes');
    await rm(canonicalFile());
    git('checkout', '--', 'plugins/claude-bridge/mcp/canonical.mjs');
    const second = install(root);
    expect(second.status).toBe(1);
    expect(second.stderr).toContain('the staged copy was removed');
    // The previous install is untouched and still the live tree; no staging directory is left behind.
    expect(await readFile(join(opt, version, 'mcp', 'server.mjs'), 'utf8')).toBe(serverBefore);
    expect((await stat(join(opt, 'current'))).isDirectory()).toBe(true);
    expect(await readFile(join(opt, 'current', 'mcp', 'server.mjs'), 'utf8')).toBe(serverBefore);
    expect((await readdir(opt)).filter((name) => name.startsWith('.staging-') || name.includes('.old-'))).toEqual([]);
  });

  it('refuses a symlink, a FIFO or any non-regular file in the copied tree before root reads it', async () => {
    const dest = join(root, 'dest');
    await mkdir(join(dest, 'skills'), { recursive: true });
    const scan = () => spawnSync('/bin/bash', [script, '--dry-run', '--root', root, '--repo', srcRepo, '--self-test-dest-scan', dest], { env: { ...process.env, HOME: join(root, 'home'), CLAUDE_BRIDGE_TEST_MODE: '1' }, encoding: 'utf8' });
    expect(scan().status).toBe(0);
    const fifo = join(dest, 'skills', 'pipe');
    expect(spawnSync('/usr/bin/mkfifo', [fifo]).status).toBe(0);
    const withFifo = scan();
    expect(withFifo.status).toBe(1);
    expect(withFifo.stderr).toContain(`${fifo} is not a regular file or directory`);
    await rm(fifo);
    await symlink(join(root, 'victim'), join(dest, 'skills', 'planted'));
    const withLink = scan();
    expect(withLink.status).toBe(1);
    expect(withLink.stderr).toContain(`${join(dest, 'skills', 'planted')} is a symbolic link`);
  });

  it('never runs the owner login shell or profile to find Claude', async () => {
    const marker = join(root, 'profile-ran');
    await mkdir(join(root, 'home', '.local', 'bin'), { recursive: true });
    await writeFile(join(root, 'home', '.bash_profile'), `printf x > ${marker}\n`);
    await writeFile(join(root, 'home', '.bashrc'), `printf x > ${marker}\n`);
    await writeFile(join(root, 'home', '.local', 'bin', 'claude'), CLAUDE_TEXT, { mode: 0o755 });
    // No --claude-bin: the default is found by trying the fixed candidates as the owner, no login shell.
    const result = spawnSync('/bin/bash', [script, '--dry-run', '--root', root, '--repo', srcRepo], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(result.status, result.stderr).toBe(0);
    expect(existsSync(marker)).toBe(false);
    const pinned = join(root, 'opt', 'claude-bridge', await versionOf(), 'claude', 'claude');
    expect(await readFile(pinned, 'utf8')).toBe(CLAUDE_TEXT);
  });

  it('records root-computed subtree ids equal to the checkout subtrees for a clean install', async () => {
    const opt = join(root, 'opt', 'claude-bridge');
    const version = await versionOf();
    expect(install(root).status).toBe(0);
    const from = await installedFrom(opt, version);
    expect(from.source).toBe(checkout);
    expect(from.source_commit).toBe(git('rev-parse', 'HEAD'));
    expect(from.source_tree).toBe(git('rev-parse', 'HEAD:plugins/claude-bridge'));
    expect(from.clean).toBe('yes');
    for (const sub of ['mcp', 'hooks', 'bin', '.codex-plugin', 'skills']) {
      expect(from[`installed_tree_${sub}`], sub).toBe(git('rev-parse', `HEAD:plugins/claude-bridge/${sub}`));
    }
    expect(from.installed_mcp_json_source).toBe(git('rev-parse', 'HEAD:plugins/claude-bridge/.mcp.json'));
  });

  it('computes installed subtree ids from the copied bytes, not the owner object store, under a refs/replace forgery', async () => {
    const opt = join(root, 'opt', 'claude-bridge');
    const version = await versionOf();
    const genuineMcp = git('rev-parse', 'HEAD:plugins/claude-bridge/mcp');
    const genuineTree = git('rev-parse', 'HEAD:plugins/claude-bridge');
    // Forge an mcp file that the repo-key step does not import, then make git serve the forged plugin tree for the
    // genuine one. With replace honoured the checkout reads clean; the installer uses --no-replace-objects.
    const forgedFile = join(checkout, 'plugins', 'claude-bridge', 'mcp', 'isolation.mjs');
    await writeFile(forgedFile, '// forged isolation\n');
    git('add', '-A');
    git('commit', '-q', '--no-verify', '-m', 'forged');
    const forgedMcp = git('rev-parse', 'HEAD:plugins/claude-bridge/mcp');
    git('replace', genuineTree, git('rev-parse', 'HEAD:plugins/claude-bridge'));
    git('reset', '-q', '--hard', 'HEAD~1'); // HEAD back to genuine; the checkout resolves through replace to forged
    expect(await readFile(forgedFile, 'utf8')).toBe('// forged isolation\n');
    expect(git('status', '--porcelain', '--', 'plugins/claude-bridge')).toBe('');
    // --no-replace-objects sees the forged working files against the genuine committed tree: refused.
    const refused = install(root);
    expect(refused.status).toBe(1);
    // --allow-dirty records ids root computed from the copied (forged) bytes, and the owner-reported genuine tree.
    expect(install(root, ['--allow-dirty']).status).toBe(0);
    const from = await installedFrom(opt, version);
    expect(from.clean).toBe('no');
    expect(from.source_tree).toBe(genuineTree);
    expect(from.installed_tree_mcp).toBe(forgedMcp);
    expect(from.installed_tree_mcp).not.toBe(genuineMcp);
  });

  it('refuses a sha256 checkout', async () => {
    const sha256 = join(root, 'sha256');
    await mkdir(join(sha256, 'plugins'), { recursive: true });
    await cp(join(checkout, 'plugins', 'claude-bridge'), join(sha256, 'plugins', 'claude-bridge'), { recursive: true });
    const g = (...args) => spawnSync('/usr/bin/git', ['-C', sha256, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', ...args], { encoding: 'utf8' });
    expect(g('init', '-q', '--object-format=sha256').status).toBe(0);
    g('add', '-A'); g('commit', '-q', '--no-verify', '-m', 'bridge');
    const target = await mkdtemp(join(root, 's-'));
    const result = spawnSync('/bin/bash', [join(sha256, 'plugins', 'claude-bridge', 'bin', 'install.sh'), '--dry-run', '--root', target, '--repo', sha256, '--claude-bin', claudeBin], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('sha256 repositories are not supported');
    expect(existsSync(join(target, 'opt'))).toBe(false);
  });

  it('reads the pinned Claude binary with a 1 GiB cap, and refuses a file that reaches it', async () => {
    const traced = spawnSync('/bin/bash', ['-x', script, '--dry-run', '--root', root, '--repo', srcRepo, '--claude-bin', claudeBin], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(traced.status, traced.stderr).toBe(0);
    expect(traced.stderr).toMatch(/\bhead -c 1073741824\b/);
    expect(traced.stderr).not.toMatch(/\bcat -- .*claude-install/);
    // A sparse file at the cap is refused before it can fill /opt.
    const big = join(root, 'big-claude');
    expect(spawnSync('/usr/bin/truncate', ['-s', '1073741824', big]).status).toBe(0);
    const target = await mkdtemp(join(root, 'cap-'));
    const refused = spawnSync('/bin/bash', [script, '--dry-run', '--root', target, '--repo', srcRepo, '--claude-bin', big], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/Claude binary .* is 1073741824 bytes or larger/);
    expect(existsSync(join(target, 'opt', 'claude-bridge', await versionOf(), 'claude', 'claude'))).toBe(false);
  });

  it('escapes the install root for sed', async () => {
    const odd = join(root, 'r&o#ot');
    await mkdir(odd);
    const result = install(odd);
    expect(result.status, result.stderr).toBe(0);
    const opt = join(odd, 'opt', 'claude-bridge');
    const hooks = JSON.parse(await readFile(join(odd, '.codex', 'hooks.json'), 'utf8'));
    expect(hooks.hooks.Stop[0].hooks[0].command).toBe(`/usr/bin/python3 -I ${join(opt, 'current', 'hooks', 'bridge_hook.py')}`);
    const mcp = JSON.parse(await readFile(join(opt, await versionOf(), '.mcp.json'), 'utf8'));
    expect(mcp.mcpServers.claude_bridge.args[0]).toBe(join(opt, 'current', 'mcp', 'server.mjs'));
  });

  it('refuses a repository without .git', async () => {
    const result = spawnSync('/bin/bash', [script, '--dry-run', '--root', root, '--repo', root], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`refusing to install: ${root} has no .git`);
    expect(existsSync(join(root, 'opt'))).toBe(false);
  });

  it('removes the staging tree and leaves the previous install when a build step aborts', async () => {
    const opt = join(root, 'opt', 'claude-bridge');
    const version = await versionOf();
    // First install succeeds; record the live tree.
    expect(install(root).status).toBe(0);
    const serverBefore = await readFile(join(opt, version, 'mcp', 'server.mjs'), 'utf8');
    // A second install whose seed step aborts (a file where the per-run state directory belongs); the abort happens
    // while the staging tree is being built, before the swap.
    await rm(join(root, 'state'), { recursive: true, force: true });
    await writeFile(join(root, 'state'), 'a file where the state directory belongs\n');
    const result = install(root);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`install aborted; the previous install is live at ${join(opt, version)}`);
    // The previous install is intact, current points at it, and the staging tree is gone.
    expect(await readFile(join(opt, version, 'mcp', 'server.mjs'), 'utf8')).toBe(serverBefore);
    expect(await readFile(join(opt, 'current', 'mcp', 'server.mjs'), 'utf8')).toBe(serverBefore);
    expect((await readdir(opt)).filter((name) => name.startsWith('.staging-') || name.includes('.old-'))).toEqual([]);
  });

  it('leaves the owner key at 0400 whatever aborts the install', async () => {
    const etc = join(root, 'etc', 'claude-bridge');
    await mkdir(etc, { recursive: true });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    await writeFile(join(etc, 'owner.key'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o644 });
    await chmod(join(etc, 'owner.key'), 0o644);
    await writeFile(join(etc, 'owner.pub'), publicKey.export({ type: 'spki', format: 'pem' }));
    // A file where the state directory belongs makes the seed step abort after the copy.
    await writeFile(join(root, 'state'), 'not a directory\n');
    const result = install(root);
    expect(result.status).not.toBe(0);
    expect((await stat(join(etc, 'owner.key'))).mode & 0o777).toBe(0o400);
  });

  it('refuses a half-generated owner key pair before touching the install', async () => {
    await mkdir(join(root, 'etc', 'claude-bridge'), { recursive: true });
    await writeFile(join(root, 'etc', 'claude-bridge', 'owner.pub'), 'orphan\n');
    const result = install(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('remove the half-generated pair');
    expect(result.stderr).not.toContain('install aborted');
    expect(existsSync(join(root, 'opt'))).toBe(false);
  });

  it('refuses a symlink planted at hooks.json and leaves its target untouched', async () => {
    const victim = join(root, 'victim');
    await writeFile(victim, 'victim\n');
    await mkdir(join(root, '.codex'), { recursive: true });
    await symlink(victim, join(root, '.codex', 'hooks.json'));
    const result = install(root);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`refusing to install: ${join(root, '.codex', 'hooks.json')} is a symbolic link`);
    expect(await readFile(victim, 'utf8')).toBe('victim\n');
    expect(existsSync(join(root, 'opt'))).toBe(false);
  });

  it('refuses a symlink planted at the Codex plugin cache and writes nothing through it', async () => {
    const victim = join(root, 'victim');
    await mkdir(victim, { recursive: true });
    await writeFile(join(victim, 'kept'), 'kept\n');
    await mkdir(join(root, '.codex', 'plugins'), { recursive: true });
    await symlink(victim, join(root, '.codex', 'plugins', 'cache'));
    const result = install(root);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`refusing to install: ${join(root, '.codex', 'plugins', 'cache')} is a symbolic link`);
    expect(await readdir(victim)).toEqual(['kept']);
  });

  it('refuses a symlink in the source tree before anything is copied', async () => {
    const src = join(root, 'src', 'claude-bridge');
    await cp(resolve('plugins/claude-bridge'), src, { recursive: true });
    await symlink(join(root, 'victim.mjs'), join(src, 'mcp', 'planted.mjs'));
    const target = join(root, 'target');
    await mkdir(target);
    const result = install(target, [], join(src, 'bin', 'install.sh'));
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`refusing to install: ${join(src, 'mcp', 'planted.mjs')} is a symbolic link`);
    expect(existsSync(join(target, 'opt'))).toBe(false);
  });

  // A scratch copy of the plugin source; the installer always takes SRC from its own location.
  const scratchSource = async () => {
    const src = join(root, 'src', 'claude-bridge');
    await cp(resolve('plugins/claude-bridge'), src, { recursive: true });
    const target = join(root, 'target');
    await mkdir(target);
    return { src, target, run: () => install(target, [], join(src, 'bin', 'install.sh')) };
  };

  it('refuses a plugin version that is not MAJOR.MINOR.PATCH before root builds a path from it', async () => {
    const { src, target, run } = await scratchSource();
    const manifest = JSON.parse(await readFile(join(src, '.codex-plugin', 'plugin.json'), 'utf8'));
    await writeFile(join(src, '.codex-plugin', 'plugin.json'), `${JSON.stringify({ ...manifest, version: '../../escape' }, null, 2)}\n`);
    const result = run();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('plugin version is not MAJOR.MINOR.PATCH');
    expect(existsSync(join(target, 'opt'))).toBe(false);
    expect(existsSync(join(target, 'escape'))).toBe(false);
  });

  it('refuses a repository key that is not 20 hex digits before root builds a path from it', async () => {
    const { src, target, run } = await scratchSource();
    await writeFile(join(src, 'mcp', 'verdict.mjs'), "export const repoKey = () => '../../x';\n");
    const result = run();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('repository key is not a 20-hex-digit string');
    expect(existsSync(join(target, 'etc'))).toBe(false);
    expect(existsSync(join(target, 'x'))).toBe(false);
  });

  it('refuses when the repository code computes a different repository key than root does', async () => {
    const { src, target, run } = await scratchSource();
    await writeFile(join(src, 'mcp', 'verdict.mjs'), "export const repoKey = () => '0123456789abcdef0123';\n");
    const result = run();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('repository key mismatch');
    expect(existsSync(join(target, 'etc'))).toBe(false);
    expect(existsSync(join(target, 'opt'))).toBe(false);
  });

  it('scans the source for links before reading the plugin manifest', async () => {
    const { src, target, run } = await scratchSource();
    const manifest = JSON.parse(await readFile(join(src, '.codex-plugin', 'plugin.json'), 'utf8'));
    const outside = join(root, 'outside-plugin.json');
    await writeFile(outside, `${JSON.stringify({ ...manifest, version: 'not-a-version' })}\n`);
    await rm(join(src, '.codex-plugin', 'plugin.json'));
    await symlink(outside, join(src, '.codex-plugin', 'plugin.json'));
    const result = run();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(`refusing to install: ${join(src, '.codex-plugin', 'plugin.json')} is a symbolic link`);
    expect(result.stderr).not.toContain('plugin version');
    expect(existsSync(join(target, 'opt'))).toBe(false);
  });

  it('refuses a repository path containing a newline', async () => {
    const odd = join(root, 're\npo');
    await mkdir(join(odd, '.git'), { recursive: true });
    const result = spawnSync('/bin/bash', [script, '--dry-run', '--root', root, '--repo', odd], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('repository path contains a newline');
    expect(existsSync(join(root, 'etc'))).toBe(false);
  });

  it('reports no install is live when a first install cannot even create its staging tree', async () => {
    const opt = join(root, 'opt', 'claude-bridge');
    await mkdir(opt, { recursive: true });
    await chmod(opt, 0o555); // the staging directory under $OPT cannot be created
    try {
      const result = install(root);
      expect(result.status).not.toBe(0);
      // A refusal before the staging tree is even created leaves nothing behind and nothing to relock.
      expect(result.stderr).toMatch(/cannot create directory .*\.staging-/);
      expect(result.stderr).not.toContain('install aborted');
      expect(existsSync(join(opt, await versionOf()))).toBe(false);
    } finally { await chmod(opt, 0o755); }
  });

  it('scans the install tree for links (test-mode self-test, dry run only)', async () => {
    const dest = join(root, 'dest');
    await mkdir(join(dest, 'skills'), { recursive: true });
    const scan = (env) => spawnSync('/bin/bash', [script, '--dry-run', '--root', root, '--repo', srcRepo, '--self-test-dest-scan', dest], { env: { ...process.env, HOME: join(root, 'home'), ...env }, encoding: 'utf8' });
    const clean = scan({ CLAUDE_BRIDGE_TEST_MODE: '1' });
    expect(clean.status, clean.stderr).toBe(0);
    expect(clean.stdout).toContain(`install tree scan clean: ${dest}`);
    await symlink(join(root, 'victim'), join(dest, 'skills', 'planted'));
    const linked = scan({ CLAUDE_BRIDGE_TEST_MODE: '1' });
    expect(linked.status).toBe(1);
    expect(linked.stderr).toContain(`refusing to install: ${join(dest, 'skills', 'planted')} is a symbolic link`);
    const { CLAUDE_BRIDGE_TEST_MODE: _mode, ...outsideTestMode } = process.env;
    const refused = spawnSync('/bin/bash', [script, '--dry-run', '--root', root, '--repo', srcRepo, '--self-test-dest-scan', dest], { env: { ...outsideTestMode, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(refused.status).toBe(2);
    expect(refused.stderr).toContain('--self-test-dest-scan needs --dry-run and CLAUDE_BRIDGE_TEST_MODE=1');
    expect(existsSync(join(root, 'opt'))).toBe(false);
  });

  it('refuses --root without --dry-run, so owner commands never run as root against a scratch root', () => {
    const result = spawnSync('/bin/bash', [script, '--root', root, '--repo', srcRepo, '--claude-bin', claudeBin], { env: { ...process.env, HOME: join(root, 'home') }, encoding: 'utf8' });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('--root is for --dry-run previews only');
    expect(existsSync(join(root, 'opt'))).toBe(false);
  });

  it('refuses a dry run without --root, so a preview never writes the real system', () => {
    const result = spawnSync('/bin/bash', [script, '--dry-run', '--repo', srcRepo], { env: { ...process.env, HOME: root }, encoding: 'utf8' });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/--dry-run needs --root/);
    expect(result.stdout).toBe('');
  });
  it('never runs an owner command against the root-only staging tree (the owner cannot open it)', async () => {
    const script = await readFile(new URL('../../../../plugins/claude-bridge/bin/install.sh', import.meta.url), 'utf8');
    const offending = script.split('\n').filter((line) => {
      if (!line.includes('as_owner') || !line.includes('$STAGE')) return false;
      // An owner process may write to a root-opened redirect into staging; it may never be handed a staging path.
      const redirect = line.indexOf('>');
      const stage = line.indexOf('$STAGE');
      return redirect === -1 || stage < redirect;
    });
    expect(offending).toEqual([]);
    expect(script).toMatch(/seedState[\s\S]*"\$DEST\/mcp\/verdict\.mjs"/);
  });
});
