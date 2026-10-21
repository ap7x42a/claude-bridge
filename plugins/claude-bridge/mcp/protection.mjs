// plugins/claude-bridge/mcp/protection.mjs
import { execFileSync } from 'node:child_process';
import { accessSync, constants, existsSync, lstatSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { dirname, join, resolve, relative, isAbsolute, sep } from 'node:path';
import { repoKey } from './verdict.mjs';

const DEFAULT_PROTECTED_ROOT = '/opt/claude-bridge';
const DEFAULT_ETC_DIR = '/etc/claude-bridge';
const NO_OWNER_KEY = 'no owner public key; owner clears unverified';
export const CLAUDE_BINARY_WRITABLE = 'Claude binary is owner-writable';
export const CLAUDE_BINARY_MISSING = 'Claude binary is missing';
export const CACHE_LAUNCH_CONFIG_MISMATCH = 'Codex cache launch config is not the installed one';
export const LOADER_VARIABLES_SET = 'loader variables set';
// Variables that load code into a process before its own code runs.
const LOADER_VARIABLES = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'NODE_OPTIONS'];

export function protectedRoot(env = process.env) { return env.CLAUDE_BRIDGE_PROTECTED_ROOT || DEFAULT_PROTECTED_ROOT; }
export function etcDir(env = process.env) { return env.CLAUDE_BRIDGE_ETC_DIR || DEFAULT_ETC_DIR; }

const isInside = (path, parent) => {
  const rel = relative(parent, path);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
};

// Knobs an installed program drops: their values come from runtimeDefaults, or they are test-only.
const INSTALLED_DROPPED_KEYS = ['CLAUDE_BRIDGE_BIN', 'CLAUDE_BRIDGE_STATE_CLI'];

/** The passwd home of the process uid; HOME is not consulted. */
function passwdHome() {
  try { return userInfo().homedir; } catch { return homedir(); }
}

/**
 * Every location and knob a Claude Bridge program reads, for a program at `selfPath`. A program under the literal
 * /opt/claude-bridge (the bridge, its state CLI, the owner command) ignores the environment: the roots are
 * /opt/claude-bridge and /etc/claude-bridge, HOME is the passwd entry of the process uid, the Claude binary is the
 * pinned copy, bubblewrap is the system binary, and no CLAUDE_BRIDGE_TEST_* knob
 * applies. `env` is then a copy holding those values, for the modules that read the environment. Anywhere else the
 * values come from `env` as given, and `env` is returned unchanged. bridge_hook.py runtime_defaults mirrors this.
 */
export function runtimeDefaults({ selfPath, env = process.env } = {}) {
  const installed = typeof selfPath === 'string' && isInside(resolve(selfPath), DEFAULT_PROTECTED_ROOT);
  if (!installed) {
    const home = env.HOME || homedir();
    const codex = env.CODEX_HOME || join(home, '.codex');
    return {
      installed: false, home, codexHome: codex,
      stateRoot: env.CLAUDE_BRIDGE_STATE_DIR || join(home, '.local', 'state', 'claude-bridge'),
      sessionsRoot: env.CLAUDE_BRIDGE_SESSIONS_ROOT || join(codex, 'sessions'),
      protectedRoot: protectedRoot(env), etcDir: etcDir(env),
      claudeBin: (env.CLAUDE_BRIDGE_CLAUDE_BIN?.trim() || env.CLAUDE_BRIDGE_BIN?.trim()) || null,
      bwrapBin: env.CLAUDE_BRIDGE_BWRAP_BIN?.trim() || '/usr/bin/bwrap',
      testMode: env.CLAUDE_BRIDGE_TEST_MODE === '1',
      env,
    };
  }
  const home = passwdHome();
  const codex = join(home, '.codex');
  const defaults = {
    installed: true, home, codexHome: codex,
    stateRoot: join(home, '.local', 'state', 'claude-bridge'), sessionsRoot: join(codex, 'sessions'),
    protectedRoot: DEFAULT_PROTECTED_ROOT, etcDir: DEFAULT_ETC_DIR,
    claudeBin: join(DEFAULT_PROTECTED_ROOT, 'current', 'claude', 'claude'),
    bwrapBin: '/usr/bin/bwrap', testMode: false,
  };
  const normalized = Object.fromEntries(Object.entries(env).filter(([key]) => !key.startsWith('CLAUDE_BRIDGE_TEST_') && !INSTALLED_DROPPED_KEYS.includes(key)));
  Object.assign(normalized, {
    HOME: home, CODEX_HOME: codex, CLAUDE_BRIDGE_STATE_DIR: defaults.stateRoot, CLAUDE_BRIDGE_SESSIONS_ROOT: defaults.sessionsRoot,
    CLAUDE_BRIDGE_PROTECTED_ROOT: defaults.protectedRoot, CLAUDE_BRIDGE_ETC_DIR: defaults.etcDir, CLAUDE_BRIDGE_CLAUDE_BIN: defaults.claudeBin,
    CLAUDE_BRIDGE_BWRAP_BIN: defaults.bwrapBin,
  });
  return { ...defaults, env: normalized };
}

/**
 * The roots a caller at `serverPath` uses (see runtimeDefaults). `protected` is true when the caller runs from the
 * installed tree under the literal /opt/claude-bridge.
 */
export function effectiveRoots({ serverPath, env = process.env } = {}) {
  const defaults = runtimeDefaults({ selfPath: serverPath, env });
  return { protectedRoot: defaults.protectedRoot, etcDir: defaults.etcDir, protected: defaults.installed };
}

/** `roots` wins; then the roots for `serverPath`; with neither, the env-overridden roots. */
const rootsFor = (env, { serverPath, roots } = {}) => roots ?? effectiveRoots({ serverPath, env });

/**
 * The hook command, single-spaced: `/usr/bin/python3 -I <root>/current/hooks/bridge_hook.py`. `-I` keeps user
 * site-packages (.pth files run at startup, user-writable) and PYTHON* variables from altering the hook.
 */
export function expectedHookCommand(env = process.env, options = {}) {
  return `/usr/bin/python3 -I ${join(rootsFor(env, options).protectedRoot, 'current', 'hooks', 'bridge_hook.py')}`;
}

/** The installed owner public key file: `<protectedRoot>/current/owner.pub`, else `<etcDir>/owner.pub`, else null. */
export function installedOwnerPublicKeyPath({ serverPath, env = process.env, roots } = {}) {
  const { protectedRoot: root, etcDir: etc } = rootsFor(env, { serverPath, roots });
  for (const path of [join(root, 'current', 'owner.pub'), join(etc, 'owner.pub')]) {
    if (existsSync(path)) return path;
  }
  return null;
}

/** The PEM text of the installed owner public key, or null when there is none or it cannot be read. */
export function installedOwnerPublicKey(options = {}) {
  const path = installedOwnerPublicKeyPath(options);
  if (path === null) return null;
  try { return readFileSync(path, 'utf8'); } catch { return null; }
}

function immutable(path) {
  try {
    const out = execFileSync('/usr/bin/lsattr', ['-d', path], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return /^[-a-zA-Z]*i[-a-zA-Z]*\s/.test(out.trim());
  } catch { return false; }
}

/** Writable by this process's uid, or group- or world-writable; a path that cannot be read counts as writable. */
function writableByOthersThanRoot(path) {
  let stat;
  try { stat = statSync(path); } catch { return true; }
  if ((stat.mode & 0o022) !== 0) return true;
  try { accessSync(path, constants.W_OK); return true; } catch { return false; }
}

/**
 * The pinned Claude binary `<root>/current/claude/claude`: null when it is a file that neither it nor any directory
 * above it (its real path, up to the directory holding the protected root, such as /opt) lets anyone but root write;
 * otherwise the reason it cannot be trusted.
 */
export function pinnedClaudeBinaryReason(root) {
  let real;
  try { real = realpathSync(join(root, 'current', 'claude', 'claude')); } catch { return CLAUDE_BINARY_MISSING; }
  try { if (!statSync(real).isFile()) return CLAUDE_BINARY_MISSING; } catch { return CLAUDE_BINARY_MISSING; }
  const stop = dirname(resolve(root));
  for (let path = real; ; path = dirname(path)) {
    if (writableByOthersThanRoot(path)) return CLAUDE_BINARY_WRITABLE;
    if (path === stop || dirname(path) === path) return null;
  }
}

/**
 * Codex launches the bridge from its plugin cache entry, which the owner's account can write. It is the installed
 * launch config only when `<codexHome>/plugins/cache/claude-bridge-local/claude-bridge/<version>/.mcp.json` (the version
 * from the installed manifest) is a regular file owned by `rootUid`, not group- or world-writable, and byte-identical
 * to `<protectedRoot>/current/.mcp.json`.
 */
export function codexCacheLaunchConfigOk({ codexHome: home, protectedRoot: root, rootUid = 0 }) {
  try {
    const { version } = JSON.parse(readFileSync(join(root, 'current', '.codex-plugin', 'plugin.json'), 'utf8'));
    if (typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) return false;
    const cached = join(home, 'plugins', 'cache', 'claude-bridge-local', 'claude-bridge', version, '.mcp.json');
    const stat = lstatSync(cached);
    if (!stat.isFile() || stat.uid !== rootUid || (stat.mode & 0o022) !== 0) return false;
    return readFileSync(cached).equals(readFileSync(join(root, 'current', '.mcp.json')));
  } catch { return false; }
}

export function protectionStatus({ serverPath, env = process.env }) {
  const reasons = [];
  const roots = effectiveRoots({ serverPath, env });
  const root = resolve(roots.protectedRoot);
  const real = resolve(serverPath);
  if (!isInside(real, root)) reasons.push(`server runs outside ${root}`);
  if (reasons.length === 0) {
    let stat;
    try { stat = statSync(real); } catch (error) { reasons.push(`server path unreadable: ${error.message}`); }
    if (stat) {
      if (stat.uid !== 0) reasons.push(`server file owned by uid ${stat.uid}, not root`);
      if ((stat.mode & 0o022) !== 0) reasons.push('server file is group- or world-writable');
      if (!immutable(real)) reasons.push('server file is not immutable (chattr +i)');
    }
    const claude = pinnedClaudeBinaryReason(root);
    if (claude !== null) reasons.push(claude);
    // Checked once the install itself holds: an owner-written cache entry can launch some other server.
    const { codexHome: home } = runtimeDefaults({ selfPath: serverPath, env });
    if (reasons.length === 0 && !codexCacheLaunchConfigOk({ codexHome: home, protectedRoot: root })) reasons.push(CACHE_LAUNCH_CONFIG_MISMATCH);
  }
  // Installed only: the environment the bridge started with could have loaded code into it.
  if (roots.protected && LOADER_VARIABLES.some((key) => typeof env[key] === 'string' && env[key] !== '')) reasons.push(LOADER_VARIABLES_SET);
  if (installedOwnerPublicKey({ roots, env }) === null) reasons.push(NO_OWNER_KEY);
  return { status: reasons.length === 0 ? 'protected' : 'unprotected', reasons };
}

export function isRegisteredRepo(repoRoot, env = process.env, options = {}) {
  const file = join(rootsFor(env, options).etcDir, 'repos', repoKey(repoRoot));
  if (!existsSync(file)) return false;
  try { return readFileSync(file, 'utf8').trim() === resolve(repoRoot); } catch { return false; }
}

/**
 * The bridge hook registration: one group per event holding exactly
 * `{ type: 'command', command: expectedHookCommand(), timeout }`, with the group `matcher` only where
 * listed. Single source of truth; hooks.template.json carries the same values.
 */
export const EXPECTED_HOOKS = Object.freeze({
  SessionStart: Object.freeze({ matcher: 'startup|resume|clear|compact', timeout: 10 }),
  UserPromptSubmit: Object.freeze({ timeout: 10 }),
  PreToolUse: Object.freeze({ timeout: 10 }),
  PostToolUse: Object.freeze({ timeout: 10 }),
  Stop: Object.freeze({ timeout: 15 }),
});
const snakeCase = (event) => event.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const hasExactKeys = (object, keys) => {
  const own = Object.keys(object).sort();
  return own.length === keys.length && [...keys].sort().every((key, i) => key === own[i]);
};

// Codex config.toml is read with a TOML 1.0 parser, Python's tomllib (python3 is a hard requirement of the bridge),
// so the trust entry is the one Codex reads, whatever escapes, dotted keys or strings the file holds.
const TOML_READER = [
  'import json, sys, tomllib',
  'try:',
  '    doc = tomllib.loads(sys.stdin.buffer.read().decode("utf-8"))',
  'except Exception as error:',
  '    print(type(error).__name__ + ": " + str(error)); sys.exit(3)',
  'mark = lambda value: {"__not_json__": type(value).__name__}',
  'print(json.dumps({"hooks": doc.get("hooks"), "features": doc.get("features")}, default=mark))',
].join('\n');

/** `{ hooks, features }` from config.toml as TOML reads it, or `{ error }` when it cannot be parsed. */
export function readCodexConfig(text) {
  let out;
  try {
    out = execFileSync('/usr/bin/python3', ['-I', '-c', TOML_READER], {
      input: text, encoding: 'utf8', timeout: 5_000, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C.UTF-8' }, stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (error) {
    const said = typeof error?.stdout === 'string' && error.stdout.trim() ? error.stdout.trim() : (error?.message ?? String(error));
    return { error: said.split('\n')[0] };
  }
  try { return JSON.parse(out); } catch { return { error: 'the TOML reader printed no JSON' }; }
}

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
// The hash Codex writes: sha256: and 64 hex digits; the bare digits are accepted too.
const TRUSTED_HASH = /^(?:sha256:)?[0-9a-f]{64}$/;

/**
 * Our hook's entry in the parsed `hooks.state` table: 'trusted' only for exactly `{ trusted_hash }` or that plus
 * `enabled: true`; 'disabled' for `enabled: false`; 'untrusted' when there is no entry (or an empty one); anything
 * else (another key, value or type) is 'unexpected'.
 */
export function trustEntryState(stateTable, key) {
  if (stateTable === undefined || stateTable === null) return 'untrusted';
  if (!isPlainObject(stateTable)) return 'unexpected';
  if (!Object.hasOwn(stateTable, key)) return 'untrusted';
  const entry = stateTable[key];
  if (!isPlainObject(entry)) return 'unexpected';
  const keys = Object.keys(entry);
  if (keys.some((name) => name !== 'trusted_hash' && name !== 'enabled')) return 'unexpected';
  if (Object.hasOwn(entry, 'enabled') && typeof entry.enabled !== 'boolean') return 'unexpected';
  if (Object.hasOwn(entry, 'trusted_hash') && !(typeof entry.trusted_hash === 'string' && TRUSTED_HASH.test(entry.trusted_hash))) return 'unexpected';
  if (entry.enabled === false) return 'disabled';
  if (keys.length === 0) return 'untrusted';
  return Object.hasOwn(entry, 'trusted_hash') ? 'trusted' : 'unexpected';
}

/**
 * [group, hook] index of our command under one event in hooks.json when it is registered exactly once
 * in the expected shape; 'unexpected' when our command is there in any other shape; null when absent.
 */
function hookIndex(groups, command, expected) {
  const found = [];
  for (const [g, group] of groups.entries()) {
    const list = Array.isArray(group?.hooks) ? group.hooks : [];
    for (const [h, hook] of list.entries()) if (hook?.command === command) found.push({ g, h, group, hook });
  }
  if (found.length === 0) return null;
  if (found.length > 1) return 'unexpected';
  const { g, h, group, hook } = found[0];
  const groupOk = expected.matcher === undefined
    ? hasExactKeys(group, ['hooks'])
    : hasExactKeys(group, ['matcher', 'hooks']) && group.matcher === expected.matcher;
  const hookOk = hasExactKeys(hook, ['type', 'command', 'timeout']) && hook.type === 'command' && hook.timeout === expected.timeout;
  return groupOk && hookOk ? [g, h] : 'unexpected';
}

export function hooksIntact(env = process.env, options = {}) {
  const reasons = [];
  const home = runtimeDefaults({ selfPath: options.serverPath, env }).codexHome;
  const hooksPath = join(home, 'hooks.json');
  let hooks;
  try { hooks = JSON.parse(readFileSync(hooksPath, 'utf8')).hooks ?? {}; } catch { return { intact: false, reasons: [`${hooksPath} missing or unreadable`] }; }
  const command = expectedHookCommand(env, options);
  let config = null;
  try { config = readFileSync(join(home, 'config.toml'), 'utf8'); } catch { /* no config means nothing is trusted yet */ }
  let stateTable;
  if (config !== null) {
    const parsed = readCodexConfig(config);
    if (parsed.error !== undefined) return { intact: false, reasons: [`cannot parse config.toml: ${parsed.error}`] };
    if (isPlainObject(parsed.features) && parsed.features.codex_hooks === false) {
      return { intact: false, reasons: ['hooks disabled by features.codex_hooks'] };
    }
    if (parsed.hooks !== undefined && parsed.hooks !== null && !isPlainObject(parsed.hooks)) stateTable = 'not a table';
    else stateTable = parsed.hooks?.state;
  }
  for (const [event, expected] of Object.entries(EXPECTED_HOOKS)) {
    const at = hookIndex(Array.isArray(hooks[event]) ? hooks[event] : [], command, expected);
    if (!at) { reasons.push(`${event} hook not registered for ${command}`); continue; }
    if (at === 'unexpected') { reasons.push(`${event} hook is registered with an unexpected shape`); continue; }
    // Codex keys trust as <hooks.json path>:<snake_case event>:<group index>:<hook index>.
    const state = trustEntryState(stateTable, `${hooksPath}:${snakeCase(event)}:${at[0]}:${at[1]}`);
    if (state === 'untrusted') reasons.push(`${event} hook is not yet trusted in Codex`);
    else if (state === 'disabled') reasons.push(`${event} hook is disabled in Codex config`);
    else if (state === 'unexpected') reasons.push(`${event} hook is not intact: unexpected trust state`);
  }
  return { intact: reasons.length === 0, reasons };
}
