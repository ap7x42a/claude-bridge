import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readlinkSync,
  realpathSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';

import process from 'node:process';

import { runtimeDefaults } from './protection.mjs';

const CODEX_CREDENTIALS_FILENAME = 'auth.json';
// PATH inside the bridge's sandbox (subscription-only mode).
const SANDBOX_PATH = '/usr/local/bin:/usr/bin:/bin';
const ISOLATION_STATE_DIRECTORY = 'claude-bridge-isolation';
// Session notes can be masked independently of repository write access.
const BUILDER_PRIVATE_MASKED_PATHS = Object.freeze([
  '.context-ledger',
]);

const DATA_PLANE_ENV_KEYS = Object.freeze([
  'DATABASE_URL',
  'DB_HOST',
  'DB_NAME',
  'DB_PASSWORD',
  'DB_PORT',
  'DB_USER',
  'NEO4J_AUTH',
  'NEO4J_DATABASE',
  'NEO4J_HTTP_URL',
  'NEO4J_PASSWORD',
  'NEO4J_URI',
  'NEO4J_URL',
  'NEO4J_USER',
  'NEO4J_USERNAME',
  'PGDATABASE',
  'PGHOST',
  'PGHOSTADDR',
  'PGOPTIONS',
  'PGPASSFILE',
  'PGPASSWORD',
  'PGPORT',
  'PGSERVICE',
  'PGSERVICEFILE',
  'PGSSLMODE',
  'PGUSER',
  'POSTGRES_CONNECTION_STRING',
  'POSTGRES_DATABASE',
  'POSTGRES_HOST',
  'POSTGRES_PASSWORD',
  'POSTGRES_PORT',
  'POSTGRES_URL',
  'POSTGRES_USER',
  'POSTGRES_USERNAME',
  'POSTGRESQL_URL',
]);

const SAFE_INHERITED_ENV_KEYS = Object.freeze([
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'LOGNAME',
  'PATH',
  'SHELL',
  'SSL_CERT_DIR',
  'SSL_CERT_FILE',
  'TERM',
  'TZ',
  'USER',
]);

function ensurePrivateDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || realpathSync(path) !== resolve(path)) {
    throw new Error('delegate isolation refused a non-directory or symlinked state path: ' + path);
  }
  chmodSync(path, 0o700);
}

function isPathInsideOrEqual(candidate, root) {
  const relation = relative(root, candidate);
  return relation === ''
    || (!relation.startsWith(`..${sep}`) && relation !== '..' && !isAbsolute(relation));
}

function pathsOverlap(left, right) {
  return isPathInsideOrEqual(left, right) || isPathInsideOrEqual(right, left);
}

function resolvedPathAliases(path) {
  const aliases = new Set([resolve(path)]);
  if (existsSync(path)) aliases.add(realpathSync(path));
  return aliases;
}

function assertNativeProviderMountSafety(nativeConfigDir, protectedMountDestinations) {
  if (!nativeConfigDir) return;
  for (const destination of protectedMountDestinations) {
    if (!destination) continue;
    for (const alias of resolvedPathAliases(destination)) {
      if (pathsOverlap(nativeConfigDir, alias)) {
        throw new Error(
          'Claude Code native config directory must not override a protected sandbox mount: '
          + destination,
        );
      }
    }
  }
}

function isolationRepositoryRoot(repoRoot, stateDirectory = ISOLATION_STATE_DIRECTORY) {
  const repoKey = createHash('sha256').update(resolve(repoRoot)).digest('hex').slice(0, 20);
  return join(
    tmpdir(),
    stateDirectory + '-' + (process.getuid?.() ?? 'user'),
    repoKey,
  );
}

function prepareIsolationLayout({
  provider,
  repoRoot,
  authorityParts,
  authorityScope,
  persistentProviderSession = false,
  includeProviderCredentials = true,
  env = process.env,
  stateDirectory = ISOLATION_STATE_DIRECTORY,
}) {
  const canonicalRoot = resolve(repoRoot);
  if (dirname(canonicalRoot) === canonicalRoot) {
    throw new Error('delegate isolation refuses a filesystem root as the repository boundary');
  }
  const authorityKey = createHash('sha256')
    .update([...authorityParts, provider, authorityScope].join('\0'))
    .digest('hex')
    .slice(0, 24);
  const authorityRoot = join(isolationRepositoryRoot(canonicalRoot, stateDirectory), authorityKey);
  const root = join(authorityRoot, 'launch-' + randomBytes(12).toString('hex'));
  const layout = {
    authorityRoot,
    root,
    homeDir: join(root, 'home'),
    configDir: join(root, 'config'),
    cacheDir: join(root, 'cache'),
    scratchDir: join(root, 'scratch'),
    providerConfigDir: persistentProviderSession
      ? join(authorityRoot, provider + '-session-config')
      : join(root, provider + '-config'),
    nativeProviderConfigDir: undefined,
    maskDir: join(root, 'masks', 'empty'),
    credentialBridges: [],
    readOnlyToolBridges: [],
  };
  const providerConfigExisted = existsSync(layout.providerConfigDir);
  try {
    for (const path of [
    dirname(root),
    root,
    layout.homeDir,
    layout.configDir,
    layout.cacheDir,
    layout.scratchDir,
    join(layout.scratchDir, 'runtime'),
    layout.providerConfigDir,
    dirname(layout.maskDir),
    layout.maskDir,
    ]) ensurePrivateDirectory(path);
    for (const writablePath of [
    layout.homeDir,
    layout.configDir,
    layout.cacheDir,
    layout.scratchDir,
    layout.providerConfigDir,
    ]) {
      const realWritable = realpathSync(writablePath);
      if (isPathInsideOrEqual(realWritable, canonicalRoot)) {
        throw new Error('delegate isolation writable state must be outside the repository: ' + writablePath);
      }
    }
    if (includeProviderCredentials) {
      if (provider === 'claude') {
        const sourceConfigDir = env.CLAUDE_CONFIG_DIR || join(homedir(), '.claude');
        if (!existsSync(sourceConfigDir)) {
          throw new Error('Claude Code native config directory is unavailable');
        }
        const nativeProviderConfigDir = realpathSync(sourceConfigDir);
        const nativeConfigStat = lstatSync(nativeProviderConfigDir);
        if (!nativeConfigStat.isDirectory() || nativeConfigStat.isSymbolicLink()) {
          throw new Error('Claude Code native config path must resolve to a directory');
        }
        if (pathsOverlap(nativeProviderConfigDir, canonicalRoot)) {
          throw new Error('Claude Code native config directory must not overlap the repository');
        }
        if (
          pathsOverlap(nativeProviderConfigDir, authorityRoot)
          || pathsOverlap(nativeProviderConfigDir, '/tmp/claude')
        ) {
          throw new Error('Claude Code native config directory must not overlap isolation state');
        }
        layout.nativeProviderConfigDir = nativeProviderConfigDir;
      } else {
        throw new Error('unsupported delegate provider: ' + String(provider));
      }
    }
    return layout;
  } catch (error) {
    rmSync(layout.root, { recursive: true, force: true });
    if (persistentProviderSession && !providerConfigExisted) {
      rmSync(layout.providerConfigDir, { recursive: true, force: true });
    }
    if (existsSync(authorityRoot) && readdirSync(authorityRoot).length === 0) {
      rmSync(authorityRoot, { recursive: true, force: true });
    }
    throw error;
  }
}

function prepareBridgeIsolationLayout({
  repoRoot,
  sessionKey,
  persistentProviderSession = false,
  includeProviderCredentials = true,
  env = process.env,
}) {
  return prepareIsolationLayout({
    provider: 'claude',
    repoRoot,
    authorityParts: [sessionKey],
    authorityScope: 'codex-bridge',
    persistentProviderSession,
    includeProviderCredentials,
    env,
  });
}

function validateIsolationLayout(canonicalRoot, layout) {
  const writablePaths = [
    layout.homeDir,
    layout.configDir,
    layout.cacheDir,
    layout.scratchDir,
    layout.providerConfigDir,
  ];
  for (const path of [layout.root, layout.maskDir, ...writablePaths]) {
    if (
      !isAbsolute(path)
      || !existsSync(path)
      || lstatSync(path).isSymbolicLink()
      || realpathSync(path) !== path
    ) {
      throw new Error('delegate isolation refused invalid writable state: ' + path);
    }
  }
  for (const bridge of layout.credentialBridges) {
    if (
      !isAbsolute(bridge.source)
      || !isAbsolute(bridge.destination)
      || !existsSync(bridge.source)
      || lstatSync(bridge.source).isSymbolicLink()
      || !existsSync(bridge.destination)
      || lstatSync(bridge.destination).isSymbolicLink()
      || (
        bridge.destination !== layout.providerConfigDir
        && !bridge.destination.startsWith(layout.providerConfigDir + sep)
      )
    ) {
      throw new Error('delegate isolation refused an invalid read-only credential bridge');
    }
  }
  for (const bridge of layout.readOnlyToolBridges ?? []) {
    const sourceStat = existsSync(bridge.source) ? lstatSync(bridge.source) : undefined;
    const destinationStat = existsSync(bridge.destination) ? lstatSync(bridge.destination) : undefined;
    if (
      !isAbsolute(bridge.source)
      || !isAbsolute(bridge.destination)
      || !sourceStat
      || sourceStat.isSymbolicLink()
      || !destinationStat
      || destinationStat.isSymbolicLink()
      || sourceStat.isDirectory() !== destinationStat.isDirectory()
      || !isPathInsideOrEqual(bridge.destination, layout.homeDir)
    ) {
      throw new Error('delegate isolation refused an invalid read-only tool-state bridge');
    }
  }
  for (const path of writablePaths) {
    if (isPathInsideOrEqual(path, canonicalRoot)) {
      throw new Error('delegate isolation refused writable state inside the repository: ' + path);
    }
  }
  if (layout.nativeProviderConfigDir !== undefined) {
    const nativeConfigStat = existsSync(layout.nativeProviderConfigDir)
      ? lstatSync(layout.nativeProviderConfigDir)
      : undefined;
    if (
      !isAbsolute(layout.nativeProviderConfigDir)
      || !nativeConfigStat?.isDirectory()
      || nativeConfigStat.isSymbolicLink()
      || realpathSync(layout.nativeProviderConfigDir) !== layout.nativeProviderConfigDir
      || pathsOverlap(layout.nativeProviderConfigDir, canonicalRoot)
      || pathsOverlap(layout.nativeProviderConfigDir, layout.authorityRoot)
      || pathsOverlap(layout.nativeProviderConfigDir, '/tmp/claude')
    ) {
      throw new Error('delegate isolation refused an invalid native provider config directory');
    }
  }
  return writablePaths;
}

function readOnlyMountArgs(paths) {
  const mounts = [];
  const seen = new Set();
  for (const destination of paths) {
    if (seen.has(destination) || !existsSync(destination)) continue;
    seen.add(destination);
    mounts.push('--ro-bind', realpathSync(destination), destination);
  }
  return mounts;
}

function rootFilesystemAliasArgs() {
  const args = [];
  for (const path of ['/bin', '/sbin', '/lib', '/lib64']) {
    if (!existsSync(path)) continue;
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) args.push('--symlink', readlinkSync(path), path);
    else args.push('--ro-bind', path, path);
  }
  return args;
}

function hostAllowlistMountArgs(commandBin) {
  const systemPaths = [
    '/usr',
    '/etc/ca-certificates',
    '/etc/pki',
    '/etc/ssl',
    '/etc/gai.conf',
    '/etc/group',
    '/etc/host.conf',
    '/etc/hosts',
    '/etc/ld.so.cache',
    '/etc/localtime',
    '/etc/machine-id',
    '/etc/nsswitch.conf',
    '/etc/os-release',
    '/etc/passwd',
    '/etc/protocols',
    '/etc/resolv.conf',
    '/etc/services',
  ];
  const userHome = homedir();
  // ~/.local/bin is not bound by name: it is bound below only when the Claude binary itself lives there (a checkout
  // run with the native installer's link), never for the pinned binary under /opt.
  const toolchainPaths = [
    resolve(userHome, '.local', 'share', 'claude'),
  ];
  if (isAbsolute(commandBin) && existsSync(commandBin)) {
    toolchainPaths.push(dirname(commandBin), dirname(realpathSync(commandBin)));
  }
  const rootAliases = rootFilesystemAliasArgs();
  return [
    ...readOnlyMountArgs(systemPaths),
    ...rootAliases,
    // Root aliases already expose these directories; binding over /bin fails on usr-merged hosts.
    ...readOnlyMountArgs(toolchainPaths.filter(destination => !rootAliases.includes(destination))),
  ];
}

function explicitSubscriptionEnvironment(input, depth) {
  const env = {};
  for (const key of SAFE_INHERITED_ENV_KEYS) {
    if (typeof input[key] === 'string' && input[key].length > 0) env[key] = input[key];
  }
  env.CLAUDE_BRIDGE_DEPTH = String(depth + 1);
  // An explicit retry limit may bound provider-side retries.
  if (typeof input.CLAUDE_CODE_MAX_RETRIES === 'string' && /^\d{1,2}$/u.test(input.CLAUDE_CODE_MAX_RETRIES)) {
    env.CLAUDE_CODE_MAX_RETRIES = input.CLAUDE_CODE_MAX_RETRIES;
  }
  env.DISABLE_TELEMETRY = '1';
  env.DISABLE_ERROR_REPORTING = '1';
  env.DISABLE_BUG_COMMAND = '1';
  env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1';
  if (input.CLAUDE_BRIDGE_TEST_MODE === '1') {
    env.CLAUDE_BRIDGE_TEST_MODE = '1';
    for (const key of [
      'FAKE_CLAUDE_LOG',
      'FAKE_CLAUDE_SESSION_ID',
      'FAKE_CLAUDE_VERSION_FAILURE',
      'FAKE_CLAUDE_VERSION_HANG',
      'FAKE_BWRAP_LOG',
    ]) {
      if (typeof input[key] === 'string') env[key] = input[key];
    }
  }
  return env;
}

function wrapIsolatedCommand({
  repoRoot,
  command,
  isolationLayout,
  repositoryAccess = 'read-only',
  unshareNetwork = false,
  environmentMode = 'preserve-command',
  bridgeDepth = 0,
  bwrapBin,
  // Additive only: a caller can mask more repository paths, never fewer.
  extraBuilderPrivatePaths = [],
}) {
  if (process.platform !== 'linux') throw new Error('delegate isolation requires Linux bubblewrap');
  const canonicalRoot = resolve(repoRoot);
  if (!existsSync(canonicalRoot) || realpathSync(canonicalRoot) !== canonicalRoot) {
    throw new Error('delegate isolation refused a missing or symlinked canonical repository root');
  }
  if (!['read-only', 'read-write'].includes(repositoryAccess)) {
    throw new Error('delegate isolation refused repository access mode: ' + String(repositoryAccess));
  }
  const bubblewrap = bwrapBin?.trim()
    || '/usr/bin/bwrap';
  if (!isAbsolute(bubblewrap) || !existsSync(bubblewrap)) {
    throw new Error('delegate isolation unavailable: bwrap executable missing at ' + bubblewrap);
  }
  const writablePaths = validateIsolationLayout(canonicalRoot, isolationLayout);
  const hostAllowlistArgs = hostAllowlistMountArgs(command.bin);
  const hostAllowlistDestinations = hostAllowlistArgs.flatMap((value, index) => (
    value === '--ro-bind' || value === '--symlink'
      ? [hostAllowlistArgs[index + 2]]
      : []
  ));
  const credentialMasks = [];
  const uid = process.getuid?.();
  const nativeProviderConfigDir = command.provider === 'claude'
    ? isolationLayout.nativeProviderConfigDir
    : undefined;
  const defaultClaudeConfigDir = resolve(homedir(), '.claude');
  const canonicalDefaultClaudeConfigDir = existsSync(defaultClaudeConfigDir)
    ? realpathSync(defaultClaudeConfigDir)
    : defaultClaudeConfigDir;
  const maskedDirectories = [
    ...(uid !== undefined ? [resolve('/run/user', String(uid))] : []),
    '/run/postgresql',
    '/run/mysqld',
    '/run/redis',
    resolve(homedir(), '.config', 'gh'),
    resolve(homedir(), '.ssh'),
    resolve(homedir(), '.claude'),
    resolve(homedir(), '.config', 'neo4j'),
    resolve(homedir(), '.neo4j'),
    join(canonicalRoot, 'secrets'),
    join(canonicalRoot, '.secrets'),
  ].filter((directory) => !(
    nativeProviderConfigDir
    && directory === defaultClaudeConfigDir
    && nativeProviderConfigDir === canonicalDefaultClaudeConfigDir
  ));
  for (const directory of maskedDirectories) {
    if (existsSync(directory)) {
      credentialMasks.push('--ro-bind', isolationLayout.maskDir, directory);
    }
  }
  // Mask credential-bearing files, not tracked executables: changing a tracked
  // file's type inside the namespace makes ordinary Git evidence commands fail.
  const maskedCredentialFiles = [
    resolve(homedir(), '.git-credentials'),
    resolve(homedir(), '.netrc'),
    resolve(homedir(), '.pgpass'),
    resolve(homedir(), '.codex', CODEX_CREDENTIALS_FILENAME),
    join(canonicalRoot, '.env'),
    join(canonicalRoot, '.env.local'),
    join(canonicalRoot, '.env.production'),
  ];
  for (const file of maskedCredentialFiles) {
    if (existsSync(file)) credentialMasks.push('--ro-bind', '/dev/null', file);
  }
  // Private-path masks are appended after repository mounts so they take precedence.
  const residueMaskedPaths = [];
  for (const relativePath of [...BUILDER_PRIVATE_MASKED_PATHS, ...extraBuilderPrivatePaths]) {
    const absolutePath = join(canonicalRoot, ...relativePath.split('/'));
    if (!existsSync(absolutePath)) continue;
    const stat = lstatSync(absolutePath);
    if (stat.isSymbolicLink() || realpathSync(absolutePath) !== absolutePath) {
      throw new Error(
        'delegate isolation refused builder-private path with symlinked ancestry: ' + absolutePath,
      );
    }
    if (stat.isDirectory()) {
      credentialMasks.push('--ro-bind', isolationLayout.maskDir, absolutePath);
    } else if (stat.isFile()) {
      credentialMasks.push('--ro-bind', '/dev/null', absolutePath);
    } else {
      throw new Error(
        'delegate isolation refused non-file, non-directory builder-private path: ' + absolutePath,
      );
    }
    residueMaskedPaths.push(absolutePath);
  }
  assertNativeProviderMountSafety(nativeProviderConfigDir, [
    ...hostAllowlistDestinations,
    '/dev',
    '/proc',
    ...(existsSync('/sys/fs/cgroup') ? ['/sys/fs/cgroup'] : []),
    '/tmp/claude',
    canonicalRoot,
    ...writablePaths,
    ...isolationLayout.credentialBridges.map((bridge) => bridge.destination),
    ...(isolationLayout.readOnlyToolBridges ?? []).map((bridge) => bridge.destination),
    ...maskedDirectories,
    ...maskedCredentialFiles,
    ...residueMaskedPaths,
  ]);
  const providerEnv = command.provider === 'claude'
    ? { CLAUDE_CONFIG_DIR: nativeProviderConfigDir ?? isolationLayout.providerConfigDir }
    : { CODEX_HOME: isolationLayout.providerConfigDir };
  const baseEnv = environmentMode === 'subscription-only'
    ? explicitSubscriptionEnvironment(command.env, bridgeDepth)
    : { ...command.env };
  for (const key of [
    ...DATA_PLANE_ENV_KEYS,
  ]) delete baseEnv[key];

  return {
    ...command,
    bin: bubblewrap,
    argv: [
      '--die-with-parent',
      '--unshare-pid',
      '--unshare-ipc',
      '--unshare-uts',
      '--unshare-cgroup',
      ...(unshareNetwork ? ['--unshare-net'] : []),
      ...hostAllowlistArgs,
      '--dev', '/dev',
      '--proc', '/proc',
      ...(existsSync('/sys/fs/cgroup') ? ['--ro-bind', '/sys/fs/cgroup', '/sys/fs/cgroup'] : []),
      '--dir', '/tmp',
      '--bind', isolationLayout.scratchDir, '/tmp/claude',
      ...(repositoryAccess === 'read-write'
        ? ['--bind', canonicalRoot, canonicalRoot]
        : [
          // Claude's nested sandbox creates deny-path placeholders and Git
          // lock files before running Bash. A private COW overlay lets those
          // mechanics work while every repository mutation remains ephemeral.
          '--ro-bind', canonicalRoot, canonicalRoot,
          '--overlay-src', canonicalRoot,
          '--tmp-overlay', canonicalRoot,
        ]),
      ...writablePaths.flatMap((path) => ['--bind', path, path]),
      ...isolationLayout.credentialBridges.flatMap((bridge) => [
        '--ro-bind', bridge.source, bridge.destination,
      ]),
      ...(isolationLayout.readOnlyToolBridges ?? []).flatMap((bridge) => [
        '--ro-bind', bridge.source, bridge.destination,
      ]),
      ...credentialMasks,
      ...(nativeProviderConfigDir
        ? [
          '--bind',
          nativeProviderConfigDir,
          nativeProviderConfigDir,
        ]
        : []),
      // The bridge's sandbox searches only system directories for programs, whatever PATH the bridge was given.
      ...(environmentMode === 'subscription-only' ? ['--setenv', 'PATH', SANDBOX_PATH] : []),
      '--setenv', 'TMPDIR', '/tmp/claude',
      '--setenv', 'CLAUDE_CODE_TMPDIR', '/tmp/claude',
      '--setenv', 'CLAUDE_TMPDIR', '/tmp/claude',
      '--setenv', 'XDG_RUNTIME_DIR', '/tmp/claude/runtime',
      '--setenv', 'DBUS_SESSION_BUS_ADDRESS', 'disabled:',
      '--setenv', 'DBUS_SYSTEM_BUS_ADDRESS', 'disabled:',
      '--',
      command.bin,
      ...command.argv,
    ],
    env: {
      ...baseEnv,
      ...(environmentMode === 'subscription-only' ? { PATH: SANDBOX_PATH } : {}),
      HOME: isolationLayout.homeDir,
      XDG_CONFIG_HOME: isolationLayout.configDir,
      XDG_CACHE_HOME: isolationLayout.cacheDir,
      XDG_STATE_HOME: isolationLayout.configDir,
      ...providerEnv,
      DISABLE_LOGOUT_COMMAND: '1',
      SYSTEMD_ASK_PASSWORD_AGENT: '0',
      GIT_ASKPASS: '/bin/false',
      SSH_ASKPASS: '/bin/false',
      GIT_TERMINAL_PROMPT: '0',
      GH_TOKEN: '',
      GITHUB_TOKEN: '',
      ...Object.fromEntries(DATA_PLANE_ENV_KEYS.map((key) => [key, ''])),
    },
  };
}

/**
 * The Claude Code binary. A bridge running from /opt/claude-bridge (`serverPath` there) runs only the pinned,
 * root-owned copy at /opt/claude-bridge/current/claude/claude and ignores every override.
 */
function resolveClaudeBin(env = process.env, { bridge = false, serverPath } = {}) {
  if (bridge && serverPath !== undefined) {
    const defaults = runtimeDefaults({ selfPath: serverPath, env });
    if (defaults.installed) return { bin: defaults.claudeBin, resolved: existsSync(defaults.claudeBin) };
  }
  const override = bridge
    ? (
      env.CLAUDE_BRIDGE_CLAUDE_BIN?.trim()
      || env.CLAUDE_BRIDGE_BIN?.trim()
    )
    : env.CLAUDE_BRIDGE_CLAUDE_BIN?.trim();
  if (override) return { bin: override, resolved: isAbsolute(override) && existsSync(override) };
  const candidates = [];
  for (const dir of (env.PATH || '').split(':')) {
    if (dir) candidates.push(join(dir, 'claude'));
  }
  candidates.push(join(env.HOME || homedir(), '.local', 'bin', 'claude'));
  candidates.push('/usr/local/bin/claude', '/usr/bin/claude');
  for (const candidate of candidates) {
    if (existsSync(candidate)) return { bin: candidate, resolved: true };
  }
  return { bin: 'claude', resolved: false };
}

function cleanupIsolationLayout(layout, { preserveAuthority = false } = {}) {
  if (layout?.root) rmSync(layout.root, { recursive: true, force: true });
  if (!preserveAuthority && layout?.authorityRoot) {
    rmSync(layout.authorityRoot, { recursive: true, force: true });
  }
}

export {
  DATA_PLANE_ENV_KEYS,
  cleanupIsolationLayout,
  explicitSubscriptionEnvironment,
  isolationRepositoryRoot,
  prepareBridgeIsolationLayout,
  resolveClaudeBin,
  wrapIsolatedCommand,
};
