import { spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import process from 'node:process';
import { clearTimeout, setTimeout } from 'node:timers';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
export const SERVER_PATH = join(REPO_ROOT, 'plugins', 'claude-bridge', 'mcp', 'server.mjs');
export const FAKE_SESSION_ID = '123e4567-e89b-42d3-a456-426614174000';
const PROTOCOL_VERSION = '2024-11-05';

const FAKE_CLAUDE_SOURCE = String.raw`#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs';

const argv = process.argv.slice(2);
const logPath = process.env.FAKE_CLAUDE_LOG;

function append(record) {
  if (logPath) fs.appendFileSync(logPath, JSON.stringify(record) + '\n');
}

if (argv.includes('--version')) {
  append({ kind: 'version', argv });
  if (process.env.FAKE_CLAUDE_VERSION_HANG === '1') {
    process.on('SIGTERM', () => {
      append({ kind: 'signal', signal: 'SIGTERM', pid: process.pid });
      process.exit(143);
    });
    setInterval(() => {}, 60_000);
  } else if (process.env.FAKE_CLAUDE_VERSION_FAILURE === '1') {
    process.stderr.write('version failed: Bearer AbCdEf0123+/==\n');
    process.exit(9);
  } else {
    process.stdout.write('2.1.210 (Claude Code)\n');
    process.exit(0);
  }
}

let prompt = '';
for await (const chunk of process.stdin) prompt += chunk;

function argumentValue(flag) {
  const index = argv.indexOf(flag);
  return index === -1 ? undefined : argv[index + 1];
}

const primaryModel = argumentValue('--model');
const fallbackModels = String(argumentValue('--fallback-model') ?? '')
  .split(',')
  .map(model => model.trim())
  .filter(Boolean);

const selectedEnv = {};
for (const key of [
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_CUSTOM_HEADERS',
  'ANTHROPIC_MODEL',
  'ANTHROPIC_DEFAULT_SONNET_MODEL',
  'ANTHROPIC_DEFAULT_OPUS_MODEL',
  'ANTHROPIC_DEFAULT_HAIKU_MODEL',
  'CLAUDECODE',
  'CLAUDE_CODE_ENTRYPOINT',
  'CLAUDE_CODE_SUBAGENT_MODEL',
  'CLAUDE_BRIDGE_DEPTH',
  'CLAUDE_CONFIG_DIR',
]) {
  if (Object.hasOwn(process.env, key)) selectedEnv[key] = process.env[key];
}

append({
  kind: 'work',
  argv,
  prompt,
  cwd: process.cwd(),
  env: selectedEnv,
  pid: process.pid,
  primaryModel,
  fallbackModels,
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    append({ kind: 'signal', signal, pid: process.pid });
    process.exit(signal === 'SIGTERM' ? 143 : 130);
  });
}

if (prompt.includes('__FAKE_STUBBORN_TREE__')) {
  const grandchild = spawn(process.execPath, [
    '-e',
    "process.on('SIGTERM', () => {}); setInterval(() => {}, 60000)",
  ], { stdio: 'ignore' });
  append({ kind: 'grandchild', pid: grandchild.pid });
  setTimeout(() => process.exit(124), 5_000);
  setInterval(() => {}, 60_000);
}

if (prompt.includes('__FAKE_PRIMARY_MODEL_UNAVAILABLE__')) {
  const selectedModel = fallbackModels[0];
  process.stdout.write(JSON.stringify({
    type: 'result',
    subtype: selectedModel ? 'success' : 'error_during_execution',
    is_error: !selectedModel,
    result: selectedModel
      ? 'fake Claude Code native fallback selected ' + selectedModel
      : 'primary model unavailable and no fallback model was configured',
    session_id: process.env.FAKE_CLAUDE_SESSION_ID || '${FAKE_SESSION_ID}',
    duration_ms: 12,
    num_turns: 1,
    ...(selectedModel ? { modelUsage: { [selectedModel]: {} } } : {}),
  }) + '\n');
  process.exit(0);
}

if (prompt.includes('__FAKE_BRIDGE_MODEL_USAGE_LIMIT__') && /^(?:claude-)?fable(?:-|$)/.test(primaryModel)) {
  process.stdout.write(JSON.stringify({
    type: 'result',
    subtype: 'success',
    is_error: true,
    result: 'Fable 5 requires usage allocation',
    session_id: process.env.FAKE_CLAUDE_SESSION_ID || '${FAKE_SESSION_ID}',
    duration_ms: 12,
    num_turns: 1,
  }) + '\n');
  process.exit(1);
}

if (
  // Out of usage on every model the bridge may run.
  prompt.includes('__FAKE_GENERIC_OUT_OF_USAGE__')
  && (primaryModel === 'claude-fable-5-1' || primaryModel === 'claude-opus-5-5')
) {
  process.stdout.write(JSON.stringify({
    type: 'result',
    subtype: 'success',
    is_error: true,
    result: "You're out of usage.",
    session_id: process.env.FAKE_CLAUDE_SESSION_ID || '${FAKE_SESSION_ID}',
    duration_ms: 12,
    num_turns: 1,
  }) + '\n');
  process.exit(1);
}

if (prompt.includes('__FAKE_NONZERO_MALFORMED__')) {
  process.stdout.write('not-json prompt=' + prompt + ' secret=sk-ant-malformed-secret');
  process.stderr.write('malformed stderr must not escape\n');
  process.exit(8);
}

if (prompt.includes('__FAKE_NONZERO_PRIMITIVE__')) {
  process.stdout.write(JSON.stringify('primitive prompt=' + prompt + ' Bearer Primitive+/=='));
  process.stderr.write('primitive stderr must not escape\n');
  process.exit(8);
}

if (prompt.includes('__FAKE_NONZERO__')) {
  const doubleEncodedPrompt = JSON.stringify(JSON.stringify({
    prompt,
    credential: 'sk-ant-fake-nonzero-secret',
    bearer: 'Bearer AbCdEf0123+/==',
    expansion: '\\\\'.repeat(4_000) + '\u0001CONTROL_BACKSLASH_EXPANSION_SECRET',
  }));
  process.stdout.write(JSON.stringify({
    type: 'result',
    subtype: 'error_during_execution',
    is_error: true,
    result: 'Delegate execution failed. ' + doubleEncodedPrompt,
    session_id: 'raw-session-id-must-not-escape',
    duration_ms: 12,
    num_turns: 2,
  }) + '\n');
  process.stderr.write(
    'RAW_DELEGATE_STDERR prompt=' + prompt
      + ' key=sk-ant-stderr-secret Bearer StderrToken+/=='
      + ' control=\\u0001\\\\CONTROL_STDERR_EXPANSION_SECRET\n',
  );
  process.exit(7);
}

if (prompt.includes('__FAKE_MALFORMED__')) {
  process.stdout.write('{not-json');
  process.exit(0);
}

if (prompt.includes('__FAKE_FLOOD__')) {
  process.stdout.write('x'.repeat(2_000_000));
  process.exit(0);
}

// A finished run whose envelope reports an error: Claude Code's turn limit.
if (prompt.includes('__FAKE_ERROR_RESULT__')) {
  process.stdout.write(JSON.stringify({
    type: 'result', subtype: 'error_max_turns', is_error: true,
    result: 'fake delegate reached its turn limit',
    session_id: process.env.FAKE_CLAUDE_SESSION_ID || '${FAKE_SESSION_ID}',
    duration_ms: 12, num_turns: 50,
  }) + '\n');
  process.exit(0);
}

// Exit 0 with a JSON object that carries no string result.
if (prompt.includes('__FAKE_INVALID_ENVELOPE__')) {
  process.stdout.write(JSON.stringify({ type: 'result', subtype: 'success', is_error: false }) + '\n');
  process.exit(0);
}

// A second model in modelUsage, as when Claude Code runs a side task on Haiku.
const sideModel = prompt.includes('__FAKE_SIDE_MODEL__') ? { 'claude-haiku-5-5': {} } : {};

if (prompt.includes('__FAKE_VERDICT__')) {
  const marker = /__FAKE_VERDICT__:(\{.*?\}):__END__/s.exec(prompt);
  const verdict = marker ? JSON.parse(marker[1]) : undefined;
  process.stdout.write(JSON.stringify({
    type: 'result', subtype: 'success', is_error: false,
    result: 'fake adversarial review complete',
    session_id: process.env.FAKE_CLAUDE_SESSION_ID || '${FAKE_SESSION_ID}',
    duration_ms: 20, num_turns: 3,
    modelUsage: { [primaryModel]: {}, ...sideModel },
    ...(verdict ? { structured_output: verdict } : {}),
  }) + '\n');
  process.exit(0);
}

if (prompt.includes('__FAKE_EVIDENCE_LIST__')) {
  const dir = (process.env.FAKE_SCRATCH_DIR || '/tmp/claude') + '/evidence';
  const names = fs.existsSync(dir) ? fs.readdirSync(dir).sort() : [];
  const conversation = names.includes('conversation.md') ? fs.readFileSync(dir + '/conversation.md', 'utf8') : '';
  process.stdout.write(JSON.stringify({
    type: 'result', subtype: 'success', is_error: false,
    result: JSON.stringify({ names, conversation }),
    session_id: process.env.FAKE_CLAUDE_SESSION_ID || '${FAKE_SESSION_ID}',
    duration_ms: 5, num_turns: 1, modelUsage: { [primaryModel]: {} },
  }) + '\n');
  process.exit(0);
}

const emit = () => {
  const isError = prompt.includes('__FAKE_IS_ERROR__');
  const reportedModel = prompt.includes('__FAKE_RETIRED_PROVIDER_MODEL__')
    ? 'claude-opus-4-8'
    : primaryModel;
  const result = prompt.includes('__FAKE_UNICODE__')
    ? '🙂'.repeat(100_000)
    : isError
      ? 'fake delegate envelope reported an error'
      : 'fake result for: ' + prompt;
  process.stdout.write(JSON.stringify({
    type: 'result',
    subtype: isError ? 'error_during_execution' : 'success',
    is_error: isError,
    result,
    session_id: process.env.FAKE_CLAUDE_SESSION_ID || '${FAKE_SESSION_ID}',
    duration_ms: 12,
    num_turns: 1,
    ...(reportedModel ? { modelUsage: { [reportedModel]: {}, ...sideModel } } : {}),
  }) + '\n');
};

if (prompt.includes('__FAKE_HANG__')) {
  setTimeout(() => process.exit(124), 5_000);
  setInterval(() => {}, 60_000);
} else if (prompt.includes('__FAKE_SLOW__')) {
  setTimeout(emit, 1_500);
} else {
  emit();
}
`;

class JsonRpcStdioClient {
  constructor(child) {
    this.child = child;
    this.nextId = 1;
    this.pending = new Map();
    this.messages = [];
    this.nonJsonStdout = [];
    this.stderr = '';
    this.stdoutBuffer = '';
    this.closed = false;

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => this.#readStdout(chunk));
    child.stderr.on('data', chunk => { this.stderr += chunk; });
    child.once('exit', (code, signal) => {
      const error = new Error(`Claude bridge exited before replying (code=${code}, signal=${signal})`);
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(error);
      }
      this.pending.clear();
    });
  }

  #readStdout(chunk) {
    this.stdoutBuffer += chunk;
    let newlineIndex = this.stdoutBuffer.indexOf('\n');
    while (newlineIndex !== -1) {
      const line = this.stdoutBuffer.slice(0, newlineIndex);
      this.stdoutBuffer = this.stdoutBuffer.slice(newlineIndex + 1);
      if (line.trim()) {
        try {
          const message = JSON.parse(line);
          this.messages.push(message);
          const pending = this.pending.get(message.id);
          if (pending) {
            this.pending.delete(message.id);
            clearTimeout(pending.timer);
            pending.resolve(message);
          }
        } catch {
          this.nonJsonStdout.push(line);
        }
      }
      newlineIndex = this.stdoutBuffer.indexOf('\n');
    }
  }

  beginRequest(method, params = {}, timeoutMs = 6_000) {
    const id = this.nextId;
    this.nextId += 1;
    const promise = new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for ${method} request ${id}; stderr=${this.stderr}`));
      }, timeoutMs);
      this.pending.set(id, { resolve: resolvePromise, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
    return { id, promise };
  }

  async request(method, params = {}, timeoutMs = 6_000) {
    return await this.beginRequest(method, params, timeoutMs).promise;
  }

  notify(method, params = {}) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  async initialize() {
    const response = await this.request('initialize', {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'claude-bridge-test', version: '1.0.0' },
    });
    this.notify('notifications/initialized');
    return response;
  }

  async rawCallTool(name, args = {}, timeoutMs = 6_000) {
    return await this.request('tools/call', { name, arguments: args }, timeoutMs);
  }

  async waitForJob(jobHandle, timeoutMs = 6_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const response = await this.rawCallTool('claude_result', { job_handle: jobHandle });
      const payload = parsedToolPayload(response);
      if (!['running', 'cancelling'].includes(payload?.status)) return response;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error(`Timed out waiting for test job ${jobHandle}; stderr=${this.stderr}`);
  }

  async callTool(name, args = {}, timeoutMs = 6_000) {
    const response = await this.rawCallTool(name, args, timeoutMs);
    if (!['claude_task', 'claude_review', 'claude_continue'].includes(name)) return response;
    const payload = parsedToolPayload(response);
    if (payload?.status !== 'running' || typeof payload.job_handle !== 'string') return response;
    return await this.waitForJob(payload.job_handle, timeoutMs);
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    this.child.stdin.end();
    const exited = once(this.child, 'exit');
    const killTimer = setTimeout(() => this.child.kill('SIGKILL'), 250);
    await exited;
    clearTimeout(killTimer);
    if (this.stdoutBuffer.trim()) this.nonJsonStdout.push(this.stdoutBuffer);
  }
}

export async function createFixture() {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'claude-bridge-'));
  const workspace = join(fixtureRoot, 'workspace');
  await mkdir(join(workspace, '.git'), { recursive: true });
  const fakeClaude = join(fixtureRoot, 'claude.mjs');
  const fakeBwrap = join(fixtureRoot, 'bwrap');
  // Outside fixtureRoot: isolation ro-binds the fake binary's directory, and a native
  // config dir under that mount is refused.
  const providerConfigRoot = await mkdtemp(join(tmpdir(), 'claude-bridge-provider-'));
  const claudeConfigDir = join(providerConfigRoot, 'claude-config');
  const stateDir = join(fixtureRoot, 'state');
  const sessionsRoot = join(fixtureRoot, 'sessions');
  const invocationLog = join(fixtureRoot, 'fake-claude.jsonl');
  await mkdir(claudeConfigDir); await mkdir(stateDir); await mkdir(sessionsRoot);
  await writeFile(fakeClaude, FAKE_CLAUDE_SOURCE);
  // The fake bwrap records its argv, finds the `--bind SCRATCH /tmp/claude`
  // mapping the server always passes, exports SCRATCH as FAKE_SCRATCH_DIR, then
  // execs the real command. The fake Claude reads evidence from that directory.
  await writeFile(fakeBwrap, [
    '#!/bin/sh',
    'printf "%s\\n" "$@" > "${FAKE_BWRAP_LOG:-/dev/null}"',
    'prev=""; prev2=""',
    'for a in "$@"; do if [ "$prev2" = "--bind" ] && [ "$a" = "/tmp/claude" ]; then export FAKE_SCRATCH_DIR="$prev"; fi; prev2="$prev"; prev="$a"; done',
    'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done',
    'shift',
    'exec "$@"',
    '',
  ].join('\n'));
  await chmod(fakeClaude, 0o755); await chmod(fakeBwrap, 0o755);
  await symlink(fakeClaude, join(fixtureRoot, 'claude'));
  return {
    fixtureRoot, workspace, fakeClaude, fakeBwrap, claudeConfigDir, stateDir, sessionsRoot, invocationLog,
    clients: new Set(),
    async cleanup() {
      await Promise.all([...this.clients].map((client) => client.close()));
      await rm(fixtureRoot, { recursive: true, force: true });
      await rm(providerConfigRoot, { recursive: true, force: true });
    },
  };
}

export function baseEnvironment(fixture, overrides = {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(CLAUDE_BRIDGE_DEPTH)/.test(key)) delete env[key];
  }
  Object.assign(env, {
    CLAUDE_BRIDGE_CLAUDE_BIN: fixture.fakeClaude,
    CLAUDE_BRIDGE_BWRAP_BIN: fixture.fakeBwrap,
    CLAUDE_BRIDGE_TEST_MODE: '1',
    CLAUDE_BRIDGE_ALLOWED_ROOTS: fixture.fixtureRoot,
    CLAUDE_BRIDGE_STATE_DIR: fixture.stateDir,
    CLAUDE_BRIDGE_SESSIONS_ROOT: fixture.sessionsRoot,
    CLAUDE_BRIDGE_PROTECTED_ROOT: join(fixture.fixtureRoot, 'opt-claude-bridge'),
    CLAUDE_BRIDGE_ETC_DIR: join(fixture.fixtureRoot, 'etc-claude-bridge'),
    CLAUDE_CONFIG_DIR: fixture.claudeConfigDir,
    CODEX_HOME: join(fixture.fixtureRoot, 'codex-home'),
    FAKE_CLAUDE_LOG: fixture.invocationLog,
    FAKE_CLAUDE_SESSION_ID: FAKE_SESSION_ID,
    PATH: `${dirname(fixture.fakeClaude)}:${env.PATH ?? ''}`,
  }, overrides);
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return env;
}

export async function startServer(fixture, overrides = {}, serverArgs = ['--stdio'], serverPath = SERVER_PATH) {
  const child = spawn(process.execPath, [serverPath, ...serverArgs], {
    cwd: fixture.workspace, env: baseEnvironment(fixture, overrides), stdio: ['pipe', 'pipe', 'pipe'],
  });
  const client = new JsonRpcStdioClient(child);
  fixture.clients.add(client);
  const response = await client.initialize();
  if (response.error) throw new Error(`initialize failed: ${JSON.stringify(response.error)}`);
  return client;
}

export async function workInvocations(fixture) {
  let text;
  try { text = await readFile(fixture.invocationLog, 'utf8'); } catch (error) { if (error?.code === 'ENOENT') return []; throw error; }
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line)).filter((r) => r.kind === 'work');
}

export function parsedToolPayload(response) {
  const text = response?.result?.content?.map((c) => c.text ?? '').join('') ?? '';
  try { return JSON.parse(text); } catch { return undefined; }
}

export function flagValue(argv, flag) {
  const index = argv.indexOf(flag);
  return index === -1 ? undefined : argv[index + 1];
}

/**
 * The reproduced bypass: the real Stop entry is disabled behind a key that spells '/' as \u002F, and a decoy
 * multi-line string holds the literal trusted table text a line-by-line reader would take instead.
 */
export const trustBypassConfig = (hooksPath, hash = `sha256:${'0123456789abcdef'.repeat(4)}`) => [
  'decoy = """',
  `[hooks.state."${hooksPath}:stop:0:0"]`,
  `trusted_hash = "${hash}"`,
  'enabled = true',
  '[decoy.end]',
  '"""',
  '',
  ...['session_start', 'user_prompt_submit', 'pre_tool_use', 'post_tool_use'].map((key) => `[hooks.state."${hooksPath}:${key}:0:0"]\ntrusted_hash = "${hash}"\n`),
  `[hooks.state."${hooksPath.replaceAll('/', '\\u002F')}:stop:0:0"]`,
  `trusted_hash = "${hash}"`,
  'enabled = false',
  '',
].join('\n');
