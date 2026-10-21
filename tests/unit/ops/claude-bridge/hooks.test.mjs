// tests/unit/ops/claude-bridge/hooks.test.mjs
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, renameSync, statSync, utimesSync } from 'node:fs';
import { cp, mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { canonicalJson, sha256Hex } from '../../../../plugins/claude-bridge/mcp/canonical.mjs';
import { trustBypassConfig } from './harness.mjs';
import { EXPECTED_HOOKS, expectedHookCommand } from '../../../../plugins/claude-bridge/mcp/protection.mjs';
import {
  TURNS_LEDGER, applyOwnerClear, currentState, readLedger, recordRunStarted, recordVerdict, readOpen, readChain, repoStateDir, repoKey, seedState, signOwnerClear,
} from '../../../../plugins/claude-bridge/mcp/verdict.mjs';

const HOOK = fileURLToPath(new URL('../../../../plugins/claude-bridge/hooks/bridge_hook.py', import.meta.url));
const TEMPLATE = fileURLToPath(new URL('../../../../plugins/claude-bridge/hooks/hooks.template.json', import.meta.url));
const verdict = {
  verdict: 'corrected', deception_found: true, counter_to_operator_request: true, findings: [], corrective_actions: [],
  reprimand: 'Plain reprimand.', required_of_codex: ['Read back.'], report: '',
  operator_readback: 'Claude Bridge verdict: corrected. Deception found. docs/report.md was edited.',
  evidence_coverage: { session_conversation: 'full', notes: '' },
};
const INTEGRITY = 'Claude Bridge verdict state failed its integrity check';
const RECORD_FAILURE = 'A Claude Bridge verdict could not be recorded; task and continuation calls are refused until a review records a verdict.';

describe('bridge_hook.py', () => {
  let root; let repo; let env;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'bridge-hook-'));
    repo = join(root, 'repo'); await mkdir(join(repo, '.git'), { recursive: true });
    env = { ...process.env, HOME: root, CODEX_HOME: join(root, '.codex'), CLAUDE_BRIDGE_STATE_DIR: join(root, 'state'), CLAUDE_BRIDGE_PROTECTED_ROOT: join(root, 'opt'), CLAUDE_BRIDGE_ETC_DIR: join(root, 'etc') };
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  function run(input) {
    const result = spawnSync('/usr/bin/python3', ['-I', HOOK], { input: JSON.stringify(input), env, encoding: 'utf8' });
    expect(result.stderr).toBe('');
    return { code: result.status, stdout: result.stdout, stderr: result.stderr, json: result.stdout.trim() ? JSON.parse(result.stdout) : null };
  }
  const base = (event, extra = {}) => ({ hook_event_name: event, session_id: 's1', cwd: join(repo, 'sub'), transcript_path: null, ...extra });
  const record = (value = verdict, extra = {}) => recordVerdict(repo, env, { job_id: 'j', profile: 'review', verdict: value, session: { match: 'none' }, prompt_sha256: 'p', model: 'm', ...extra });
  const stateDir = () => repoStateDir(repo, env);
  const context = (event = 'UserPromptSubmit') => run(base(event)).json.hookSpecificOutput.additionalContext;
  const register = async () => {
    await mkdir(join(root, 'etc', 'repos'), { recursive: true });
    await writeFile(join(root, 'etc', 'repos', repoKey(repo)), `${resolve(repo)}\n`);
  };
  const leaveLock = async (ageMs) => {
    const lock = join(stateDir(), '.lock');
    await mkdir(lock, { recursive: true });
    const when = new Date(Date.now() - ageMs);
    utimesSync(lock, when, when);
    return lock;
  };

  it('injects the standing sentence and the open verdict on prompt submit and session start', () => {
    record();
    for (const event of ['UserPromptSubmit', 'SessionStart']) {
      const out = run(base(event));
      expect(out.code).toBe(0);
      const text = out.json.hookSpecificOutput.additionalContext;
      expect(out.json.hookSpecificOutput.hookEventName).toBe(event);
      expect(text).toContain('Claude Bridge holds corrective authority delegated by the operator');
      expect(text).toContain(verdict.operator_readback);
      expect(text).toContain('Read back.');
      expect(text).not.toContain(INTEGRITY);
      expect(text).not.toContain(RECORD_FAILURE);
    }
  });

  it('reports a record-failure marker, a broken chain and a wiped registered chain in the context', async () => {
    record();
    await writeFile(join(stateDir(), 'record-failure.json'), '{"job_id":"j"}\n');
    expect(context('SessionStart')).toContain(RECORD_FAILURE);
    expect(context()).toContain(RECORD_FAILURE);
    await writeFile(join(stateDir(), 'verdicts.jsonl'), 'not json\n', { flag: 'a' });
    const broken = context();
    expect(broken).toContain(`${INTEGRITY}: verdict chain or open record unreadable`);
    expect(broken).not.toContain(verdict.operator_readback);
    await rm(stateDir(), { recursive: true, force: true });
    expect(context()).not.toContain(INTEGRITY);
    await register();
    expect(context()).toContain(`${INTEGRITY}: registered repository has no verdict state; owner clear required`);
  });

  it('makes no decision on any call that is not a bridge call: the hook guards no files', () => {
    const sessions = join(root, '.codex', 'sessions');
    const log = join(sessions, '2026', '10', '11', 'rollout-x.jsonl');
    const calls = [
      // Writes to the bridge's own paths: the root-owned, immutable install protects those, not this hook.
      base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: `cp /tmp/x ${join(root, 'opt', 'current', 'mcp', 'server.mjs')}` } }),
      base('PreToolUse', { tool_name: 'exec', tool_input: { code: `tools.exec_command({cmd:"rm ${join(root, '.codex', 'hooks.json')}"})` } }),
      base('PreToolUse', { tool_name: 'exec', tool_input: { code: `fs.writeFileSync("${join(root, 'state', 'x')}")` } }),
      { ...base('PreToolUse', { tool_name: 'apply_patch', tool_input: { patch: '*** Begin Patch\n*** Update File: plugins/claude-bridge/mcp/server.mjs\n@@\n-a\n+b\n*** End Patch\n' } }), cwd: repo },
      { ...base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: "sed -i 's/a/b/' plugins/claude-bridge/mcp/server.mjs" } }), cwd: repo },
      base('PreToolUse', { tool_name: 'apply_patch', tool_input: { patch: '*** Begin Patch\n*** Update File: docs/a\u0000b\n*** End Patch\n' } }),
      // Reads the old token match refused: ordinary words and characters it took for writes.
      base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: `cat ${join(root, 'opt', 'current', 'bin', 'install.sh')} 2>&1 | head` } }),
      { ...base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: "rg -n 'mkdir|rename|install' plugins/claude-bridge" } }), cwd: repo },
      // Shapes of the Codex session-log reads the installed hook refused on 2026-10-11, and a write.
      base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: `rg --files -g '*memory*' ${join(sessions, '2026', '04')} 2>/dev/null | head -100` } }),
      base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: `python3 - <<'PY'\nfor ln, line in enumerate(open('${log}'), 1):\n    if not line.startswith('<environment_context>'): print(ln, line)\nPY` } }),
      base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: `jq -r 'select(.text | startswith("<environment_context>") | not)' ${log}` } }),
      base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: `printf x >> ${log}` } }),
      // An input the hook cannot resolve is still not its business.
      { ...base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: 'ls' } }), cwd: '/tmp/a\u0000b' },
    ];
    for (const input of calls) {
      const out = run(input);
      expect(out.code).toBe(0); expect(out.stdout).toBe('');
    }
  });

  it('lets a bridge call through whatever its prompt names, and fails closed only on a bridge call it cannot evaluate', () => {
    const review = run(base('PreToolUse', { tool_name: 'mcp__claude_bridge__claude_review', tool_input: {
      prompt: `A read of ${join(root, '.codex', 'sessions', '2026', '04')} was refused; see ${join(repo, 'plugins', 'claude-bridge', 'bin', 'install.sh')}. ADR-4 states INFORMS cosine>.75.` } }));
    expect(review.code).toBe(0); expect(review.stdout).toBe('');
    const unresolvable = { cwd: '/tmp/a\u0000b' };
    const broken = run({ ...base('PreToolUse', { tool_name: 'mcp__claude_bridge__claude_review', tool_input: { prompt: 'x' } }), ...unresolvable });
    expect(broken.code).toBe(0);
    expect(broken.json.hookSpecificOutput).toEqual({ hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'Claude Bridge hook could not evaluate this call safely: ValueError' });
    // A bridge call is known by its tool name: Codex hands a script's own calls to the hook under their names.
    for (const tool of [{ tool_name: 'exec', tool_input: { code: 'tools.mcp__claude_bridge__claude_review({prompt:"x"})' } }, { tool_name: 'exec_command', tool_input: { cmd: "rg -n 'mcp__claude_bridge__' docs" } }]) {
      const other = run({ ...base('PreToolUse', tool), ...unresolvable });
      expect(other.code).toBe(0); expect(other.stdout).toBe('');
    }
    for (const event of ['SessionStart', 'UserPromptSubmit', 'PostToolUse', 'Stop']) {
      const quiet = run({ ...base(event, { tool_name: 'exec', tool_input: {}, last_assistant_message: 'x' }), ...unresolvable });
      expect(quiet.code).toBe(0);
      expect(quiet.stdout).toBe('');
    }
  });

  it('tells Codex to read back after a bridge result', () => {
    const readback = { output: JSON.stringify({ operator_readback: 'Claude Bridge verdict: corrected.' }) };
    const out = run(base('PostToolUse', { tool_name: 'mcp__claude_bridge__claude_result', tool_input: { job_handle: 'x' }, tool_response: readback }));
    expect(out.json.systemMessage).toMatch(/read operator_readback to the operator verbatim/i);
    // Calls that only mention the result tool or the readback field get nothing.
    for (const call of [
      { tool_name: 'exec_command', tool_input: { cmd: 'ls' }, tool_response: { output: 'x' } },
      { tool_name: 'exec_command', tool_input: { cmd: 'rg -n claude_result docs' }, tool_response: { output: 'docs/x.md:3: claude_result returns operator_readback' } },
      { tool_name: 'exec', tool_input: { code: 'tools.mcp__claude_bridge__claude_result({job_handle:"x"})' }, tool_response: readback },
    ]) {
      expect(run(base('PostToolUse', call)).stdout.trim()).toBe('');
    }
  });

  it('says the readback counts only from the message that ends a turn: in the context, after a result call, and when blocking a stop', () => {
    record();
    const text = context();
    expect(text).toContain('Say operator_readback to the operator verbatim as the message that ends your turn');
    expect(text).toContain('interim commentary is never handed to the hook');
    const readback = { output: JSON.stringify({ operator_readback: 'Claude Bridge verdict: corrected.' }) };
    const after = run(base('PostToolUse', { tool_name: 'mcp__claude_bridge__claude_result', tool_input: { job_handle: 'x' }, tool_response: readback }));
    expect(after.json.systemMessage).toContain('as the message that ends your turn');
    const blocked = run(base('Stop', { last_assistant_message: 'commentary that merely mentions the verdict', stop_hook_active: false }));
    expect(blocked.json.decision).toBe('block');
    expect(blocked.json.reason).toContain('as the message that ends this turn');
    expect(blocked.json.reason).toContain(verdict.operator_readback);
  });

  it('blocks Stop until the readback appears, then confirms and lifts a corrected verdict', async () => {
    expect(run(base('Stop', { last_assistant_message: 'Done.', stop_hook_active: false })).stdout.trim()).toBe('');
    expect(existsSync(join(root, 'state'))).toBe(false);
    const recorded = record();
    const blocked = run(base('Stop', { last_assistant_message: 'Done with the task.', stop_hook_active: false }));
    expect(blocked.json.decision).toBe('block');
    expect(blocked.json.reason).toContain(verdict.operator_readback);
    expect(readOpen(repo, env).readback_attempts).toBe(1);
    const spoken = run(base('Stop', { last_assistant_message: 'Here is the verdict:\n\n> **Claude Bridge verdict:**  corrected.   Deception found.\n> `docs/report.md` was edited.\n', stop_hook_active: true }));
    expect(spoken.stdout.trim()).toBe('');
    expect(spoken.code).toBe(0);
    expect(readOpen(repo, env)).toBeNull();
    const chain = readChain(stateDir());
    expect(chain.intact).toBe(true);
    expect(chain.records.at(-1).type).toBe('readback_confirmed');
    expect(chain.records.at(-1).verdict_id).toBe(recorded.id);
    expect(run(base('Stop', { last_assistant_message: 'Next task done.', stop_hook_active: false })).stdout.trim()).toBe('');
    const lifted = context();
    expect(lifted).not.toContain(INTEGRITY);
    expect(lifted).not.toContain(verdict.operator_readback);
  });

  const assistantEntry = (said, extra = {}) => JSON.stringify({ ...extra, type: 'response_item', payload: { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: said }] } }) + '\n';

  // Ledgers an assistant message as the hook does at Stop, now, without running a Stop.
  const ledgerAssistantMessage = (said) => {
    const script = [
      'import os, sys',
      `sys.path.insert(0, ${JSON.stringify(dirname(HOOK))})`,
      'import bridge_hook as hook',
      'root = hook.repo_root(os.path.realpath(sys.argv[1]))',
      'body = {"type": "assistant_message", "session_id": "s1", "recorded_at": hook.now_iso(), **hook.turn_text("text", sys.argv[2])}',
      'print(hook.record_turn(root, hook.is_registered(root), body))',
    ].join('\n');
    const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', script, repo, said], { env, encoding: 'utf8' });
    expect(result.stderr).toBe('');
    expect(result.stdout.trim()).toBe('True');
  };

  it('confirms a transcript readback only against a message the hook ledgered after the verdict, and stops blocking after three attempts', async () => {
    // A message the hook ledgered before the verdict existed.
    await mkdir(stateDir(), { recursive: true });
    expect(run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: false })).stdout.trim()).toBe('');
    await delay(5);
    record({ ...verdict, verdict: 'blocked' });
    // The operator's own message carries the readback; only an assistant message counts. The entry names
    // "assistant" so the line passes the substring prefilter and only the role check rejects it.
    const userTranscript = join(root, 'user.jsonl');
    await writeFile(userTranscript, JSON.stringify({ type: 'response_item', source: 'assistant', payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text: verdict.operator_readback }] } }) + '\n');
    for (let i = 0; i < 3; i += 1) expect(run(base('Stop', { last_assistant_message: 'nope', stop_hook_active: i > 0, transcript_path: userTranscript })).json.decision).toBe('block');
    expect(readOpen(repo, env).readback_confirmed).toBe(false);
    const fourth = run(base('Stop', { last_assistant_message: 'nope', stop_hook_active: true }));
    expect(fourth.json.decision).toBeUndefined();
    expect(fourth.json.systemMessage).toMatch(/verdict .* remains open/i);
    const transcript = join(root, 't.jsonl');
    // A line written into the session file, never ledgered.
    await writeFile(transcript, assistantEntry(`${verdict.operator_readback} Done.`));
    expect(run(base('Stop', { last_assistant_message: null, stop_hook_active: true, transcript_path: transcript })).json.systemMessage).toMatch(/remains open/);
    // The exact text, with a fresh timestamp the agent wrote: the only ledger record of it predates the verdict.
    await writeFile(transcript, assistantEntry(verdict.operator_readback, { timestamp: new Date(Date.now() + 60_000).toISOString() }), { flag: 'a' });
    expect(run(base('Stop', { last_assistant_message: null, stop_hook_active: true, transcript_path: transcript })).json.systemMessage).toMatch(/remains open/);
    expect(readOpen(repo, env).readback_confirmed).toBe(false);
    // Ledgered after the verdict: the line confirms, whatever timestamp the session file gives it.
    ledgerAssistantMessage(verdict.operator_readback);
    await writeFile(transcript, assistantEntry(verdict.operator_readback, { timestamp: '2000-01-01T00:00:00.000Z' }));
    const found = run(base('Stop', { last_assistant_message: null, stop_hook_active: true, transcript_path: transcript }));
    expect(found.stdout.trim()).toBe('');
    expect(readOpen(repo, env).readback_confirmed).toBe(true);
    expect(currentState(repo, env)).toMatchObject({ status: 'open', open: { verdict: 'blocked', readback_confirmed: true } });
  });

  it('does not confirm from a transcript line that is not in the ledger, even with the ledger in place', async () => {
    record();
    // The ledger holds other messages, not this one.
    expect(run(base('Stop', { last_assistant_message: 'Something else entirely.', stop_hook_active: false })).json.decision).toBe('block');
    const transcript = join(root, 'forged.jsonl');
    await writeFile(transcript, assistantEntry(verdict.operator_readback));
    expect(run(base('Stop', { last_assistant_message: null, stop_hook_active: true, transcript_path: transcript })).json.decision).toBe('block');
    expect(readOpen(repo, env)).not.toBeNull();
    expect(readChain(stateDir()).records.map((entry) => entry.type)).toEqual(['verdict']);
  });

  const turns = () => readLedger(stateDir(), TURNS_LEDGER);

  it('ledgers the owner prompt, the final assistant message and bridge calls, hash-chained like the verdicts', async () => {
    // An unregistered repository the bridge holds no state for: nothing is recorded.
    run({ ...base('UserPromptSubmit'), prompt: 'unrelated work' });
    expect(existsSync(stateDir())).toBe(false);
    await register();
    const prompt = 'Owner: review the migration against my question.';
    expect(run({ ...base('UserPromptSubmit'), prompt, turn_id: 't-1' }).json.hookSpecificOutput.additionalContext).toContain('Claude Bridge holds corrective authority');
    run(base('Stop', { last_assistant_message: 'Codex: the migration answers it.', stop_hook_active: false }));
    run(base('Stop', { last_assistant_message: '', stop_hook_active: false }));
    const transcript = join(root, 'session.jsonl');
    await writeFile(transcript, '{}\n');
    expect(run({ ...base('PreToolUse', { tool_name: 'mcp__claude_bridge__claude_review', tool_input: { prompt: 'x' } }), transcript_path: transcript }).stdout.trim()).toBe('');
    const long = 'x'.repeat(16_001);
    run({ ...base('UserPromptSubmit'), prompt: long });
    const ledger = turns();
    expect(ledger.consistent).toBe(true);
    expect(ledger.records.map((entry) => entry.type)).toEqual(['owner_prompt', 'assistant_message', 'bridge_call', 'owner_prompt']);
    const [owner, said, call, cut] = ledger.records;
    expect(owner).toMatchObject({ session_id: 's1', turn_id: 't-1', sha256: sha256Hex(prompt), prompt });
    expect(Object.keys(owner)).toEqual(['type', 'session_id', 'turn_id', 'recorded_at', 'sha256', 'prompt', 'prev', 'id']);
    expect(said).toMatchObject({ session_id: 's1', sha256: sha256Hex('Codex: the migration answers it.'), text: 'Codex: the migration answers it.' });
    expect(call).toEqual({ type: 'bridge_call', session_id: 's1', transcript_path: transcript, inode: String(statSync(transcript, { bigint: true }).ino), recorded_at: call.recorded_at, prev: call.prev, id: call.id });
    expect(cut).toMatchObject({ sha256: sha256Hex(long), truncated: true });
    expect(cut.prompt).toHaveLength(16_000);
    // The verdict chain is untouched by the turns.
    expect(readChain(stateDir()).exists).toBe(false);
  });

  it("writes turns records Node reads as intact, hashing each as Node's canonical form does", async () => {
    await mkdir(stateDir(), { recursive: true });
    const odd = 'é   \u0001\u001f "q" \\ / 😀\t\n\u2028 \uD800 lone';
    run({ ...base('UserPromptSubmit', { session_id: 'sé\u0001' }), prompt: odd, turn_id: '10' });
    run(base('Stop', { last_assistant_message: odd, stop_hook_active: false }));
    run({ ...base('PreToolUse', { tool_name: 'mcp__claude_bridge__claude_task', tool_input: {} }), transcript_path: join(root, 'missing \uD800.jsonl') });
    const ledger = turns();
    expect(ledger.consistent).toBe(true);
    expect(ledger.records).toHaveLength(3);
    const lines = (await readFile(join(stateDir(), 'turns.jsonl'), 'utf8')).split('\n').filter(Boolean);
    for (const [index, line] of lines.entries()) {
      expect(JSON.stringify(JSON.parse(line))).toBe(line);
      expect(ledger.records[index]).toEqual(JSON.parse(line));
    }
    // The lone surrogate reads as U+FFFD, and the hash is Node's hash of the text as the app sent it.
    expect(ledger.records[0].prompt).toBe(odd.replace('\uD800', '\uFFFD'));
    expect(ledger.records[0].sha256).toBe(sha256Hex(odd));
    expect(ledger.records[1].sha256).toBe(sha256Hex(odd));
    expect(ledger.records[2]).toMatchObject({ transcript_path: join(root, 'missing \uFFFD.jsonl'), inode: null });
    const head = JSON.parse(await readFile(join(stateDir(), 'turns-head.json'), 'utf8'));
    expect(head).toEqual({ hash: sha256Hex(canonicalJson(ledger.records.at(-1))), count: 3 });
  });

  it('prints the verdict state and the protection together from the state CLI context command', async () => {
    const recorded = record();
    const out = spawnSync(process.execPath, [STATE_CLI, 'context', repo], { env, encoding: 'utf8' });
    expect(out.status, out.stderr).toBe(0);
    const answer = JSON.parse(out.stdout);
    expect(answer.state).toMatchObject({ status: 'open', open: { id: recorded.id } });
    expect(answer.protection).toMatchObject({ status: 'unprotected', hooks: { intact: false } });
    expect(spawnSync(process.execPath, [STATE_CLI, 'context'], { env, encoding: 'utf8' }).status).toBe(1);
  });

  it('runs the state CLI once per context event', async () => {
    record();
    await mkdir(join(root, 'opt'), { recursive: true });
    const log = join(root, 'cli-calls.log');
    const cli = join(root, 'counting-cli.mjs');
    await writeFile(cli, `import { appendFileSync } from 'node:fs';\nappendFileSync(${JSON.stringify(log)}, process.argv.slice(2).join(' ') + '\\n');\nprocess.stdout.write(JSON.stringify({ state: { status: 'clear', open: null }, protection: { status: 'unprotected', reasons: [], hooks: { intact: true, reasons: [] } } }) + '\\n');\n`);
    withStateCli(cli);
    for (const event of ['SessionStart', 'UserPromptSubmit']) {
      await rm(log, { force: true });
      run({ ...base(event), prompt: 'owner words' });
      expect((await readFile(log, 'utf8')).trim().split('\n'), event).toEqual([`context ${repo}`]);
    }
  });

  it('gives up the prompt ledger after 2 s on a held lock, so UserPromptSubmit stays inside its budget', async () => {
    record();
    await leaveLock(0);
    const started = Date.now();
    const text = run({ ...base('UserPromptSubmit'), prompt: 'owner words' }).json.hookSpecificOutput.additionalContext;
    const elapsed = Date.now() - started;
    expect(text).toContain(verdict.operator_readback);
    expect(elapsed).toBeGreaterThanOrEqual(1_900);
    expect(elapsed).toBeLessThan(2_900);
  });

  it('runs the state CLI at Stop with the state lock released', async () => {
    record();
    const log = join(root, 'cli.log');
    const cli = join(root, 'lock-probe-cli.mjs');
    const verdictModule = new URL('../../../../plugins/claude-bridge/mcp/verdict.mjs', import.meta.url).href;
    await writeFile(cli, [
      "import { appendFileSync, existsSync } from 'node:fs';",
      `const { currentState, repoStateDir } = await import(${JSON.stringify(verdictModule)});`,
      'const [command, repo] = process.argv.slice(2);',
      `appendFileSync(${JSON.stringify(log)}, JSON.stringify({ command, locked: command === 'current-state' && existsSync(repoStateDir(repo, process.env) + '/.lock') }) + '\\n');`,
      "process.stdout.write(JSON.stringify(command === 'current-state' ? currentState(repo, process.env) : { status: 'unprotected', reasons: [], hooks: { intact: true, reasons: [] } }) + '\\n');",
    ].join('\n'));
    withStateCli(cli);
    expect(run(base('Stop', { last_assistant_message: 'not yet', stop_hook_active: false })).json.decision).toBe('block');
    expect(run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: true })).stdout.trim()).toBe('');
    expect(readOpen(repo, env)).toBeNull();
    const calls = (await readFile(log, 'utf8')).split('\n').filter(Boolean).map((line) => JSON.parse(line)).filter((entry) => entry.command === 'current-state');
    expect(calls.length).toBeGreaterThanOrEqual(2);
    expect(calls.every((entry) => entry.locked === false)).toBe(true);
  });

  it('keys a cwd in a nested, unregistered .git to the registered repository around it', async () => {
    await register();
    seedState(repo, env);
    record(verdict, { registered: true });
    await mkdir(join(repo, 'src', '.git'), { recursive: true });
    // Re-keyed only where the protected install exists, as the protected bridge keys it.
    await mkdir(join(root, 'opt'), { recursive: true });
    const nested = { ...base('UserPromptSubmit'), cwd: join(repo, 'src'), prompt: 'owner words from the nested directory' };
    expect(run(nested).json.hookSpecificOutput.additionalContext).toContain(verdict.operator_readback);
    expect(turns().records.at(-1)).toMatchObject({ type: 'owner_prompt', prompt: 'owner words from the nested directory' });
    expect(existsSync(repoStateDir(join(repo, 'src'), env))).toBe(false);
  });

  it('takes the readback from the chain, not from open.json', async () => {
    record();
    const file = join(stateDir(), 'open.json');
    await writeFile(file, JSON.stringify({ ...JSON.parse(await readFile(file, 'utf8')), operator_readback: 'Nothing to report.' }, null, 2) + '\n');
    expect(context()).toContain(verdict.operator_readback);
    const out = run(base('Stop', { last_assistant_message: 'Nothing to report.', stop_hook_active: false }));
    expect(out.json.decision).toBe('block');
    expect(out.json.reason).toContain(verdict.operator_readback);
    expect(readChain(stateDir()).records).toHaveLength(1);
  });

  it('reproduces the Node canonical hash for the chain', async () => {
    record();
    run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: false }));
    const lines = (await readFile(join(stateDir(), 'verdicts.jsonl'), 'utf8')).split('\n').filter(Boolean);
    const first = JSON.parse(lines[0]); const second = JSON.parse(lines[1]);
    const sorted = (value) => Array.isArray(value) ? value.map(sorted) : (value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, sorted(value[k])])) : value);
    expect(second.prev).toBe(createHash('sha256').update(JSON.stringify(sorted(first))).digest('hex'));
  });

  it('leaves a chain it cannot trust untouched at Stop', async () => {
    const chainFile = () => join(stateDir(), 'verdicts.jsonl');
    const firstHash = () => sha256Hex(canonicalJson(readChain(stateDir()).records[0]));
    const tamperings = [
      async () => { record(); await writeFile(join(stateDir(), 'head.json'), '{"hash":"0","count":1}\n'); },
      async () => { record(); await writeFile(chainFile(), 'null\n', { flag: 'a' }); },
      // Linked and headed as Python would hash it, but a float has no canonical form both languages agree on.
      async () => {
        record();
        const line = `{"n":1.5,"prev":"${firstHash()}"}`;
        await writeFile(chainFile(), `${line}\n`, { flag: 'a' });
        await writeFile(join(stateDir(), 'head.json'), JSON.stringify({ hash: sha256Hex(line), count: 2 }) + '\n');
      },
      async () => { record(); await writeFile(chainFile(), `{"prev":"${firstHash()}","s":"\\ud800"}\n`, { flag: 'a' }); },
      async () => { await register(); record(verdict, { registered: true }); },
    ];
    const snapshot = () => Promise.all(['verdicts.jsonl', 'head.json', 'open.json'].map((file) => readFile(join(stateDir(), file), 'utf8').catch(() => null)));
    for (const tamper of tamperings) {
      await rm(join(root, 'state'), { recursive: true, force: true });
      await rm(join(root, 'etc'), { recursive: true, force: true });
      await tamper();
      const before = await snapshot();
      for (const message of [verdict.operator_readback, 'nope']) {
        expect(run(base('Stop', { last_assistant_message: message, stop_hook_active: false })).stdout.trim()).toBe('');
      }
      expect(await snapshot()).toEqual(before);
      expect(context()).toContain(INTEGRITY);
    }
  });

  it('mirrors verdict.mjs appends: the reset before a lock break on a wiped registered chain, and no head repair', async () => {
    const probe = (registered) => {
      const script = [
        'import sys',
        `sys.path.insert(0, ${JSON.stringify(dirname(HOOK))})`,
        'import bridge_hook as hook',
        'directory, registered = sys.argv[1], sys.argv[2] == "1"',
        'hook.with_state_lock(directory, lambda: hook.append_record(directory, {"type": "probe", "recorded_at": hook.now_iso()}, registered), registered)',
      ].join('\n');
      const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', script, stateDir(), registered ? '1' : '0'], { env, encoding: 'utf8' });
      expect(result.stderr).toBe('');
      expect(result.status).toBe(0);
    };
    await register();
    await leaveLock(60_000);
    probe(true);
    let chain = readChain(stateDir());
    expect(chain.intact).toBe(true);
    expect(chain.records.map((entry) => entry.type)).toEqual(['state_reset_detected', 'lock_broken', 'probe']);
    expect(currentState(repo, env, { registered: true })).toMatchObject({ status: 'tampered', reason: 'verdict state was reset; owner clear required' });
    const head = join(stateDir(), 'head.json');
    await writeFile(head, '{"hash":"0","count":3}\n');
    probe(true);
    chain = readChain(stateDir());
    expect(chain.intact).toBe(true);
    expect(chain.records).toHaveLength(4);
    expect(await readFile(head, 'utf8')).toBe('{"hash":"0","count":3}\n');
  });

  it('on a held state lock, blocks once without counting an attempt, then allows with the verdict still open', async () => {
    record();
    const lock = await leaveLock(0);
    const snapshot = () => Promise.all(['verdicts.jsonl', 'head.json', 'open.json'].map((file) => readFile(join(stateDir(), file), 'utf8')));
    const before = await snapshot();
    const testEnv = env;
    env = { ...testEnv, CLAUDE_BRIDGE_TEST_MODE: '1', CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS: '200' };
    const first = run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: false }));
    expect(first.json.decision).toBe('block');
    expect(first.json.reason).toContain('Claude Bridge verdict state is locked; say operator_readback again');
    expect(first.json.reason).toContain(verdict.operator_readback);
    const second = run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: true }));
    expect(second.json.decision).toBeUndefined();
    expect(second.json.systemMessage).toMatch(/verdict \S+ remains open.*refuses/);
    expect(await snapshot()).toEqual(before);
    expect(readOpen(repo, env).readback_attempts).toBe(0);
    expect(existsSync(lock)).toBe(true);
    // The short timeout is honoured only in test mode.
    env = { ...testEnv, CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS: '200' };
    const started = Date.now();
    expect(run(base('Stop', { last_assistant_message: 'nope', stop_hook_active: true })).json.systemMessage).toMatch(/remains open/);
    expect(Date.now() - started).toBeGreaterThanOrEqual(2900);
  });

  it('decides again under the lock: a chain tampered while the hook waits is left alone', async () => {
    record();
    const lock = await leaveLock(0);
    const child = spawn('/usr/bin/python3', ['-I', HOOK], { env });
    let stdout = ''; let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const exited = once(child, 'close');
    child.stdin.end(JSON.stringify(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: false })));
    await delay(300);
    await writeFile(join(stateDir(), 'head.json'), '{"hash":"0","count":1}\n');
    await rm(lock, { recursive: true });
    const [code] = await exited;
    expect({ code, stdout, stderr }).toEqual({ code: 0, stdout: '', stderr: '' });
    expect(readChain(stateDir()).records).toHaveLength(1);
    expect(readOpen(repo, env).readback_attempts).toBe(0);
  });

  it('hashes a Node record with JavaScript key order, and Node reads the Python append as intact', async () => {
    // Integer-like keys come first in JavaScript; other keys sort by UTF-16 code unit.
    const job_id = { b: 1, 10: 2, 9: 3, a: 4, '￿': 5, '\u{1F600}': 6, text: 'é   \u0001 "q" \\ 😀' };
    record(verdict, { job_id });
    run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: false }));
    const chain = readChain(stateDir());
    expect(chain.intact).toBe(true);
    expect(chain.records.map((entry) => entry.type)).toEqual(['verdict', 'readback_confirmed']);
    expect(JSON.parse(await readFile(join(stateDir(), 'head.json'), 'utf8'))).toEqual({ hash: sha256Hex(canonicalJson(chain.records.at(-1))), count: 2 });
    expect(currentState(repo, env).status).toBe('clear');
  });

  it('breaks a stale lock in Python, and the chain stays consistent for both readers after a Node append', async () => {
    record();
    const lock = await leaveLock(60_000);
    expect(run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: false })).stdout.trim()).toBe('');
    expect(existsSync(lock)).toBe(false);
    let chain = readChain(stateDir());
    expect(chain.records.map((entry) => entry.type)).toEqual(['verdict', 'lock_broken', 'readback_confirmed']);
    expect(Number.isInteger(chain.records[1].stale_ms) && chain.records[1].stale_ms >= 60_000).toBe(true);
    const second = { ...verdict, verdict: 'blocked', operator_readback: 'Claude Bridge verdict: blocked. Stop the release.' };
    record(second);
    chain = readChain(stateDir());
    expect(chain.intact).toBe(true);
    expect(currentState(repo, env).status).toBe('open');
    const text = context();
    expect(text).not.toContain(INTEGRITY);
    expect(text).toContain(second.operator_readback);
  });

  const notIntact = 'Claude Bridge hook registration is not intact';
  const bridgeCall = () => base('PreToolUse', { tool_name: 'mcp__claude_bridge__claude_review', tool_input: { prompt: 'review' } });
  const renderHooks = async (edit = (text) => text) => {
    await mkdir(join(root, '.codex'), { recursive: true });
    const rendered = (await readFile(TEMPLATE, 'utf8')).split('__PROTECTED_ROOT__').join(join(root, 'opt'));
    await writeFile(join(root, '.codex', 'hooks.json'), edit(rendered));
  };
  // Codex's trust entries for the five hooks, as Codex writes them.
  const trustHooks = async () => {
    const hooksPath = join(root, '.codex', 'hooks.json');
    const tables = ['session_start', 'user_prompt_submit', 'pre_tool_use', 'post_tool_use', 'stop']
      .map((key) => `[hooks.state."${hooksPath}:${key}:0:0"]\ntrusted_hash = "sha256:${'ab'.repeat(32)}"\nenabled = true\n`);
    await writeFile(join(root, '.codex', 'config.toml'), ['[hooks.state]\n', ...tables].join('\n'));
  };
  const installStateCli = async () => {
    await mkdir(join(root, 'opt', 'current'), { recursive: true });
    await cp(dirname(STATE_CLI), join(root, 'opt', 'current', 'mcp'), { recursive: true });
  };

  it('reads the registration the template renders as intact, and the unisolated command as not intact', async () => {
    await mkdir(join(root, 'opt'), { recursive: true });
    expect(context()).toContain(notIntact);
    await renderHooks();
    await trustHooks();
    // The protected install exists, so a bridge call needs its state CLI to check the install.
    await installStateCli();
    expect(context()).not.toContain(notIntact);
    expect(run(bridgeCall()).stdout.trim()).toBe('');
    await renderHooks((text) => text.split('/usr/bin/python3 -I ').join('/usr/bin/python3 '));
    expect(context()).toContain(notIntact);
    expect(run(bridgeCall()).json.hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('denies bridge calls when the hook itself runs with LD_PRELOAD or LD_LIBRARY_PATH set', async () => {
    await mkdir(join(root, 'opt'), { recursive: true });
    await renderHooks();
    await trustHooks();
    await installStateCli();
    expect(run(bridgeCall()).stdout.trim()).toBe('');
    const clean = env;
    env = { ...clean, LD_LIBRARY_PATH: join(root, 'no-libs') };
    const denied = run(bridgeCall()).json.hookSpecificOutput;
    expect(denied.permissionDecision).toBe('deny');
    expect(denied.permissionDecisionReason).toContain('LD_PRELOAD or LD_LIBRARY_PATH');
    expect(run(base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: 'ls' } })).stdout.trim()).toBe('');
    env = clean;
  });

  // A stand-in for the state CLI: `protection` prints the given status, `current-state` a clear state, `context` both.
  const fakeStateCli = async (protection, { exitCode = 0 } = {}) => {
    const cli = join(root, 'fake-state-cli.mjs');
    const clear = { status: 'clear', open: null };
    const answers = { protection, 'current-state': clear, context: { state: clear, protection } };
    await writeFile(cli, `const [command] = process.argv.slice(2);\nprocess.stdout.write(JSON.stringify(${JSON.stringify(answers)}[command]) + '\\n');\nprocess.exitCode = ${exitCode};\n`);
    withStateCli(cli);
  };
  const CACHE = 'Codex cache launch config is not the installed one';

  it('denies bridge calls when the Codex cache launch config is not the installed one, or the check cannot run', async () => {
    await mkdir(join(root, 'opt'), { recursive: true });
    await renderHooks();
    const taskCall = base('PreToolUse', { tool_name: 'mcp__claude_bridge__claude_task', tool_input: { prompt: 'x' } });
    const plain = base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: 'ls' } });
    // Not bridge calls: a script whose own bridge call reaches the hook separately, and a command naming the tool.
    const others = [base('PreToolUse', { tool_name: 'exec', tool_input: { code: 'await tools.mcp__claude_bridge__claude_task({prompt:"x"})' } }),
      base('PreToolUse', { tool_name: 'exec_command', tool_input: { cmd: "rg -n 'mcp__claude_bridge__' docs" } })];
    await fakeStateCli({ status: 'unprotected', reasons: [CACHE], hooks: { intact: true, reasons: [] } });
    for (const call of [bridgeCall(), taskCall]) {
      const out = run(call).json.hookSpecificOutput;
      expect(out.permissionDecision).toBe('deny');
      expect(out.permissionDecisionReason).toContain(CACHE);
    }
    for (const call of [plain, ...others]) expect(run(call).stdout.trim()).toBe('');
    await fakeStateCli({ status: 'unprotected', reasons: ['server file owned by uid 1000, not root'], hooks: { intact: true, reasons: [] } });
    expect(run(bridgeCall()).stdout.trim()).toBe('');
    await fakeStateCli({ error: 'boom' }, { exitCode: 1 });
    expect(run(bridgeCall()).json.hookSpecificOutput.permissionDecisionReason).toMatch(/could not check its protected install/);
    expect(run(plain).stdout.trim()).toBe('');
    // No protected install: nothing to check.
    await rm(join(root, 'opt'), { recursive: true });
    expect(run(bridgeCall()).stdout.trim()).toBe('');
  });

  it('reports the hook trust state from the state CLI in the session context', async () => {
    await mkdir(join(root, 'opt'), { recursive: true });
    await renderHooks();
    await fakeStateCli({ status: 'unprotected', reasons: [], hooks: { intact: false, reasons: ['Stop hook is disabled in Codex config'] } });
    for (const event of ['SessionStart', 'UserPromptSubmit']) {
      expect(context(event)).toContain(`${notIntact}: Stop hook is disabled in Codex config.`);
    }
    await fakeStateCli({ status: 'protected', reasons: [], hooks: { intact: true, reasons: [] } });
    expect(context()).not.toContain(notIntact);
  });

  it('prints the protection status and hook trust from the state CLI', async () => {
    const out = spawnSync(process.execPath, [STATE_CLI, 'protection'], { env, encoding: 'utf8' });
    expect(out.status, out.stderr).toBe(0);
    const protection = JSON.parse(out.stdout);
    expect(protection.status).toBe('unprotected');
    expect(protection.reasons[0]).toMatch(/^server runs outside /);
    expect(protection.hooks).toEqual({ intact: false, reasons: [`${join(root, '.codex', 'hooks.json')} missing or unreadable`] });
    const bad = spawnSync(process.execPath, [STATE_CLI, 'protection', repo], { env, encoding: 'utf8' });
    expect(bad.status).toBe(1);
  });

  const FALLBACK = "state read by the hook's own replay; owner clears unverified";
  const STATE_CLI = fileURLToPath(new URL('../../../../plugins/claude-bridge/mcp/state-cli.mjs', import.meta.url));
  const ownerKeys = () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return { privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicPem: publicKey.export({ type: 'spki', format: 'pem' }) };
  };
  const installOwnerKey = async () => {
    const owner = ownerKeys();
    await mkdir(join(root, 'etc'), { recursive: true });
    await writeFile(join(root, 'etc', 'owner.pub'), owner.publicPem);
    return owner;
  };
  // A writer with its own key pair appends a clear that its own key accepts.
  const forgeClear = (verdictId) => {
    const attacker = ownerKeys();
    const signed = signOwnerClear({ verdict_id: verdictId, reason: 'forged', issued_at: new Date().toISOString(), repo_key: repoKey(repo) }, attacker.privatePem);
    expect(applyOwnerClear(repo, env, signed, attacker.publicPem).applied).toBe(true);
  };
  const withStateCli = (cli = STATE_CLI) => { env = { ...env, CLAUDE_BRIDGE_TEST_MODE: '1', CLAUDE_BRIDGE_STATE_CLI: cli }; };

  it('prints the verdict state from the state CLI, with owner clears verified against the installed key', async () => {
    const cli = (args) => spawnSync(process.execPath, [STATE_CLI, ...args], { env, encoding: 'utf8' });
    const recorded = record();
    let out = cli(['current-state', repo]);
    expect(out.status, out.stderr).toBe(0);
    expect(JSON.parse(out.stdout)).toMatchObject({ status: 'open', open: { id: recorded.id, verdict: 'corrected', operator_readback: verdict.operator_readback, readback_confirmed: false } });
    await installOwnerKey();
    forgeClear(recorded.id);
    out = cli(['current-state', repo]);
    expect(out.status, out.stderr).toBe(0);
    expect(JSON.parse(out.stdout)).toMatchObject({ status: 'tampered', open: null, reason: 'forged owner clear in chain' });
    for (const args of [[], ['other', repo], ['current-state']]) {
      const bad = cli(args);
      expect(bad.status).toBe(1);
      expect(JSON.parse(bad.stdout).error).toMatch(/usage/);
    }
  });

  it('reads the state through the state CLI: a forged owner clear reads as tampered and Stop stays silent', async () => {
    await installOwnerKey();
    const recorded = record({ ...verdict, verdict: 'blocked' });
    forgeClear(recorded.id);
    withStateCli();
    const text = context();
    expect(text).toContain(`${INTEGRITY}: forged owner clear in chain`);
    expect(text).not.toContain(FALLBACK);
    const before = await readFile(join(stateDir(), 'verdicts.jsonl'), 'utf8');
    for (const message of [verdict.operator_readback, 'nope']) {
      expect(run(base('Stop', { last_assistant_message: message, stop_hook_active: false })).stdout.trim()).toBe('');
    }
    expect(await readFile(join(stateDir(), 'verdicts.jsonl'), 'utf8')).toBe(before);
  });

  it('falls back to its own replay when the state CLI is absent, fails, or its override is outside test mode', async () => {
    await installOwnerKey();
    const recorded = record({ ...verdict, verdict: 'blocked' });
    forgeClear(recorded.id);
    // No CLI under the protected root: the hook's replay takes the forged clear as written.
    let text = context();
    expect(text).toContain(FALLBACK);
    expect(text).not.toContain(INTEGRITY);
    // The override is honoured only in test mode.
    env = { ...env, CLAUDE_BRIDGE_STATE_CLI: STATE_CLI };
    expect(context()).toContain(FALLBACK);
    // A CLI that fails.
    const failing = join(root, 'failing-cli.mjs');
    await writeFile(failing, 'process.stdout.write(JSON.stringify({ error: "boom" })); process.exit(1);\n');
    withStateCli(failing);
    text = context();
    expect(text).toContain(FALLBACK);
    expect(text).not.toContain(INTEGRITY);
    // A CLI whose output is not a state.
    await writeFile(failing, 'process.stdout.write(JSON.stringify({ status: "fine" }));\n');
    expect(context()).toContain(FALLBACK);
  });

  it('runs the state CLI with /usr/bin/node and a minimal environment, whatever PATH and NODE_OPTIONS say', async () => {
    await installOwnerKey();
    const recorded = record({ ...verdict, verdict: 'blocked' });
    forgeClear(recorded.id);
    withStateCli();
    // A node on PATH that claims the state is clear, and NODE_OPTIONS that would stop any node from starting.
    const bin = join(root, 'bin');
    await mkdir(bin);
    await writeFile(join(bin, 'node'), '#!/bin/sh\nprintf \'{"status":"clear","open":null}\\n\'\n', { mode: 0o755 });
    env = { ...env, PATH: `${bin}:${env.PATH}`, NODE_OPTIONS: `--require ${join(root, 'missing.cjs')}` };
    const text = context();
    expect(text).toContain(`${INTEGRITY}: forged owner clear in chain`);
    expect(text).not.toContain(FALLBACK);
  });

  it('uses the state CLI installed under the protected root, and its open verdict for the Stop decision', async () => {
    await installOwnerKey();
    await mkdir(join(root, 'opt', 'current'), { recursive: true });
    await cp(dirname(STATE_CLI), join(root, 'opt', 'current', 'mcp'), { recursive: true });
    const recorded = record();
    const text = context();
    expect(text).not.toContain(FALLBACK);
    expect(text).toContain(verdict.operator_readback);
    const blocked = run(base('Stop', { last_assistant_message: 'Done.', stop_hook_active: false }));
    expect(blocked.json.decision).toBe('block');
    expect(blocked.json.reason).toContain(verdict.operator_readback);
    expect(readOpen(repo, env).readback_attempts).toBe(1);
    expect(run(base('Stop', { last_assistant_message: verdict.operator_readback, stop_hook_active: true })).stdout.trim()).toBe('');
    expect(readOpen(repo, env)).toBeNull();
    const chain = readChain(stateDir());
    expect(chain.intact).toBe(true);
    expect(chain.records.at(-1)).toMatchObject({ type: 'readback_confirmed', verdict_id: recorded.id, by: 'stop_hook' });
    expect(currentState(repo, env).status).toBe('clear');
  });

  const pythonChain = () => {
    const script = [
      'import json, sys',
      `sys.path.insert(0, ${JSON.stringify(dirname(HOOK))})`,
      'import bridge_hook as hook',
      'chain = hook.read_chain(sys.argv[1])',
      'print(json.dumps({"intact": chain.intact, "count": len(chain.records)}))',
    ].join('\n');
    const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', script, stateDir()], { env, encoding: 'utf8' });
    expect(result.stderr).toBe('');
    return JSON.parse(result.stdout);
  };

  it('reads a planted line that is not a compact object as broken, in Python as in Node', async () => {
    record();
    const [first] = (await readFile(join(stateDir(), 'verdicts.jsonl'), 'utf8')).split('\n');
    const prev = sha256Hex(canonicalJson(JSON.parse(first)));
    for (const planted of [
      'null', '5', '[]', '"text"',
      `{"type":"lock_broken","stale_ms":5.0,"prev":"${prev}"}`,
      `{"type":"lock_broken", "prev":"${prev}"}`,
      `{"type":"lock_broken","note":"\\u0041","prev":"${prev}"}`,
      `{"b":1,"10":2,"prev":"${prev}"}`,
      `{"type":"lock_broken","type":"verdict","prev":"${prev}"}`,
      `{"type":"lock_broken","note":"\\ud800","prev":"${prev}"}`,
    ]) {
      await writeFile(join(stateDir(), 'verdicts.jsonl'), `${first}\n${planted}\n`);
      expect(readChain(stateDir()).intact, planted).toBe(false);
      expect(pythonChain().intact, planted).toBe(false);
    }
  });

  it("passes a Node-written chain through Python's compact-form check", async () => {
    const owner = ownerKeys();
    const job_id = { b: 1, 10: 2, 9: 3, a: 4, '￿': 5, '\u{1F600}': 6, text: 'é   \u0001\u001f "q" \\ / 😀\t\n' };
    record(verdict, { job_id });
    record({ ...verdict, verdict: 'blocked', report: 'line one\nline two é中\u{1F600}', reprimand: null });
    recordRunStarted(repo, env, { job_id: 'job é\u0001', profile: 'review', model: 'claude-fable-5-1' });
    const junk = { type: 'owner_clear', verdict_id: 'x', reason: 'y', issued_at: new Date().toISOString(), repo_key: repoKey(repo), signature: 'AAAA' };
    expect(applyOwnerClear(repo, env, junk, owner.publicPem)).toEqual({ applied: false, reason: 'signature invalid' });
    const signed = signOwnerClear({ verdict_id: '*', reason: 'owner é', issued_at: new Date().toISOString(), repo_key: repoKey(repo) }, owner.privatePem);
    expect(applyOwnerClear(repo, env, signed, owner.publicPem).applied).toBe(true);
    const chain = readChain(stateDir());
    expect(chain.intact).toBe(true);
    expect(pythonChain()).toEqual({ intact: true, count: chain.records.length });
    expect(chain.records.map((entry) => entry.type)).toEqual(['verdict', 'verdict', 'run_started', 'rejected_clear', 'owner_clear']);
  });

  it('ignores every location and test knob in the environment when the hook runs from /opt/claude-bridge', () => {
    const probe = (selfPath) => {
      const script = [
        'import json, sys',
        `sys.path.insert(0, ${JSON.stringify(dirname(HOOK))})`,
        'import bridge_hook as hook',
        'print(json.dumps(hook.runtime_defaults(sys.argv[1])))',
      ].join('\n');
      const knobs = {
        ...env, CLAUDE_BRIDGE_SESSIONS_ROOT: join(root, 'sessions'), CLAUDE_BRIDGE_TEST_MODE: '1',
        CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS: '100', CLAUDE_BRIDGE_STATE_CLI: join(root, 'cli.mjs'),
      };
      const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', script, selfPath], { env: knobs, encoding: 'utf8' });
      expect(result.stderr).toBe('');
      return JSON.parse(result.stdout);
    };
    expect(probe(join(root, 'opt', 'current', 'hooks', 'bridge_hook.py'))).toEqual({
      installed: false, home: root, codex_home: join(root, '.codex'), state_root: join(root, 'state'), sessions_root: join(root, 'sessions'),
      protected_root: join(root, 'opt'), etc_dir: join(root, 'etc'), test_mode: true, state_cli: join(root, 'cli.mjs'), lock_timeout_ms: 100,
    });
    const home = userInfo().homedir;
    expect(probe('/opt/claude-bridge/current/hooks/bridge_hook.py')).toEqual({
      installed: true, home, codex_home: join(home, '.codex'), state_root: join(home, '.local', 'state', 'claude-bridge'), sessions_root: join(home, '.codex', 'sessions'),
      protected_root: '/opt/claude-bridge', etc_dir: '/etc/claude-bridge', test_mode: false, state_cli: '/opt/claude-bridge/current/mcp/state-cli.mjs', lock_timeout_ms: 3000,
    });
    expect(probe('/opt/claude-bridge-other/hooks/bridge_hook.py').installed).toBe(false);
  });

  const pythonHooksIntact = () => {
    const script = [
      'import json, sys',
      `sys.path.insert(0, ${JSON.stringify(dirname(HOOK))})`,
      'import bridge_hook as hook',
      'intact, reasons = hook.hooks_intact()',
      'print(json.dumps({"intact": intact, "reasons": reasons}))',
    ].join('\n');
    const result = spawnSync('/usr/bin/python3', ['-I', '-B', '-c', script], { env, encoding: 'utf8' });
    expect(result.stderr).toBe('');
    return JSON.parse(result.stdout);
  };

  it('keeps serving when python3 lacks tomllib: trust reads not intact and the hook does not crash', async () => {
    await mkdir(join(root, 'opt'), { recursive: true });
    await renderHooks();
    await trustHooks();
    // Run the hook through a wrapper that makes `import tomllib` fail, as it would on python3 < 3.11.
    const withoutTomllib = (input) => {
      const wrapper = `import sys; sys.modules['tomllib'] = None; import runpy; runpy.run_path(${JSON.stringify(HOOK)}, run_name='__main__')`;
      const result = spawnSync('/usr/bin/python3', ['-I', '-c', wrapper], { input: JSON.stringify(input), env, encoding: 'utf8' });
      return { code: result.status, stdout: result.stdout, stderr: result.stderr, json: result.stdout.trim() ? JSON.parse(result.stdout) : null };
    };
    // The context (state CLI absent → the hook's own trust check) reads not intact without crashing.
    const ctx = withoutTomllib(base('SessionStart'));
    expect(ctx.stderr).toBe('');
    expect(ctx.json.hookSpecificOutput.additionalContext).toContain('python3 lacks tomllib');
    // A bridge call is still denied, not allowed, and the hook does not crash.
    const pre = withoutTomllib(base('PreToolUse', { tool_name: 'mcp__claude_bridge__claude_review', tool_input: { prompt: 'x' } }));
    expect(pre.code).toBe(0);
    expect(pre.json.hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('reads the Codex trust entries with tomllib, as protection.mjs does', async () => {
    const hooksPath = join(root, '.codex', 'hooks.json');
    await renderHooks();
    const hash = `sha256:${'ab'.repeat(32)}`;
    const table = (key, extra = '') => `[hooks.state."${hooksPath}:${key}:0:0"]\ntrusted_hash = "${hash}"\n${extra}`;
    const keys = ['session_start', 'user_prompt_submit', 'pre_tool_use', 'post_tool_use', 'stop'];
    const configPath = join(root, '.codex', 'config.toml');
    await writeFile(configPath, keys.map((key) => table(key)).join('\n'));
    expect(pythonHooksIntact()).toEqual({ intact: true, reasons: [] });
    await writeFile(configPath, trustBypassConfig(hooksPath, hash));
    expect(pythonHooksIntact()).toEqual({ intact: false, reasons: ['Stop hook is disabled in Codex config'] });
    await writeFile(configPath, ['[features]\ncodex_hooks = false\n', ...keys.map((key) => table(key))].join('\n'));
    expect(pythonHooksIntact()).toEqual({ intact: false, reasons: ['hooks disabled by features.codex_hooks'] });
    await writeFile(configPath, [`[hooks.state]\n"${hooksPath}:stop:0:0".enabled = false\n`, ...keys.map((key) => table(key))].join('\n'));
    expect(pythonHooksIntact().reasons.join(' ')).toMatch(/^cannot parse config\.toml: /);
    await writeFile(configPath, [...keys.map((key) => table(key)), table('stop')].join('\n'));
    expect(pythonHooksIntact().reasons.join(' ')).toMatch(/^cannot parse config\.toml: /);
    await writeFile(configPath, [...keys.filter((key) => key !== 'stop').map((key) => table(key)), table('stop', 'status = "on"\n')].join('\n'));
    expect(pythonHooksIntact()).toEqual({ intact: false, reasons: ['Stop hook is not intact: unexpected trust state'] });
    // Without the state CLI, the hook's own context reports what it read.
    await mkdir(join(root, 'opt'), { recursive: true });
    await writeFile(configPath, trustBypassConfig(hooksPath, hash));
    expect(context()).toContain(`${notIntact}: Stop hook is disabled in Codex config.`);
  });

  it('registers the hook exactly as protection.mjs expects', async () => {
    const dummy = '/dummy/opt/claude-bridge';
    const rendered = JSON.parse((await readFile(TEMPLATE, 'utf8')).split('__PROTECTED_ROOT__').join(dummy));
    const command = expectedHookCommand({ CLAUDE_BRIDGE_PROTECTED_ROOT: dummy });
    expect(command).toBe('/usr/bin/python3 -I /dummy/opt/claude-bridge/current/hooks/bridge_hook.py');
    expect(Object.keys(rendered)).toEqual(['hooks']);
    expect(Object.keys(rendered.hooks).sort()).toEqual(Object.keys(EXPECTED_HOOKS).sort());
    for (const [event, expected] of Object.entries(EXPECTED_HOOKS)) {
      expect(rendered.hooks[event]).toHaveLength(1);
      const [group] = rendered.hooks[event];
      expect(Object.keys(group).sort()).toEqual(expected.matcher === undefined ? ['hooks'] : ['hooks', 'matcher']);
      expect(group.matcher).toBe(expected.matcher);
      expect(group.hooks).toHaveLength(1);
      expect(Object.keys(group.hooks[0]).sort()).toEqual(['command', 'timeout', 'type']);
      expect(group.hooks[0]).toEqual({ type: 'command', command, timeout: expected.timeout });
    }
  });
});
