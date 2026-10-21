// plugins/claude-bridge/mcp/session-evidence.mjs
import { existsSync, mkdirSync, readdirSync, statSync, fstatSync, writeFileSync, openSync, readSync, closeSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { sha256Hex } from './canonical.mjs';

export function sessionsRoot(env = process.env) {
  return env.CLAUDE_BRIDGE_SESSIONS_ROOT || join(env.CODEX_HOME || join(env.HOME || homedir(), '.codex'), 'sessions');
}

function insideRepo(candidate, repoRoot) {
  const rel = relative(resolve(repoRoot), resolve(candidate));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

// Real rollouts open with a ~22 KB session_meta line and grow past the ~512 MB one
// JavaScript string can hold, so logs are read in chunks. Lines split on the newline
// byte, which never occurs inside a multi-byte UTF-8 sequence.
export const READ_CHUNK_BYTES = 1 << 20;

// The tool call that carries the prompt is appended at the end of the calling
// session's log, and whole logs reach 1.2 GB, so the locator reads only the tail.
export const TAIL_SEARCH_BYTES = 8 << 20;

function eachChunk(path, onChunk) {
  const fd = openSync(path, 'r');
  try {
    const buffer = Buffer.allocUnsafe(READ_CHUNK_BYTES);
    for (let position = 0; ;) {
      const bytes = readSync(fd, buffer, 0, buffer.length, position);
      if (bytes === 0 || onChunk(buffer.subarray(0, bytes)) === false) return;
      position += bytes;
    }
  } finally { closeSync(fd); }
}

function eachLine(path, onLine) {
  let pending = [];
  eachChunk(path, (chunk) => {
    let start = 0;
    for (let end = chunk.indexOf(10); end !== -1; end = chunk.indexOf(10, start)) {
      const piece = chunk.subarray(start, end);
      onLine((pending.length > 0 ? Buffer.concat([...pending, piece]) : piece).toString('utf8'));
      pending = [];
      start = end + 1;
    }
    if (start < chunk.length) pending.push(Buffer.from(chunk.subarray(start)));
  });
  if (pending.length > 0) onLine(Buffer.concat(pending).toString('utf8'));
}

// One chunk bounds the read; a first line without a newline inside it fails to parse.
function readFirstLine(path) {
  let first = '';
  eachChunk(path, (chunk) => {
    const end = chunk.indexOf(10);
    first = chunk.subarray(0, end === -1 ? chunk.length : end).toString('utf8');
    return false;
  });
  return first;
}

function readTail(path) {
  const fd = openSync(path, 'r');
  try {
    const { size } = fstatSync(fd);
    const start = Math.max(0, size - TAIL_SEARCH_BYTES);
    const buffer = Buffer.allocUnsafe(size - start);
    let filled = 0;
    while (filled < buffer.length) {
      const bytes = readSync(fd, buffer, filled, buffer.length - filled, start + filled);
      if (bytes === 0) break;
      filled += bytes;
    }
    return buffer.subarray(0, filled).toString('utf8');
  } finally { closeSync(fd); }
}

function walk(dir, out) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && /^rollout-.*\.jsonl$/.test(entry.name)) out.push(full);
  }
  return out;
}

export function listCandidateSessions({ sessionsRoot: root, repoRoot, now = Date.now(), maxAgeMs = 12 * 3600_000 }) {
  const found = [];
  for (const path of walk(root, [])) {
    let stat;
    try { stat = statSync(path); } catch { continue; }
    if (now - stat.mtimeMs > maxAgeMs) continue;
    let meta;
    try { meta = JSON.parse(readFirstLine(path)); } catch { continue; }
    const payload = meta?.payload;
    if (meta?.type !== 'session_meta' || typeof payload?.cwd !== 'string') continue;
    const source = payload.source;
    if (typeof source === 'object' && source !== null && 'subagent' in source) continue;
    if (!insideRepo(payload.cwd, repoRoot)) continue;
    found.push({ path, id: payload.id, cwd: payload.cwd, mtimeMs: stat.mtimeMs });
  }
  return found.sort((a, b) => b.mtimeMs - a.mtimeMs);
}

function escapeJson(text) {
  return JSON.stringify(text).slice(1, -1);
}

// The log stores the tool-call source as a JSON string. A prompt written as a template or
// single-quoted JS string appears escaped once; one written as a double-quoted JS string has
// its quotes and backslashes escaped twice. Needles come from the first non-empty line, cut at
// 160 code points, in tiers, strongest first: the whole line in both forms, then, when the line
// holds a quote or backslash, the text before it. A needle under 20 characters is too weak to
// trust, so a prompt without one yields no tiers.
function promptNeedles(prompt) {
  const line = String(prompt).split('\n').find((text) => text.trim() !== '') ?? '';
  const first = Array.from(line).slice(0, 160).join('');
  if (escapeJson(first).length < 20) return [];
  const forms = (text) => [...new Set([escapeJson(text), escapeJson(escapeJson(text))])];
  const tiers = [forms(first)];
  const cut = first.search(/["\\]/);
  if (cut !== -1 && Array.from(first.slice(0, cut)).length >= 20) tiers.push(forms(first.slice(0, cut)));
  return tiers;
}

// The newest candidate holding the strongest tier wins, so a newer log that holds only a
// shared prefix never beats an older one holding the whole line.
function bestMatch(candidates, tiers) {
  let best = null;
  for (const candidate of candidates) {
    let text;
    try { text = readTail(candidate.path); } catch { continue; }
    const tier = tiers.findIndex((needles) => needles.some((needle) => text.includes(needle)));
    if (tier !== -1 && (best === null || tier < best.tier)) best = { candidate, tier };
    if (best?.tier === 0) break;
  }
  return best?.candidate ?? null;
}

export async function locateSession({ sessionsRoot: root, repoRoot, prompt, timeoutMs = 3_000, pollMs = 250, now = Date.now }) {
  const tiers = promptNeedles(prompt);
  const deadline = now() + timeoutMs;
  let candidates = [];
  while (true) {
    candidates = listCandidateSessions({ sessionsRoot: root, repoRoot, now: now() });
    if (tiers.length === 0) break; // nothing to search for: waiting cannot change the answer
    const found = bestMatch(candidates, tiers);
    if (found) return { match: 'prompt', path: found.path, id: found.id, candidates: candidates.length };
    if (now() >= deadline) break;
    await sleep(pollMs);
  }
  if (candidates.length > 0) return { match: 'recency', path: candidates[0].path, id: candidates[0].id, candidates: candidates.length };
  return { match: 'none', path: null, id: null, candidates: 0 };
}

const INJECTED = [
  [/^# AGENTS\.md instructions/, () => '[injected: AGENTS.md instructions]'],
  [/^<skill>\s*\n<name>([^<\n]+)<\/name>/, (m) => `[injected: skill ${m[1]}]`],
  [/^<environment_context>/, () => '[injected: environment context]'],
  [/^<INSTRUCTIONS>/, () => '[injected: instructions]'],
];

// Every body line is indented four spaces, so a body can never start a line with `## [`:
// headers stay at column 0 and truncation splits only on real ones. A lone CR counts as a
// line break, as Markdown reads it.
function indentBody(text) {
  return text.split(/\r\n|\r|\n/).map((line) => `    ${line}`).join('\n');
}

function collapse(text) {
  for (const [pattern, render] of INJECTED) {
    const match = pattern.exec(text);
    if (match) return render(match);
  }
  return text;
}

export const VERIFIED_RULE = 'Messages marked verified were recorded by the Codex hook in some turn for this repository, not necessarily at this place in the log; unverified messages come only from the session file, which the agent can write.';

const ledgerHashes = (ledger, type) => new Set((Array.isArray(ledger) ? ledger : [])
  .filter((record) => record?.type === type && typeof record.sha256 === 'string')
  .map((record) => record.sha256));

/**
 * The owner and agent messages of a Codex session log. `ledger` is the hook's turns ledger: a user message whose
 * text hashes to an `owner_prompt` there is `OWNER (verified)`, an assistant message hashing to an
 * `assistant_message` is `CODEX (verified)`; every other message is labelled unverified.
 */
export function extractConversation(jsonlPath, { maxBytes = 2_000_000, ledger = [] } = {}) {
  const owner = ledgerHashes(ledger, 'owner_prompt');
  const codex = ledgerHashes(ledger, 'assistant_message');
  const blocks = [];
  let messages = 0;
  let verified = 0;
  eachLine(jsonlPath, (line) => {
    if (!line.trim()) return;
    let entry;
    try { entry = JSON.parse(line); } catch { return; }
    if (entry === null || typeof entry !== 'object') return;
    const stamp = typeof entry.timestamp === 'string' ? entry.timestamp.slice(11, 19) + 'Z' : '--:--:--Z';
    if (entry.type === 'compacted') { blocks.push(`---- compaction ---- [${stamp}]`); return; }
    const payload = entry.payload;
    if (entry.type !== 'response_item' || payload?.type !== 'message') return;
    if (payload.role !== 'user' && payload.role !== 'assistant') return;
    const parts = Array.isArray(payload.content) ? payload.content : [];
    const raw = parts.map((part) => part?.text ?? '').join('\n');
    const text = raw.trim();
    if (!text) return;
    messages += 1;
    const hashes = payload.role === 'user' ? owner : codex;
    const recorded = hashes.has(sha256Hex(raw)) || hashes.has(sha256Hex(text));
    if (recorded) verified += 1;
    const label = payload.role === 'user'
      ? (recorded ? 'OWNER (verified)' : 'OWNER (unverified: not recorded by the hook)')
      : (recorded ? 'CODEX (verified)' : 'CODEX (unverified)');
    blocks.push(`## [${stamp}] ${label}\n${indentBody(collapse(text))}`);
  });
  let markdown = blocks.join('\n\n') + '\n';
  let truncated = false;
  if (Buffer.byteLength(markdown, 'utf8') > maxBytes) {
    truncated = true;
    const bytes = Buffer.from(markdown, 'utf8');
    let tail = bytes.subarray(bytes.length - maxBytes).toString('utf8');
    const firstBlock = tail.indexOf('\n## [');
    if (firstBlock !== -1) tail = tail.slice(firstBlock + 1);
    markdown = `> Conversation truncated to the last ${maxBytes} bytes of a ${bytes.length}-byte transcript. Earlier messages exist in the session log.\n\n${tail}`;
  }
  return { markdown, messages, truncated, verified, unverified: messages - verified };
}

export const BRIDGE_CALL_MAX_AGE_MS = 10 * 60_000;

/**
 * The session the hook recorded for this bridge call: the transcript path of the newest `bridge_call` in the turns
 * ledger, no older than BRIDGE_CALL_MAX_AGE_MS, whose file still has the recorded inode. Null when there is none.
 */
export function ledgerSession(records, { now = Date.now(), maxAgeMs = BRIDGE_CALL_MAX_AGE_MS } = {}) {
  for (const record of [...(Array.isArray(records) ? records : [])].reverse()) {
    if (record?.type !== 'bridge_call' || typeof record.transcript_path !== 'string' || typeof record.inode !== 'string') continue;
    const at = Date.parse(record.recorded_at);
    if (!Number.isFinite(at) || now - at > maxAgeMs) continue;
    let inode;
    try { inode = String(statSync(record.transcript_path, { bigint: true }).ino); } catch { continue; }
    if (inode !== record.inode) continue;
    return { match: 'ledger', path: record.transcript_path, id: typeof record.session_id === 'string' ? record.session_id : null, candidates: 0 };
  }
  return null;
}

export function historyMarkdown(records) {
  const verdicts = records.filter((record) => record.type === 'verdict');
  if (verdicts.length === 0) return '# Prior bridge calls\n\nNone recorded for this repository.\n';
  const rows = verdicts.map((record) => `- ${record.recorded_at} job ${record.job_id} (${record.profile}): verdict **${record.verdict?.verdict}**, prompt sha256 ${record.prompt_sha256}; readback: ${record.verdict?.operator_readback ?? ''}`);
  return `# Prior bridge calls\n\n${rows.join('\n')}\n`;
}

export function writeEvidence({ evidenceDir, conversation, brief, history, session, profile }) {
  mkdirSync(evidenceDir, { recursive: true });
  const files = {
    'conversation.md': `# Owner and agent conversation (from the Codex session log)\n\nSession match: ${session.match}${session.path ? ` (${session.path})` : ''}. Messages: ${conversation.messages}.${conversation.truncated ? ' Truncated.' : ''}\n\nEach message body is indented four spaces. Only a line starting at column 0 with \`## [\` is a message header.\n\n${VERIFIED_RULE}${conversation.ledger_note ? ` ${conversation.ledger_note}` : ''}\n\n${conversation.markdown}`,
    'brief.md': `# The agent's brief\n\nThis is the agent's framing of the task. Treat it as a claim.\n\n---\n\n${brief}\n`,
    'bridge-history.md': history,
  };
  for (const [name, text] of Object.entries(files)) writeFileSync(join(evidenceDir, name), text);
  const manifest = {
    profile, session, written_at: new Date().toISOString(),
    files: [...Object.keys(files), 'manifest.json'],
    sha256: Object.fromEntries(Object.entries(files).map(([name, text]) => [name, sha256Hex(text)])),
    conversation: { messages: conversation.messages, truncated: conversation.truncated, verified: conversation.verified ?? 0, unverified: conversation.unverified ?? conversation.messages },
  };
  writeFileSync(join(evidenceDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}
