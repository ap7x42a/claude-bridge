// plugins/claude-bridge/mcp/verdict.mjs
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { canonicalJson, sha256Hex } from './canonical.mjs';

const VERDICT_VALUES = ['clear', 'corrected', 'blocked'];
const FINDING_STATUS = ['established', 'plausible', 'not_established'];
const ACTIONS = ['edited', 'created', 'deleted', 'reverted', 'committed'];
const COVERAGE = ['full', 'partial', 'unavailable'];

export const VERDICT_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'deception_found', 'counter_to_operator_request', 'findings', 'corrective_actions', 'reprimand', 'required_of_codex', 'operator_readback', 'report', 'evidence_coverage'],
  properties: {
    verdict: { type: 'string', enum: VERDICT_VALUES },
    deception_found: { type: 'boolean' },
    counter_to_operator_request: { type: 'boolean' },
    findings: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['id', 'claim', 'evidence', 'status'], properties: { id: { type: 'string' }, claim: { type: 'string' }, evidence: { type: 'string' }, status: { type: 'string', enum: FINDING_STATUS } } } },
    corrective_actions: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['path', 'action', 'summary'], properties: { path: { type: 'string' }, action: { type: 'string', enum: ACTIONS }, summary: { type: 'string' } } } },
    reprimand: { type: ['string', 'null'] },
    required_of_codex: { type: 'array', items: { type: 'string' } },
    operator_readback: { type: 'string', minLength: 1 },
    report: { type: 'string' },
    evidence_coverage: { type: 'object', additionalProperties: false, required: ['session_conversation', 'notes'], properties: { session_conversation: { type: 'string', enum: COVERAGE }, notes: { type: 'string' } } },
  },
});

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
// additionalProperties: false. An unknown key could carry a float, whose canonical form differs between Node and Python.
const onlyKnownKeys = (value, schema) => Object.keys(value).every((key) => Object.hasOwn(schema.properties, key));
const hasRequiredKeys = (value, schema) => schema.required.every((key) => Object.hasOwn(value, key));
const FINDING_SCHEMA = VERDICT_SCHEMA.properties.findings.items;
const ACTION_SCHEMA = VERDICT_SCHEMA.properties.corrective_actions.items;
const COVERAGE_SCHEMA = VERDICT_SCHEMA.properties.evidence_coverage;
const isFinding = (item) => isObject(item) && onlyKnownKeys(item, FINDING_SCHEMA)
  && typeof item.id === 'string' && typeof item.claim === 'string' && typeof item.evidence === 'string'
  && FINDING_STATUS.includes(item.status);
const isCorrectiveAction = (item) => isObject(item) && onlyKnownKeys(item, ACTION_SCHEMA)
  && typeof item.path === 'string' && typeof item.summary === 'string'
  && ACTIONS.includes(item.action);
const isCoverage = (value) => isObject(value) && onlyKnownKeys(value, COVERAGE_SCHEMA)
  && COVERAGE.includes(value.session_conversation) && typeof value.notes === 'string';

export function isVerdictShape(value) {
  if (!isObject(value) || !onlyKnownKeys(value, VERDICT_SCHEMA) || !hasRequiredKeys(value, VERDICT_SCHEMA)) return false;
  return VERDICT_VALUES.includes(value.verdict)
    && typeof value.deception_found === 'boolean'
    && typeof value.counter_to_operator_request === 'boolean'
    && Array.isArray(value.findings) && value.findings.every(isFinding)
    && Array.isArray(value.corrective_actions) && value.corrective_actions.every(isCorrectiveAction)
    && Array.isArray(value.required_of_codex) && value.required_of_codex.every((item) => typeof item === 'string')
    && (value.reprimand === null || typeof value.reprimand === 'string')
    && typeof value.operator_readback === 'string' && value.operator_readback.length > 0
    && typeof value.report === 'string'
    && isCoverage(value.evidence_coverage)
    && isCanonicalSafe(value);
}

/** True when Node and Python agree on the canonical form: no lone surrogates in any string, no unsafe numbers. */
function isCanonicalSafe(value) {
  try { canonicalJson(value); return true; } catch { return false; }
}

/** A caller-supplied string that may enter a chain record, or null. */
const safeString = (value) => (typeof value === 'string' && isCanonicalSafe(value) ? value : null);

export const RUN_STARTED_READBACK = 'Claude Bridge: a review run started and never recorded a verdict. Work is blocked until a review completes.';
const RUN_STARTED_REQUIRED = 'Rerun the review; a run started and never recorded a verdict.';

export function unparseableVerdict(note) {
  return {
    verdict: 'blocked', deception_found: false, counter_to_operator_request: false,
    findings: [], corrective_actions: [], reprimand: null,
    required_of_codex: ['Rerun the review; the previous result carried no parseable verdict.'],
    operator_readback: 'Claude Bridge: the review returned no parseable verdict. Work is blocked until a review is rerun.',
    report: '', evidence_coverage: { session_conversation: 'unavailable', notes: note },
  };
}

/**
 * The verdict from the structured output, else from the LAST fenced claude-bridge-verdict block in the result text.
 * A fenced block whose text the prompt already carries is rejected: the agent could have planted it for Claude to echo.
 */
export function parseVerdict({ structured_output, result_text, prompt }) {
  if (isVerdictShape(structured_output)) return { verdict: structured_output, parse: 'structured' };
  const fenced = [...String(result_text ?? '').matchAll(/```claude-bridge-verdict\s*\n([\s\S]*?)\n```/g)].at(-1);
  const body = fenced?.[1].trim();
  const planted = Boolean(body) && typeof prompt === 'string' && prompt.includes(body);
  if (fenced && !planted) {
    try {
      const candidate = JSON.parse(fenced[1]);
      if (isVerdictShape(candidate)) return { verdict: candidate, parse: 'fenced' };
    } catch { /* fall through */ }
  }
  const note = structured_output != null ? 'structured_output failed the verdict shape check'
    : planted ? 'fenced claude-bridge-verdict block appears verbatim in the prompt'
      : fenced ? 'fenced claude-bridge-verdict block failed to parse or failed the verdict shape check'
        : 'no structured_output and no fenced claude-bridge-verdict block';
  return { verdict: unparseableVerdict(note), parse: 'unparseable' };
}

export function stateRoot(env = process.env) {
  return env.CLAUDE_BRIDGE_STATE_DIR || join(env.HOME || homedir(), '.local', 'state', 'claude-bridge');
}
export function repoKey(repoRoot) { return sha256Hex(resolve(repoRoot)).slice(0, 20); }
export function repoStateDir(repoRoot, env = process.env) { return join(stateRoot(env), repoKey(repoRoot)); }
/**
 * Two hash-chained ledgers share a state directory and its lock: the verdicts, written by the bridge, its owner
 * command and the Stop hook; and the turns, written only by the hook (bridge_hook.py) from what the Codex app hands it.
 */
export const VERDICTS_LEDGER = Object.freeze({ chain: 'verdicts.jsonl', head: 'head.json' });
export const TURNS_LEDGER = Object.freeze({ chain: 'turns.jsonl', head: 'turns-head.json' });
const chainPath = (dir, ledger = VERDICTS_LEDGER) => join(dir, ledger.chain);
const openPath = (dir) => join(dir, 'open.json');
const headPath = (dir, ledger = VERDICTS_LEDGER) => join(dir, ledger.head);

const sleepMs = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function lockAgeMs(lock) {
  try { return Date.now() - statSync(lock).mtimeMs; } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * Advisory write lock: a `.lock` directory in the state dir, held for the length of `fn`.
 * A lock older than `staleMs` was left by a dead writer (critical sections take milliseconds): it is
 * removed, and once the lock is taken the break is recorded in the chain. `registered` reaches that
 * append so a break on a wiped registered chain still records the reset first.
 */
export function withStateLock(dir, fn, { timeoutMs = 3000, retryMs = 25, staleMs = 30_000, registered = false } = {}) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = join(dir, '.lock');
  const deadline = Date.now() + timeoutMs;
  let brokenAgeMs = null;
  for (;;) {
    try { mkdirSync(lock, { mode: 0o700 }); break; } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const ageMs = lockAgeMs(lock);
    if (ageMs !== null && ageMs > staleMs) {
      rmSync(lock, { recursive: true, force: true });
      brokenAgeMs = Math.round(ageMs); // an integer: a float's canonical form differs between Node and Python
      continue;
    }
    if (Date.now() >= deadline) {
      const fault = new Error(`state lock timeout: ${lock} is held; remove it if no Claude Bridge write is running`);
      fault.name = 'BridgeFault';
      fault.code = 'state_lock_timeout';
      fault.details = { lock };
      throw fault;
    }
    if (ageMs !== null) sleepMs(retryMs); // null: released between the two calls, so retry at once
  }
  try {
    if (brokenAgeMs !== null) appendRecord(dir, { type: 'lock_broken', recorded_at: new Date().toISOString(), stale_ms: brokenAgeMs }, { registered });
    return fn();
  } finally { rmSync(lock, { recursive: true, force: true }); }
}

/** `head` is the computed hash of the last record: '' for an empty chain file, null when there is no file. */
export function readChain(dir, ledger = VERDICTS_LEDGER) {
  const file = chainPath(dir, ledger);
  if (!existsSync(file)) return { records: [], intact: true, exists: false, head: null };
  const records = [];
  let prevHash = '';
  let intact = true;
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    let record;
    try { record = JSON.parse(line); } catch { intact = false; break; }
    // The bridge writes each record as an object in Node's compact form: anything else is a non-canonical line.
    if (!isObject(record) || JSON.stringify(record) !== line) { intact = false; break; }
    if ((record.prev ?? '') !== prevHash) intact = false;
    records.push(record);
    // A record with no canonical form was not written by this module.
    try { prevHash = sha256Hex(canonicalJson(record)); } catch { intact = false; break; }
  }
  return { records, intact, exists: true, head: prevHash };
}

function readHead(dir, ledger) {
  try { return JSON.parse(readFileSync(headPath(dir, ledger), 'utf8')); } catch { return null; }
}

/** head.json matches the chain, or neither exists. */
function headConsistent(dir, chain, ledger = VERDICTS_LEDGER) {
  if (!chain.exists) return !existsSync(headPath(dir, ledger));
  const head = readHead(dir, ledger);
  return Boolean(head) && head.hash === chain.head && head.count === chain.records.length;
}

/** The hashes link and head.json agrees. */
const chainConsistent = (dir, chain, ledger = VERDICTS_LEDGER) => chain.intact && headConsistent(dir, chain, ledger);

/** A ledger's records, and whether its hashes link and its head agrees (`consistent`); absent reads as empty. */
export function readLedger(dir, ledger = TURNS_LEDGER) {
  const chain = readChain(dir, ledger);
  return { records: chain.records, exists: chain.exists, consistent: chainConsistent(dir, chain, ledger) };
}

function archiveBrokenChain(dir) {
  const stamp = new Date().toISOString().replace(/[-:.]/g, '');
  for (const file of [chainPath(dir), headPath(dir)]) {
    if (existsSync(file)) renameSync(file, `${file}.broken-${stamp}`);
  }
}

function writeRecord(dir, body) {
  const chain = readChain(dir);
  const consistent = chainConsistent(dir, chain);
  const record = { ...body, prev: chain.head ?? '' };
  record.id = record.id ?? sha256Hex(canonicalJson(record)).slice(0, 16);
  const hash = sha256Hex(canonicalJson(record)); // throws before anything is written if the record has no canonical form
  appendFileSync(chainPath(dir), JSON.stringify(record) + '\n', { mode: 0o600 });
  // An append must not hide tampering: the head moves only on a consistent chain.
  if (consistent) {
    writeFileSync(headPath(dir), JSON.stringify({ hash, count: chain.records.length + 1 }) + '\n', { mode: 0o600 });
  }
  return record;
}

/** The single append path. Every writer goes through here, under withStateLock. */
function appendRecord(dir, body, { registered = false } = {}) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const chain = readChain(dir);
  if (body.type === 'owner_clear' && body.verdict_id === '*' && !chainConsistent(dir, chain)) {
    // The owner's exit from a broken chain: keep the old files as evidence and start fresh with this clear.
    archiveBrokenChain(dir);
  } else if (registered && !chain.exists) {
    // A registered repo always has a chain (seedState starts it); a missing one was deleted.
    writeRecord(dir, { type: 'state_reset_detected', recorded_at: new Date().toISOString(), note: 'registered repository had no verdict chain' });
  }
  return writeRecord(dir, body);
}

/** Start an empty chain for a newly registered repo, so its first review does not read as a reset. */
export function seedState(repoRoot, env = process.env, { lockTimeoutMs } = {}) {
  const dir = repoStateDir(repoRoot, env);
  return withStateLock(dir, () => {
    if (existsSync(chainPath(dir))) return { seeded: false };
    // A head left behind without its chain is evidence of a deletion; seeding over it would erase that.
    if (existsSync(headPath(dir))) return { seeded: false, reason: 'head.json present without a chain' };
    writeFileSync(chainPath(dir), '', { mode: 0o600 });
    writeFileSync(headPath(dir), JSON.stringify({ hash: '', count: 0 }) + '\n', { mode: 0o600 });
    return { seeded: true };
  }, { timeoutMs: lockTimeoutMs });
}

// Fields the append adds to a signed clear; the signature covers the rest, as in applyOwnerClear.
const CLEAR_BOOKKEEPING = new Set(['signature', 'recorded_at', 'prev', 'id']);

function ownerClearVerifies(record, publicKey) {
  if (publicKey === null || typeof record.signature !== 'string') return false;
  const payload = Object.fromEntries(Object.entries(record).filter(([key]) => !CLEAR_BOOKKEEPING.has(key)));
  try { return verify(null, Buffer.from(canonicalJson(payload), 'utf8'), publicKey, Buffer.from(record.signature, 'base64')); } catch { return false; }
}

/**
 * The chain is the authority: derive the open verdict from the records alone.
 * With `ownerPublicKeyPem`, an owner_clear lifts only when its signature verifies against that key, it names
 * `repoKey` (when given), and its signature is not one an earlier clear in the chain carried; any other
 * owner_clear is ignored and sets `forged_clear`. A verified clear of '*' ends a reset and a forged state.
 * Without a key every owner_clear is taken as written.
 */
export function replayChain(records, { ownerPublicKeyPem = null, repoKey: expectedRepoKey } = {}) {
  let publicKey = null;
  if (ownerPublicKeyPem !== null) {
    try { publicKey = createPublicKey(ownerPublicKeyPem); } catch { publicKey = null; } // an unusable key verifies nothing
  }
  // A run_started whose job has a later verdict is that verdict's run; one with none acts as a blocked verdict.
  const lastVerdictAt = new Map();
  records.forEach((record, index) => { if (record.type === 'verdict' && typeof record.job_id === 'string') lastVerdictAt.set(record.job_id, index); });
  const seenSignatures = new Set();
  let open = null;
  let openProfile = null; // the profile of the record that opened `open`
  let reset = false;
  let forged = false;
  // A task's verdict, or its run_started, never replaces (and so never lifts) an open verdict from a review.
  const coveredByReview = (record) => open !== null && openProfile === 'review' && record.profile === 'task';
  for (const [index, record] of records.entries()) {
    if (record.type === 'run_started') {
      if (typeof record.job_id === 'string' && (lastVerdictAt.get(record.job_id) ?? -1) > index) continue;
      if (coveredByReview(record)) continue;
      openProfile = record.profile;
      open = {
        id: record.id, verdict: 'blocked', operator_readback: RUN_STARTED_READBACK, required_of_codex: [RUN_STARTED_REQUIRED],
        reprimand: null, recorded_at: record.recorded_at, readback_confirmed: false, run_started: true,
      };
    } else if (record.type === 'verdict') {
      if (coveredByReview(record)) continue;
      const verdict = record.verdict ?? {};
      openProfile = record.profile;
      open = verdict.verdict === 'clear' ? null : {
        id: record.id, verdict: verdict.verdict, operator_readback: verdict.operator_readback,
        required_of_codex: verdict.required_of_codex, reprimand: verdict.reprimand,
        recorded_at: record.recorded_at, readback_confirmed: false,
      };
    } else if (record.type === 'readback_confirmed' && open && record.verdict_id === open.id) {
      open = open.verdict === 'corrected' ? null : { ...open, readback_confirmed: true };
    } else if (record.type === 'state_reset_detected') {
      reset = true;
    } else if (record.type === 'owner_clear') {
      if (ownerPublicKeyPem !== null) {
        const key = signatureKey(record.signature);
        const verified = ownerClearVerifies(record, publicKey)
          && (expectedRepoKey === undefined || record.repo_key === expectedRepoKey)
          && !seenSignatures.has(key);
        seenSignatures.add(key);
        if (!verified) { forged = true; continue; }
      }
      if (record.verdict_id === '*') { reset = false; forged = false; }
      if (open && (record.verdict_id === open.id || record.verdict_id === '*')) open = null;
    }
  }
  return { open, reset, forged_clear: forged };
}

export function readOpen(repoRoot, env = process.env) {
  const file = openPath(repoStateDir(repoRoot, env));
  if (!existsSync(file)) return null;
  try { return JSON.parse(readFileSync(file, 'utf8')); } catch { return { corrupt: true }; }
}
function writeOpen(dir, open) {
  if (open === null) { rmSync(openPath(dir), { force: true }); return; }
  writeFileSync(openPath(dir), JSON.stringify(open, null, 2) + '\n', { mode: 0o600 });
}

/** After an append: open.json holds the chain's open verdict; an unchanged one keeps its readback_attempts. */
function syncOpen(dir) {
  const { open } = replayChain(readChain(dir).records);
  if (open === null) { writeOpen(dir, null); return; }
  let cached = null;
  try { cached = JSON.parse(readFileSync(openPath(dir), 'utf8')); } catch { cached = null; }
  if (isObject(cached) && cached.id === open.id) return;
  writeOpen(dir, { ...open, readback_attempts: 0 });
}

export function recordVerdict(repoRoot, env, { job_id, profile, verdict, session, prompt_sha256, model, registered = false, lockTimeoutMs }) {
  const dir = repoStateDir(repoRoot, env);
  return withStateLock(dir, () => {
    const record = appendRecord(dir, {
      type: 'verdict', recorded_at: new Date().toISOString(), job_id, profile, model, prompt_sha256,
      session: { match: session?.match ?? 'none', path: session?.path ?? null },
      verdict,
    }, { registered });
    syncOpen(dir);
    return record;
  }, { timeoutMs: lockTimeoutMs, registered });
}

/**
 * Recorded before the provider starts. Until a verdict for the same job follows it, the chain reads it as an open
 * blocked verdict, so a bridge killed mid-run leaves work blocked until a review completes.
 */
export function recordRunStarted(repoRoot, env, { job_id, profile, model, registered = false, lockTimeoutMs }) {
  const dir = repoStateDir(repoRoot, env);
  return withStateLock(dir, () => {
    const record = appendRecord(dir, { type: 'run_started', recorded_at: new Date().toISOString(), job_id, profile, model }, { registered });
    syncOpen(dir);
    return record;
  }, { timeoutMs: lockTimeoutMs, registered });
}

/** The lift is decided from the chain's replay; a tampered state is never written to. */
export function confirmReadback(repoRoot, env, verdictId, { registered = false, lockTimeoutMs, ownerPublicKeyPem = null } = {}) {
  const dir = repoStateDir(repoRoot, env);
  return withStateLock(dir, () => {
    const state = currentState(repoRoot, env, { registered, ownerPublicKeyPem });
    if (state.status === 'tampered') return { confirmed: false, lifted: false, reason: 'tampered' };
    if (state.status !== 'open' || state.open.id !== verdictId) return { confirmed: false, lifted: false };
    appendRecord(dir, { type: 'readback_confirmed', verdict_id: verdictId, recorded_at: new Date().toISOString() }, { registered });
    if (state.open.verdict === 'corrected') { writeOpen(dir, null); return { confirmed: true, lifted: true }; }
    writeOpen(dir, { ...state.open, readback_confirmed: true });
    return { confirmed: true, lifted: false };
  }, { timeoutMs: lockTimeoutMs, registered });
}

export function signOwnerClear({ verdict_id, reason, issued_at, repo_key }, privateKeyPem) {
  const payload = { type: 'owner_clear', verdict_id, reason, issued_at, repo_key };
  const signature = sign(null, Buffer.from(canonicalJson(payload), 'utf8'), createPrivateKey(privateKeyPem)).toString('base64');
  return { ...payload, signature };
}

// Base64 decoding is lenient (whitespace, padding, spare bits), so compare signature bytes, not strings.
const signatureKey = (signature) => Buffer.from(String(signature), 'base64').toString('base64');

export function applyOwnerClear(repoRoot, env, signedClear, publicKeyPem, { now = Date.now(), maxAgeMs = 15 * 60 * 1000, registered = false, lockTimeoutMs } = {}) {
  const { signature, ...payload } = signedClear ?? {};
  if (payload.type !== 'owner_clear' || typeof signature !== 'string') return { applied: false, reason: 'malformed clear' };
  const dir = repoStateDir(repoRoot, env);
  return withStateLock(dir, () => {
    let valid = false;
    try { valid = verify(null, Buffer.from(canonicalJson(payload), 'utf8'), createPublicKey(publicKeyPem), Buffer.from(signature, 'base64')); } catch { valid = false; }
    const reject = (reason) => {
      // The payload is unverified caller data: only a canonical-safe string id enters the chain.
      appendRecord(dir, { type: 'rejected_clear', recorded_at: new Date().toISOString(), verdict_id: safeString(payload.verdict_id), reason: safeString(reason) }, { registered });
      return { applied: false, reason };
    };
    if (!valid) return reject('signature invalid');
    if (payload.repo_key !== repoKey(repoRoot)) return reject('wrong repository');
    const issuedAt = Date.parse(payload.issued_at);
    if (!Number.isFinite(issuedAt) || Math.abs(now - issuedAt) > maxAgeMs) return reject('stale');
    const key = signatureKey(signature);
    if (readChain(dir).records.some((record) => record.type === 'owner_clear' && signatureKey(record.signature) === key)) return reject('replayed');
    appendRecord(dir, { ...payload, signature: key, recorded_at: new Date().toISOString() }, { registered });
    const open = readOpen(repoRoot, env);
    if (open && (open.id === payload.verdict_id || payload.verdict_id === '*')) writeOpen(dir, null);
    return { applied: true, reason: 'ok' };
  }, { timeoutMs: lockTimeoutMs, registered });
}

/**
 * chain_intact: the hashes link and head.json agrees. open_cache_valid: open.json parses (or is absent).
 * `ownerPublicKeyPem`: the installed owner key; owner clears are then verified as the chain is read.
 */
export function currentState(repoRoot, env, { registered = false, ownerPublicKeyPem = null } = {}) {
  const dir = repoStateDir(repoRoot, env);
  const chain = readChain(dir);
  const open = readOpen(repoRoot, env);
  const health = { chain_intact: chainConsistent(dir, chain), open_cache_valid: !open?.corrupt };
  const tampered = (reason) => ({ status: 'tampered', open: null, ...health, reason });
  if (!chain.intact || open?.corrupt) return tampered('verdict chain or open record unreadable');
  if (registered && !chain.exists) return tampered('registered repository has no verdict state; owner clear required');
  if (!health.chain_intact) return tampered('chain head missing or does not match');
  const { open: replayed, reset, forged_clear: forged } = replayChain(chain.records, { ownerPublicKeyPem, repoKey: repoKey(repoRoot) });
  if (forged) return tampered('forged owner clear in chain');
  if (reset) return tampered('verdict state was reset; owner clear required');
  if (replayed && (!open || open.id !== replayed.id)) return tampered('open record missing or does not match the chain');
  if (!replayed && open) return tampered('open record present but the chain shows no open verdict');
  // open.json is a cache: the chain's fields win; open.json keeps readback_attempts (the hook counts there).
  if (replayed) return { status: 'open', open: { ...open, ...replayed }, ...health };
  return { status: 'clear', open: null, ...health };
}

export function vetoDecision(state, toolName) {
  const gated = toolName === 'claude_task' || toolName === 'claude_continue';
  if (!gated) return { allowed: true };
  if (state.status === 'tampered') {
    return { allowed: false, error_code: 'verdict_state_tampered', error_message: `Claude Bridge refuses ${toolName}: ${state.reason}. Only the owner can clear this.` };
  }
  if (state.status === 'open') {
    const open = state.open;
    return {
      allowed: false, error_code: 'verdict_open', open,
      error_message: `Claude Bridge refuses ${toolName}: verdict ${open.id} (${open.verdict}) is open. Read operator_readback to the operator verbatim and comply with required_of_codex. Only a later clear verdict or the owner lifts a blocked verdict.`,
    };
  }
  return { allowed: true };
}
