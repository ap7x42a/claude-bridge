// tests/fixtures/claude-bridge/make-rollout.mjs
import { mkdirSync, writeFileSync, utimesSync } from 'node:fs';
import { join } from 'node:path';

export function rolloutLine(type, payload, timestamp = '2026-10-10T20:00:00.000Z') {
  return JSON.stringify({ timestamp, type, payload });
}
export function userLine(text, ts) {
  return rolloutLine('response_item', { type: 'message', role: 'user', content: [{ type: 'input_text', text }] }, ts);
}
export function assistantLine(text, ts) {
  return rolloutLine('response_item', { type: 'message', role: 'assistant', content: [{ type: 'output_text', text }] }, ts);
}
export function toolCallLine(input, ts) {
  return rolloutLine('response_item', { type: 'custom_tool_call', name: 'exec', input }, ts);
}
/**
 * Writes sessions/<YYYY>/<MM>/<DD>/rollout-<stamp>-<id>.jsonl and returns its path.
 * `meta` adds session_meta fields; real logs carry a ~20 KB base_instructions there.
 */
export function writeRollout({ sessionsRoot, id, cwd, source = 'vscode', lines, mtime = new Date(), stamp = '2026-10-10T11-35-17', meta = {} }) {
  const dir = join(sessionsRoot, '2026', '10', '10');
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `rollout-${stamp}-${id}.jsonl`);
  const metaLine = rolloutLine('session_meta', { id, timestamp: '2026-10-10T16:35:17.100Z', cwd, originator: 'codex_mobile_linux', cli_version: '0.162.1', source, ...meta });
  writeFileSync(path, [metaLine, ...lines].join('\n') + '\n');
  utimesSync(path, mtime, mtime);
  return path;
}
