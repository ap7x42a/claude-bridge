// plugins/claude-bridge/mcp/canonical.mjs
import { createHash } from 'node:crypto';

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortValue(value[key])]));
  }
  // Python writes floats differently (1e-07 vs 1e-7, 1.0 vs 1) and keeps integers past 2^53 exact.
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('canonical JSON refuses numbers that are not safe integers');
  return value;
}

// JSON.stringify escapes only lone surrogates as \udXXX. An even run of backslashes before it is
// escaped backslashes followed by literal text, not an escape.
const LONE_SURROGATE_ESCAPE = /(?<!\\)(?:\\\\)*\\ud[89a-f][0-9a-f]{2}/i;

/**
 * Keys sorted, no whitespace. Python: json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).
 * Throws on what the two cannot agree on: lone UTF-16 surrogates and numbers that are not safe integers.
 */
export function canonicalJson(value) {
  const text = JSON.stringify(sortValue(value));
  if (LONE_SURROGATE_ESCAPE.test(text)) throw new Error('canonical JSON refuses lone surrogates');
  return text;
}

export function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}
