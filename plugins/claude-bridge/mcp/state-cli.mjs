#!/usr/bin/node
// plugins/claude-bridge/mcp/state-cli.mjs
// `node state-cli.mjs current-state <repoRoot>`: the verdict state as the bridge reads it, for the hook.
// `node state-cli.mjs protection`: the installed bridge's protectionStatus, with its hook trust state as `hooks`.
// `node state-cli.mjs context <repoRoot>`: both at once, `{ state, protection }`, so a hook needs one run.
// Read-only. Owner clears are verified against the installed public key. Every location comes from
// runtimeDefaults for this file's own path: run from /opt/claude-bridge, the environment's overrides and
// test knobs are ignored.
import process from 'node:process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hooksIntact, installedOwnerPublicKey, isRegisteredRepo, protectionStatus, runtimeDefaults } from './protection.mjs';
import { currentState } from './verdict.mjs';

const SELF = fileURLToPath(import.meta.url);

try {
  const [command, repoRoot, ...rest] = process.argv.slice(2);
  const usage = 'usage: state-cli.mjs current-state <repoRoot> | state-cli.mjs protection | state-cli.mjs context <repoRoot>';
  const { env } = runtimeDefaults({ selfPath: SELF, env: process.env });
  // The bridge server beside this file is the one Codex should be launching.
  const protection = () => ({ ...protectionStatus({ serverPath: join(dirname(SELF), 'server.mjs'), env }), hooks: hooksIntact(env, { serverPath: SELF }) });
  const state = () => currentState(repoRoot, env, {
    registered: isRegisteredRepo(repoRoot, env, { serverPath: SELF }),
    ownerPublicKeyPem: installedOwnerPublicKey({ serverPath: SELF, env }),
  });
  let output;
  if (command === 'protection' && repoRoot === undefined) output = protection();
  else if (command === 'current-state' && repoRoot && rest.length === 0) output = state();
  else if (command === 'context' && repoRoot && rest.length === 0) output = { state: state(), protection: protection() };
  else throw new Error(usage);
  process.stdout.write(`${JSON.stringify(output)}\n`);
  process.exitCode = 0;
} catch (error) {
  process.stdout.write(`${JSON.stringify({ error: error instanceof Error ? error.message : String(error) })}\n`);
  process.exitCode = 1;
}
