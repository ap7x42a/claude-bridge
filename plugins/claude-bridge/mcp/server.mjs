#!/usr/bin/node

import { spawn } from "node:child_process";
import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import readline from "node:readline";
import { setTimeout } from "node:timers";
import { fileURLToPath } from "node:url";

import * as isolation from "./isolation.mjs";
import { sha256Hex } from "./canonical.mjs";
import { effectiveRoots, hooksIntact, installedOwnerPublicKey, isRegisteredRepo, protectionStatus, runtimeDefaults } from "./protection.mjs";
import { extractConversation, historyMarkdown, ledgerSession, locateSession, sessionsRoot, writeEvidence } from "./session-evidence.mjs";
import { buildBridgeSystemPrompt } from "./system-prompt.mjs";
import { TURNS_LEDGER, VERDICT_SCHEMA, currentState, parseVerdict, readChain, readLedger, recordRunStarted, recordVerdict, repoKey, repoStateDir, vetoDecision } from "./verdict.mjs";

const {
  cleanupIsolationLayout,
  prepareBridgeIsolationLayout,
  resolveClaudeBin,
  wrapIsolatedCommand,
} = isolation;

const SERVER_NAME = "Claude Bridge";
const SERVER_VERSION = "0.5.0";
// Every run uses Fable 5.1 with Opus 5.5 as the only fallback.
// Codex cannot choose any other model.
const FABLE_MODEL = "claude-fable-5-1";
const OPUS_MODEL = "claude-opus-5-5";
const ALLOWED_MODELS = Object.freeze([FABLE_MODEL, OPUS_MODEL]);
const MODEL_ALIASES = new Map([["fable", FABLE_MODEL], ["opus", OPUS_MODEL]]);
const DEFAULT_MODEL = FABLE_MODEL;
const DEFAULT_EFFORT = "high";
const DEFAULT_PROMPT_BYTES = 200_000;
const DEFAULT_STDOUT_BYTES = 2 * 1024 * 1024;
const DEFAULT_STDERR_BYTES = 64 * 1024;
const DEFAULT_RESULT_BYTES = 60_000;
const EMPTY_MCP_CONFIG = JSON.stringify({ mcpServers: {} });
const EVIDENCE_MOUNT = "/tmp/claude/evidence";
const RECORD_FAILURE_FILE = "record-failure.json";
// Outcomes of a started run that carry no verdict; each records a blocked one.
const RUN_ERROR_CODES = new Set([
  "claude_error",
  "model_unavailable",
  "nonzero_exit",
  "stdout_limit",
  "cancelled",
  "malformed_json",
  "invalid_envelope",
  "spawn_failed",
]);
// The roots and keys come from this file's own location: the installed bridge ignores the env overrides.
const SERVER_PATH = fileURLToPath(import.meta.url);
const SESSION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
// The shape of a model id Claude reports in modelUsage. It only filters what is reported; it chooses nothing.
const PROVIDER_MODEL_PATTERN = /^claude-[a-z0-9]+(?:-[a-z0-9]+){0,7}$/;
const EFFORT_LEVELS = Object.freeze(["low", "medium", "high", "xhigh", "max"]);
// A lower effort is raised to the floor, not refused.
const EFFORT_FLOOR = "high";
const ALLOWED_EFFORTS = Object.freeze(EFFORT_LEVELS.slice(EFFORT_LEVELS.indexOf(EFFORT_FLOOR)));
const CLAUDE_RESULT_TYPES = new Set(["result"]);
const CLAUDE_RESULT_SUBTYPES = new Set([
  "success",
  "error_during_execution",
  "error_max_turns",
]);
const JsonRpcError = {
  PARSE_ERROR: -32700,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
};

export class BridgeFault extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "BridgeFault";
    this.code = code;
    this.details = details;
  }
}

function positiveNumberFromEnv(env, key, fallback, minimum = 1) {
  const parsed = Number(env[key]);
  return Number.isFinite(parsed) && parsed >= minimum ? parsed : fallback;
}

function outputLimits(env) {
  return {
    promptBytes: positiveNumberFromEnv(env, "CLAUDE_BRIDGE_MAX_PROMPT_BYTES", DEFAULT_PROMPT_BYTES, 1_024),
    stdoutBytes: positiveNumberFromEnv(
      env,
      "CLAUDE_BRIDGE_MAX_STDOUT_BYTES",
      positiveNumberFromEnv(env, "CLAUDE_BRIDGE_MAX_OUTPUT_BYTES", DEFAULT_STDOUT_BYTES, 1_024),
      1_024,
    ),
    stderrBytes: positiveNumberFromEnv(env, "CLAUDE_BRIDGE_MAX_STDERR_BYTES", DEFAULT_STDERR_BYTES, 1_024),
    resultBytes: positiveNumberFromEnv(env, "CLAUDE_BRIDGE_MAX_RESULT_BYTES", DEFAULT_RESULT_BYTES, 1_024),
  };
}

function requireObject(value, name = "arguments") {
  if (value === undefined) return {};
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BridgeFault("invalid_arguments", `${name} must be an object.`);
  }
  return value;
}

function requireString(value, name) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new BridgeFault("invalid_arguments", `${name} must be a non-empty string.`);
  }
  return value;
}

function requireBoolean(value, name, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new BridgeFault("invalid_arguments", `${name} must be a boolean.`);
  }
  return value;
}

function isInsideRoot(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === ""
    || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function configuredAllowedRoots(env) {
  return String(env.CLAUDE_BRIDGE_ALLOWED_ROOTS ?? "")
    .split(path.delimiter)
    .map((root) => root.trim())
    .filter(Boolean)
    .map((root) => {
      try {
        return realpathSync(root);
      } catch (error) {
        throw new BridgeFault(
          "invalid_configuration",
          `CLAUDE_BRIDGE_ALLOWED_ROOTS contains an invalid path: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    });
}

export function resolveWorkingDirectory(value, env = process.env) {
  const requested = requireString(value, "cwd").trim();
  if (!path.isAbsolute(requested)) {
    throw new BridgeFault("invalid_arguments", "cwd must be an absolute path.");
  }

  let canonical;
  try {
    canonical = realpathSync(requested);
  } catch (error) {
    throw new BridgeFault(
      "invalid_arguments",
      `cwd does not resolve to an existing directory: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!statSync(canonical).isDirectory()) {
    throw new BridgeFault("invalid_arguments", "cwd must resolve to a directory.");
  }
  const allowedRoots = configuredAllowedRoots(env);
  if (allowedRoots.length > 0 && !allowedRoots.some((root) => isInsideRoot(canonical, root))) {
    throw new BridgeFault("invalid_arguments", "cwd resolves outside CLAUDE_BRIDGE_ALLOWED_ROOTS.");
  }
  return canonical;
}

function assertRepositoryScopeAllowed(repositoryRoot, env) {
  const allowedRoots = configuredAllowedRoots(env);
  if (allowedRoots.length > 0 && !allowedRoots.some((root) => isInsideRoot(repositoryRoot, root))) {
    throw new BridgeFault(
      "invalid_arguments",
      "The enclosing Git repository resolves outside CLAUDE_BRIDGE_ALLOWED_ROOTS.",
    );
  }
}

function findRepositoryRoot(cwd) {
  let current = cwd;
  while (true) {
    if (existsSync(path.join(current, ".git"))) return current;
    const parent = path.dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

export function assertInvocationAllowed({ env = process.env }) {
  const depthRaw = String(env.CLAUDE_BRIDGE_DEPTH ?? "0").trim();
  const depth = Number(depthRaw);
  if (!Number.isSafeInteger(depth) || depth < 0 || depth >= 1) {
    throw new BridgeFault(
      "recursion_forbidden",
      "Nested Claude Bridge delegation is refused (CLAUDE_BRIDGE_DEPTH must be 0).",
    );
  }

  return depth;
}

// Only the two allowed models, by id or alias; anything else is refused.
function allowedModel(value) {
  const normalized = requireString(value, "model").trim().toLowerCase();
  const model = MODEL_ALIASES.get(normalized) ?? normalized;
  if (!ALLOWED_MODELS.includes(model)) {
    throw new BridgeFault(
      "model_not_allowed",
      `Claude Bridge runs only ${FABLE_MODEL} (alias fable, the default) or ${OPUS_MODEL} (alias opus, the only fallback). Codex cannot choose another model.`,
    );
  }
  return model;
}

// The effort used, raised to the floor, and the effort asked for.
function flooredEffort(value) {
  const requested = requireString(value, "effort").trim().toLowerCase();
  if (!EFFORT_LEVELS.includes(requested)) {
    throw new BridgeFault(
      "invalid_arguments",
      "effort must be one of high, xhigh or max; low and medium run as high.",
    );
  }
  const effort = EFFORT_LEVELS.indexOf(requested) < EFFORT_LEVELS.indexOf(EFFORT_FLOOR) ? EFFORT_FLOOR : requested;
  return { effort, effortRequested: requested };
}

export function resolveModelAndEffort(args) {
  const model = args.model === undefined ? DEFAULT_MODEL : allowedModel(args.model);
  return { model, ...flooredEffort(args.effort === undefined ? DEFAULT_EFFORT : args.effort) };
}

// A continuation keeps the session's model and effort. A session recorded with a model outside the set is refused.
export function continuationSettings(session) {
  return { model: allowedModel(session.model), ...flooredEffort(session.effort) };
}

// Fable 5.1 falls back to Opus 5.5 only; Opus 5.5 has no fallback.
export function resolveModelFallbacks(model) {
  return allowedModel(model) === FABLE_MODEL ? [OPUS_MODEL] : [];
}

function effortPayload(effort, effortRequested) {
  return { effort, ...(effortRequested !== undefined && effortRequested !== effort ? { effort_requested: effortRequested } : {}) };
}

const MODEL_FAMILIES = new Map([[FABLE_MODEL, "fable"], [OPUS_MODEL, "opus"]]);

export function isModelAvailabilityFailureMessage(value, model) {
  if (typeof value !== "string") return false;
  const message = value.trim();
  if (message.length === 0 || message.length > 4_096) {
    return false;
  }

  const family = MODEL_FAMILIES.get(model);
  const familyMentioned = family !== undefined
    && new RegExp(`\\b${family}\\b`, "i").test(message);
  if (familyMentioned && /\b(?:not available|unavailable|disabled|overloaded|at capacity|usage|limit|quota)\b/i.test(message)) {
    return true;
  }
  if (family === "fable" && /\b(?:requires? usage|out of usage|seat type .{0,80} usage|usage allocation)\b/i.test(message)) {
    return true;
  }
  return [
    /\b(?:model|service)\s+(?:is\s+)?(?:overloaded|unavailable|not available|at capacity)\b/i,
    // Documented Anthropic capacity wording: "Due to unexpected capacity constraints,
    // Claude is unable to respond to your message."
    /\bcapacity constraints\b/i,
    /\b(?:overloaded_error|api overloaded|repeated 529 overloaded errors)\b/i,
    /\byou(?:'ve| have)\s+(?:hit|reached)\s+your\b.{0,160}\b(?:limit|usage)\b/i,
    /\busage limit (?:reached|exceeded)\b/i,
    /\breached your specified.{0,80}usage limits\b/i,
    /\bout(?:\s+|_)of(?:\s+|_)usage\b/i,
  ].some((pattern) => pattern.test(message));
}

function validatePrompt(value, env) {
  const prompt = requireString(value, "prompt");
  const bytes = Buffer.byteLength(prompt, "utf8");
  const maximum = outputLimits(env).promptBytes;
  if (bytes > maximum) {
    throw new BridgeFault("invalid_arguments", `prompt exceeds the ${maximum}-byte bridge limit.`);
  }
  return prompt;
}

export function buildClaudeArgs({
  profile,
  model,
  effort,
  fallbackModels = resolveModelFallbacks(model),
  resumable = false,
  resumeSessionId,
  systemPrompt,
  mcpConfig = EMPTY_MCP_CONFIG,
}) {
  const review = profile === "review";
  const args = ["--print", "--model", model];
  if (fallbackModels.length > 0) args.push("--fallback-model", fallbackModels.join(","));
  args.push(
    "--effort", effort,
    // No setting sources: host settings, plugins and hooks stay out; the MCP config below still loads.
    "--setting-sources", "",
    "--strict-mcp-config", "--mcp-config", mcpConfig,
    "--disable-slash-commands",
    "--no-chrome",
    // Both profiles bypass Claude's own permission prompts: under --print nobody can answer one, and in
    // acceptEdits a task could not read the mounted evidence, run the shell, write
    // outside the repository. The bubblewrap sandbox is the
    // boundary, as the owner-approved design states for Claude without distinguishing profiles.
    "--permission-mode", "bypassPermissions",
    "--dangerously-skip-permissions",
  );
  args.push(
    "--tools", "default",
    "--disallowedTools", "Agent,Task",
    "--json-schema", JSON.stringify(VERDICT_SCHEMA),
  );
  if (typeof systemPrompt === "string" && systemPrompt.length > 0) args.push("--append-system-prompt", systemPrompt);
  args.push("--output-format", "json");
  if (resumeSessionId !== undefined) args.push("--resume", resumeSessionId);
  else if (!resumable) args.push("--no-session-persistence");
  return args;
}

function appendTail(current, chunk, maximumBytes) {
  const combined = Buffer.concat([current, Buffer.from(chunk)]);
  return combined.length <= maximumBytes
    ? combined
    : combined.subarray(combined.length - maximumBytes);
}

function redactDiagnostic(value) {
  return value
    .replace(/sk-ant-[A-Za-z0-9_-]+/g, "[REDACTED_ANTHROPIC_KEY]")
    .replace(/(ANTHROPIC_(?:API_KEY|AUTH_TOKEN)\s*[=:]\s*)\S+/gi, "$1[REDACTED]")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, "$1[REDACTED]");
}

function signalProcessGroup(child, signal) {
  if (!Number.isSafeInteger(child.pid) || child.pid <= 0) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

export function runBoundedProcess({
  bin,
  argv,
  cwd,
  env,
  stdin = "",
  stdoutLimit,
  stderrLimit,
  signal,
  onChild,
}) {
  return new Promise((resolve) => {
    let child;
    let settled = false;
    let failureCode;
    let stdoutBytes = 0;
    const stdoutChunks = [];
    let stderrBytes = 0;
    let stderrTail = Buffer.alloc(0);
    const finish = (result) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abortListener);
      resolve({
        ...result,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: redactDiagnostic(stderrTail.toString("utf8")),
        stdoutBytes,
        stderrBytes,
      });
    };

    const terminate = (code) => {
      if (failureCode !== undefined) return;
      failureCode = code;
      try {
        signalProcessGroup(child, "SIGTERM");
      } catch {
        // The close/error path below still settles the call.
      }
      setTimeout(() => {
        try {
          signalProcessGroup(child, "SIGKILL");
        } catch {
          // A vanished process group is already terminated.
        }
      }, 500);
    };

    const abortListener = () => terminate("cancelled");
    try {
      child = spawn(bin, argv, {
        cwd,
        env,
        shell: false,
        detached: process.platform !== "win32",
        stdio: ["pipe", "pipe", "pipe"],
      });
      onChild?.(child);
    } catch (error) {
      finish({ kind: "spawn_failed", error });
      return;
    }

    child.on("error", (error) => finish({ kind: "spawn_failed", error }));
    child.stdout.on("data", (chunk) => {
      const bytes = Buffer.from(chunk);
      if (stdoutBytes + bytes.length > stdoutLimit) {
        const available = Math.max(0, stdoutLimit - stdoutBytes);
        if (available > 0) stdoutChunks.push(bytes.subarray(0, available));
        stdoutBytes += bytes.length;
        terminate("stdout_limit");
        return;
      }
      stdoutBytes += bytes.length;
      stdoutChunks.push(bytes);
    });
    child.stderr.on("data", (chunk) => {
      const bytes = Buffer.from(chunk);
      stderrBytes += bytes.length;
      stderrTail = appendTail(stderrTail, bytes, stderrLimit);
    });
    child.on("close", (exitCode, exitSignal) => {
      if (failureCode !== undefined) {
        finish({ kind: failureCode, exitCode, exitSignal });
      } else {
        finish({ kind: "closed", exitCode, exitSignal });
      }
    });
    child.stdin.on("error", () => {
      // Spawn/close handlers own the structured failure result.
    });

    signal?.addEventListener("abort", abortListener, { once: true });
    if (signal?.aborted) abortListener();
    child.stdin.end(stdin);
  });
}

export function truncateUtf8(value, maximumBytes = DEFAULT_RESULT_BYTES) {
  const source = Buffer.from(value, "utf8");
  if (source.length <= maximumBytes) {
    return { text: value, truncated_bytes: 0 };
  }
  let prefix = source.subarray(0, maximumBytes).toString("utf8");
  while (prefix.endsWith("\uFFFD")) prefix = prefix.slice(0, -1);
  const used = Buffer.byteLength(prefix, "utf8");
  const omitted = source.length - used;
  return {
    text: `${prefix}\n[truncated ${omitted} UTF-8 bytes]`,
    truncated_bytes: omitted,
  };
}

export function parseClaudeEnvelope(stdout) {
  let envelope;
  try {
    envelope = JSON.parse(stdout.trim());
  } catch {
    throw new BridgeFault("malformed_json", "Claude returned malformed JSON.");
  }
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    throw new BridgeFault("invalid_envelope", "Claude JSON output must be an object.");
  }
  if (envelope.type !== undefined && envelope.type !== "result") {
    throw new BridgeFault("invalid_envelope", "Unexpected Claude envelope type.");
  }
  if (typeof envelope.result !== "string") {
    throw new BridgeFault("invalid_envelope", "Claude envelope is missing a string result.");
  }
  if (envelope.session_id !== undefined && !SESSION_ID_PATTERN.test(envelope.session_id)) {
    throw new BridgeFault("invalid_envelope", "Claude envelope contains an invalid session_id.");
  }
  const providerModels = envelope.modelUsage !== null
    && typeof envelope.modelUsage === "object"
    && !Array.isArray(envelope.modelUsage)
    ? Object.keys(envelope.modelUsage)
      .map((model) => model.trim().toLowerCase())
      .filter((model) => model.length <= 64 && PROVIDER_MODEL_PATTERN.test(model))
      .slice(0, 8)
    : [];
  return {
    result_text: envelope.result,
    session_id: envelope.session_id,
    num_turns: Number.isFinite(envelope.num_turns) ? envelope.num_turns : undefined,
    duration_ms: Number.isFinite(envelope.duration_ms) ? envelope.duration_ms : undefined,
    is_error: envelope.is_error === true
      || (typeof envelope.subtype === "string" && envelope.subtype.startsWith("error")),
    subtype: typeof envelope.subtype === "string" ? envelope.subtype : undefined,
    provider_models: providerModels.length > 0 ? providerModels : undefined,
    structured_output: envelope.structured_output !== null
      && typeof envelope.structured_output === "object"
      && !Array.isArray(envelope.structured_output)
      ? envelope.structured_output
      : undefined,
  };
}

function isModelAvailabilityFailureRun(run, model) {
  const stdout = String(run.stdout ?? "").trim();
  if (stdout.length > 0) {
    try {
      const envelope = JSON.parse(stdout);
      if (envelope !== null
        && typeof envelope === "object"
        && !Array.isArray(envelope)
        && envelope.is_error === true
        && isModelAvailabilityFailureMessage(envelope.result, model)) {
        return true;
      }
    } catch {
      return false;
    }
    return false;
  }
  return isModelAvailabilityFailureMessage(String(run.stderr ?? ""), model);
}

function whitelistedFailureIdentifier(value, allowedValues) {
  if (typeof value !== "string") return "missing";
  return allowedValues.has(value) ? value : "unrecognized";
}

function boundedTelemetryNumber(value, maximum, integer = false) {
  if (!Number.isFinite(value) || value < 0 || value > maximum) return undefined;
  if (integer && !Number.isSafeInteger(value)) return undefined;
  return value;
}

function claudeFailureStdoutMetadata(stdout) {
  if (stdout.trim().length === 0) return { format: "empty" };

  let envelope;
  try {
    envelope = JSON.parse(stdout);
  } catch {
    return { format: "malformed_json" };
  }
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    return { format: "json_non_object" };
  }

  const metadata = {
    format: envelope.type === "result" ? "claude_result" : "json_object",
    type: whitelistedFailureIdentifier(envelope.type, CLAUDE_RESULT_TYPES),
    subtype: whitelistedFailureIdentifier(envelope.subtype, CLAUDE_RESULT_SUBTYPES),
    is_error: envelope.is_error === true,
  };
  const telemetry = {};
  for (const [key, maximum, integer] of [
    ["num_turns", 1_000_000, true],
    ["duration_ms", 31_536_000_000, true],
  ]) {
    const value = boundedTelemetryNumber(envelope[key], maximum, integer);
    if (value !== undefined) telemetry[key] = value;
  }
  if (Object.keys(telemetry).length > 0) metadata.telemetry = telemetry;
  return metadata;
}

function delegateStreamMetadata(run) {
  const stdoutBytes = Number.isSafeInteger(run.stdoutBytes)
    ? run.stdoutBytes
    : Buffer.byteLength(run.stdout ?? "", "utf8");
  const stderrBytes = Number.isSafeInteger(run.stderrBytes)
    ? run.stderrBytes
    : Buffer.byteLength(run.stderr ?? "", "utf8");
  return {
    stdout_bytes: stdoutBytes,
    stdout_present: stdoutBytes > 0,
    stderr_bytes: stderrBytes,
    stderr_present: stderrBytes > 0,
  };
}

function modelSelectionPayload({
  requestedModel,
  attemptModel,
  selectedModel,
  fallbackModels,
  modelAttempts,
}) {
  return {
    owner: "claude_bridge",
    strategy: "ordered_subscription_models",
    requested_model: requestedModel,
    completed_attempt_model: attemptModel,
    selected_model: selectedModel,
    fallback_models: fallbackModels,
    attempts: modelAttempts,
    provider_native_fallback: fallbackModels.length > 0,
  };
}

function successPayload(envelope, {
  model,
  requestedModel,
  attemptModel,
  fallbackModels,
  modelAttempts,
  effort,
  effortRequested,
  resultBytes,
  sessionHandle,
}) {
  const result = truncateUtf8(envelope.result_text, resultBytes);
  return {
    ok: !envelope.is_error,
    is_error: envelope.is_error,
    result_text: result.text,
    truncated_bytes: result.truncated_bytes,
    session_handle: sessionHandle,
    model,
    model_selection: modelSelectionPayload({
      requestedModel,
      attemptModel,
      selectedModel: model,
      fallbackModels,
      modelAttempts,
    }),
    provider_models: envelope.provider_models,
    ...effortPayload(effort, effortRequested),
    num_turns: envelope.num_turns,
    duration_ms: envelope.duration_ms,
    subtype: envelope.subtype,
  };
}

function failurePayload(code, message, details = {}) {
  return {
    ok: false,
    is_error: true,
    error_code: code,
    error_message: message,
    ...details,
  };
}

function toolResult(payload, isError = false) {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
    ...(isError ? { isError: true } : {}),
  };
}

export function createBridgeState(env = process.env) {
  return {
    env,
    sessions: new Map(),
    jobs: new Map(),
    activeJobHandle: undefined,
    activeChild: undefined,
    activeStatusController: undefined,
    recordFailures: new Map(),
  };
}

/** The environment the bridge reads: run from /opt/claude-bridge, the overrides and test knobs are replaced (runtimeDefaults). */
export function bridgeEnvironmentFromArgs(env = process.env) {
  return runtimeDefaults({ selfPath: SERVER_PATH, env }).env;
}

const runtime = (env) => runtimeDefaults({ selfPath: SERVER_PATH, env });

function claudeBin(env) {
  const resolved = resolveClaudeBin(env, { bridge: true, serverPath: SERVER_PATH });
  if (!resolved.resolved) {
    throw new BridgeFault("spawn_failed", "Claude Code could not be resolved to an absolute executable path.");
  }
  return resolved.bin;
}

function bridgeProtection(env) {
  return protectionStatus({ serverPath: SERVER_PATH, env });
}

/**
 * A protected server, and any server under /opt/claude-bridge, refuses jobs unless its hooks are intact. The
 * second clause keeps a reason that is not about the server file (a missing owner public key) from switching
 * the check off.
 */
export function hooksCheckApplies({ protection, serverPath, env }) {
  return protection.status === "protected"
    || effectiveRoots({ serverPath, env }).protected
    || (env.CLAUDE_BRIDGE_TEST_MODE === "1" && env.CLAUDE_BRIDGE_TEST_FORCE_PROTECTED === "1");
}

const bridgeHooks = (env) => hooksIntact(env, { serverPath: SERVER_PATH });
const registeredRepo = (repoRoot, env) => isRegisteredRepo(repoRoot, env, { serverPath: SERVER_PATH });

/** The verdict state, with owner clears verified against the installed public key. */
function bridgeVerdictState(repoRoot, env) {
  return currentState(repoRoot, env, {
    registered: registeredRepo(repoRoot, env),
    ownerPublicKeyPem: installedOwnerPublicKey({ serverPath: SERVER_PATH, env }),
  });
}

const errorText = (error) => (error instanceof Error ? error.message : String(error));

export const LEDGER_NOTES = Object.freeze({
  empty: "The Codex hook recorded no turns for this repository (it may be disabled or not trusted), so every message below is unverified.",
  broken: "The hook's turns ledger failed its integrity check, so every message below is unverified.",
  no_owner_prompts: "The Codex hook recorded no owner prompts for this repository (its UserPromptSubmit hook may be disabled or not trusted), so every owner message below is unverified.",
});

/**
 * The hook's turns ledger for the repository: its records when it is intact, else none, and a summary. `status` is
 * `ok`, `empty` (no ledger or no records) or `broken` (the hashes or the head do not hold).
 */
function turnsLedger(repositoryRoot, env) {
  const ledger = readLedger(repoStateDir(repositoryRoot, env), TURNS_LEDGER);
  const status = ledger.records.length === 0 ? "empty" : ledger.consistent ? "ok" : "broken";
  const records = status === "ok" ? ledger.records : [];
  const summary = {
    status, records: ledger.records.length,
    owner_prompts: records.filter((record) => record?.type === "owner_prompt").length,
  };
  const note = status !== "ok" ? LEDGER_NOTES[status] : summary.owner_prompts === 0 ? LEDGER_NOTES.no_owner_prompts : null;
  return { records, summary, note };
}

// Evidence errors from the locator and the extractor never block the job: conversation.md, the
// manifest and the log say the session log could not be read. Other failures surface as errors.
async function prepareEvidence({ repositoryRoot, env, prompt, profile, scratchDir }) {
  let session;
  let error;
  let readError = false;
  const ledger = turnsLedger(repositoryRoot, env);
  // The session the hook recorded for this call wins over the locator, which reads owner-writable logs only.
  session = ledgerSession(ledger.records);
  if (session === null) {
    try {
      session = await locateSession({ sessionsRoot: sessionsRoot(env), repoRoot: repositoryRoot, prompt });
    } catch (caught) {
      error = errorText(caught);
      session = { match: "none", path: null, id: null, candidates: 0 };
    }
  }
  let conversation = { markdown: "_No Codex session log was located for this repository._\n", messages: 0, truncated: false };
  if (error === undefined && session.path) {
    try {
      conversation = extractConversation(session.path, { ledger: ledger.records });
    } catch (caught) {
      error = errorText(caught);
      readError = true;
    }
  }
  if (error !== undefined) {
    conversation = { markdown: `_The session log could not be read: ${error}_\n`, messages: 0, truncated: false };
  }
  conversation.ledger_note = ledger.note;
  const history = historyMarkdown(readChain(repoStateDir(repositoryRoot, env)).records);
  const evidenceDir = path.join(scratchDir, "evidence");
  const manifest = writeEvidence({ evidenceDir, conversation, brief: prompt, history, session, profile });
  manifest.ledger = ledger.summary;
  if (error !== undefined) manifest.evidence_error = error;
  writeFileSync(path.join(evidenceDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { session, readError, conversation, manifest, error, ledger: ledger.summary };
}

const recordFailurePath = (repoRoot, env) => path.join(repoStateDir(repoRoot, env), RECORD_FAILURE_FILE);

function readRecordFailure(markerPath) {
  try {
    const value = JSON.parse(readFileSync(markerPath, "utf8"));
    if (value !== null && typeof value === "object" && !Array.isArray(value)) return value;
  } catch {
    // An unreadable marker still refuses tasks.
  }
  return { unreadable: true };
}

/** The blocked verdict a started run records when it ends with `code` instead of a verdict. */
function runErrorVerdict(code) {
  const verdict = parseVerdict({ result_text: "" }).verdict;
  return {
    ...verdict,
    operator_readback: `Claude Bridge: the review run ended with ${code} and returned no verdict. Work is blocked until a review completes.`,
    evidence_coverage: { ...verdict.evidence_coverage, notes: `run ended without a verdict: ${code}` },
  };
}

const stateLockTimeoutMs = (env) => (runtime(env).testMode
  ? positiveNumberFromEnv(env, "CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS", undefined)
  : undefined);

/** The record-failure latch and marker: task and continuation calls are refused until a verdict is recorded. */
function latchRecordFailure(repositoryRoot, state, { job_id, message }) {
  const failure = { job_id, recorded_at: new Date().toISOString(), message };
  state.recordFailures.set(repoKey(repositoryRoot), failure);
  try {
    writeFileSync(recordFailurePath(repositoryRoot, state.env), `${JSON.stringify(failure)}\n`, { mode: 0o600 });
  } catch {
    // The latch still refuses tasks in this process.
  }
}

// A verdict that cannot be recorded is replaced by the unparseable (blocked) verdict. When that
// cannot be recorded either, a marker file and an in-process latch refuse tasks until a later job
// records a verdict; any recorded verdict lifts both.
const UNPROTECTED_READBACK = " (This bridge ran unprotected.)";

function recordBindingVerdict(repositoryRoot, state, parsed, metadata, { unprotected = false } = {}) {
  const env = state.env;
  // The operator hears, in the readback itself, that the bridge that recorded it was not the protected install.
  const mark = (verdict) => (unprotected ? { ...verdict, operator_readback: `${verdict.operator_readback}${UNPROTECTED_READBACK}` } : verdict);
  const key = repoKey(repositoryRoot);
  const markerPath = recordFailurePath(repositoryRoot, env);
  const lockTimeoutMs = stateLockTimeoutMs(env);
  const record = (verdict) => {
    const recorded = recordVerdict(repositoryRoot, env, { ...metadata, verdict, lockTimeoutMs });
    try {
      rmSync(markerPath, { force: true });
    } catch {
      // A marker that cannot be removed keeps tasks refused until the owner removes it.
    }
    state.recordFailures.delete(key);
    return recorded;
  };
  let recordError;
  const verdict = mark(parsed.verdict);
  try {
    return { record: record(verdict), verdict, parse: parsed.parse };
  } catch (error) {
    recordError = errorText(error);
  }
  const fallback = mark(parseVerdict({ result_text: "" }).verdict);
  try {
    return { record: record(fallback), verdict: fallback, parse: "record_failed", recordError };
  } catch (second) {
    const fallbackRecordError = errorText(second);
    latchRecordFailure(repositoryRoot, state, { job_id: metadata.job_id, message: `${recordError}; fallback: ${fallbackRecordError}` });
    return { recordError, fallbackRecordError };
  }
}

/** The in-process latch, else the marker file, else undefined. */
function pendingRecordFailure(repoRoot, state) {
  const markerPath = recordFailurePath(repoRoot, state.env);
  return state.recordFailures.get(repoKey(repoRoot))
    ?? (existsSync(markerPath) ? readRecordFailure(markerPath) : undefined);
}

function recordFailureStatus(repoRoot, state) {
  const pending = pendingRecordFailure(repoRoot, state);
  const text = (value) => (typeof value === "string" ? value : null);
  return pending === undefined
    ? { present: false, recorded_at: null, message: null }
    : { present: true, recorded_at: text(pending.recorded_at), message: text(pending.message) };
}

/** The outermost registered repository holding `cwd`, else undefined. */
function outermostRegisteredRepository(cwd, env) {
  let outer;
  for (let current = cwd; ; current = path.dirname(current)) {
    if (existsSync(path.join(current, ".git")) && registeredRepo(current, env)) outer = current;
    if (path.dirname(current) === current) return outer;
  }
}

/** Nested repositories are resolved against registrations where the hooks are checked: when protected. */
const nestedRepositoryCheckApplies = (env) => hooksCheckApplies({ protection: bridgeProtection(env), serverPath: SERVER_PATH, env });

/**
 * The repository a bridge call is keyed to: `{ root }`, or `{ refusal }`. Protected, a `.git` nested inside a
 * registered repository does not get its own, clean state: a task call takes the enclosing repository's refusal
 * (verdict_open, tampered or latched), and any call is refused with nested_repository unless the enclosing
 * repository is clean and the nested root is registered itself, in which case it is keyed to the nested root.
 */
function bridgeRepository(cwd, state, toolName) {
  const env = state.env;
  const nearest = findRepositoryRoot(cwd);
  if (nearest === undefined || !nestedRepositoryCheckApplies(env)) return { root: nearest };
  const outer = outermostRegisteredRepository(cwd, env);
  if (outer === undefined || outer === nearest) return { root: nearest };
  if (toolName === "claude_task" || toolName === "claude_continue") {
    const refusal = taskRefusal(outer, state, toolName);
    if (refusal !== undefined) return { refusal };
  }
  const outerClean = pendingRecordFailure(outer, state) === undefined && bridgeVerdictState(outer, env).status === "clear";
  if (outerClean && registeredRepo(nearest, env)) return { root: nearest };
  return {
    refusal: toolResult(failurePayload(
      "nested_repository",
      `Claude Bridge refuses ${toolName}: ${cwd} is in the Git repository ${nearest}, nested inside the registered repository ${outer}. Call the bridge from ${outer}${outerClean ? `, or have the owner register ${nearest}` : " once its verdict state is clear"}.`,
      { repository: nearest, enclosing_repository: outer },
    ), true),
  };
}

/** The repository whose state claude_verdict reports: protected, the outermost registered one holding `cwd`. */
function verdictRepository(cwd, env) {
  const nearest = findRepositoryRoot(cwd);
  if (nearest === undefined || !nestedRepositoryCheckApplies(env)) return nearest;
  const outer = outermostRegisteredRepository(cwd, env);
  return outer === undefined || registeredRepo(nearest, env) ? nearest : outer;
}

// Task and continuation calls are refused while an earlier verdict could not be recorded or a
// verdict is open. Checked at launch and again just before the provider starts.
function taskRefusal(repoRoot, state, toolName) {
  const pending = pendingRecordFailure(repoRoot, state);
  if (pending !== undefined) {
    return toolResult(failurePayload(
      "verdict_record_failed_pending",
      `Claude Bridge refuses ${toolName}: the verdict of an earlier job could not be recorded. Rerun claude_review; a recorded verdict lifts this refusal.`,
      { record_failure: pending },
    ), true);
  }
  const decision = vetoDecision(bridgeVerdictState(repoRoot, state.env), toolName);
  if (decision.allowed) return undefined;
  return toolResult(failurePayload(decision.error_code, decision.error_message, { open: decision.open ?? null }), true);
}

async function executeDelegate({ profile, args, state, signal, resume }) {
  if (state.activeChild !== undefined) {
    throw new BridgeFault("busy", "Claude Bridge already has an active delegate turn.");
  }
  const env = state.env;
  const prompt = validatePrompt(args.prompt, env);
  let session;
  let cwd;
  let model;
  let requestedModel;
  let effort;
  let effortRequested;
  let resumable = false;

  if (resume) {
    const handle = requireString(args.session_handle, "session_handle").trim();
    session = state.sessions.get(handle);
    if (session === undefined) {
      throw new BridgeFault(
        "unknown_session_handle",
        "The resume handle is unknown or expired; handles are valid only in the MCP process that created them.",
      );
    }
    if (session.in_use) {
      throw new BridgeFault("busy", "This Claude session is already being continued.");
    }
    ({ cwd } = session);
    ({ model, effort, effortRequested } = continuationSettings(session));
    requestedModel = model;
    profile = session.profile;
    session.in_use = true;
  } else {
    cwd = resolveWorkingDirectory(args.cwd, env);
    ({ model, effort, effortRequested } = resolveModelAndEffort(args));
    requestedModel = model;
    resumable = profile === "task" && requireBoolean(args.resumable, "resumable", false);
  }
  const fallbackModels = resolveModelFallbacks(requestedModel);
  const modelCandidates = [requestedModel, ...fallbackModels];
  const modelAttempts = [];

  const isolationSessionKey = session?.isolation_session_key ?? randomBytes(24).toString("base64url");
  const jobId = randomBytes(6).toString("hex");
  let isolationLayout;
  let preserveIsolationAuthority = resume;
  try {
    const depth = assertInvocationAllowed({ env, cwd });
    const limits = outputLimits(env);
    const toolName = resume ? "claude_continue" : profile === "review" ? "claude_review" : "claude_task";
    const resolved = bridgeRepository(cwd, state, toolName);
    if (resolved.refusal !== undefined) return resolved.refusal;
    const repositoryRoot = resolved.root;
    if (repositoryRoot === undefined) {
      throw new BridgeFault(
        "invalid_arguments",
        "cwd must be inside a Git repository; Claude Bridge refuses broader filesystem scopes.",
      );
    }
    assertRepositoryScopeAllowed(repositoryRoot, env);
    const protection = bridgeProtection(env);
    if (hooksCheckApplies({ protection, serverPath: SERVER_PATH, env })) {
      const hooks = bridgeHooks(env);
      if (!hooks.intact) {
        return toolResult(failurePayload(
          "hooks_not_intact",
          "Claude Bridge refuses to serve: its Codex hooks are missing or disabled. The owner must reinstall or re-trust them.",
          { reasons: hooks.reasons, protection: protection.status },
        ), true);
      }
    }
    isolationLayout = prepareBridgeIsolationLayout({
      repoRoot: repositoryRoot,
      sessionKey: isolationSessionKey,
      persistentProviderSession: resume || resumable,
      env,
    });
    const evidence = await prepareEvidence({
      repositoryRoot, env, prompt, profile, scratchDir: isolationLayout.scratchDir,
    });
    // The locate wait is the job's last await before the spawn: honour a verdict another bridge
    // process recorded meanwhile.
    if (profile === "task") {
      const refusal = taskRefusal(repositoryRoot, state, resume ? "claude_continue" : "claude_task");
      if (refusal !== undefined) return refusal;
    }
    const systemPrompt = buildBridgeSystemPrompt({
      profile,
      session: evidence.readError ? { ...evidence.session, read_error: true } : evidence.session,
      protection,
      evidenceMount: EVIDENCE_MOUNT,
      ledger: evidence.ledger,
    });
    const mcpConfig = EMPTY_MCP_CONFIG;
    let run;
    let envelope;
    let completedAttemptModel;
    let selectedModel;
    let sessionHandle;
    const jobMetadata = (recordedModel) => ({
      job_id: jobId,
      profile,
      session: {
        match: String(evidence.session.match),
        path: typeof evidence.session.path === "string" ? evidence.session.path : null,
      },
      prompt_sha256: sha256Hex(prompt),
      model: String(recordedModel),
      registered: registeredRepo(repositoryRoot, env),
    });
    // One log file per recorded verdict, for the operator.
    const writeJobLog = (record, fields) => {
      const logDir = path.join(repoStateDir(repositoryRoot, env), "log");
      mkdirSync(logDir, { recursive: true, mode: 0o700 });
      const logPath = path.join(logDir, `${new Date().toISOString().replace(/[:.]/g, "-")}-${record.id}.json`);
      writeFileSync(logPath, `${JSON.stringify({
        recorded_at: record.recorded_at,
        job_id: record.job_id,
        profile,
        model: fields.model,
        ...effortPayload(effort, effortRequested),
        cwd,
        repository_root: repositoryRoot,
        session: evidence.session,
        evidence: evidence.manifest,
        ...(evidence.error !== undefined ? { evidence_error: evidence.error } : {}),
        protection,
        prompt,
        system_prompt: systemPrompt,
        ...fields,
        verdict_id: record.id,
      }, null, 2)}\n`, { mode: 0o600 });
      return logPath;
    };
    const unprotected = protection.status !== "protected";
    // A started run that ends without a verdict records a blocked one, then returns its error.
    const runError = async (payload) => {
      const verdict = runErrorVerdict(payload.error_code);
      const bound = recordBindingVerdict(repositoryRoot, state, { verdict, parse: "run_error" }, jobMetadata(model), { unprotected });
      if (bound.record === undefined) {
        return toolResult({ ...payload, record_error: bound.recordError, fallback_record_error: bound.fallbackRecordError }, true);
      }
      const recordError = bound.recordError !== undefined ? { record_error: bound.recordError } : {};
      const logPath = writeJobLog(bound.record, {
        model,
        error_code: payload.error_code,
        error_message: payload.error_message,
        verdict: bound.verdict,
        verdict_parse: bound.parse,
        ...recordError,
      });
      return toolResult({
        ...payload,
        verdict: bound.verdict,
        verdict_id: bound.record.id,
        verdict_parse: bound.parse,
        ...recordError,
        log_path: logPath,
      }, true);
    };
    // Recorded before the provider starts: a bridge killed mid-run leaves it behind, and the chain reads it as a
    // blocked verdict. When it cannot be recorded, the record-failure latch refuses tasks until a verdict is.
    try {
      recordRunStarted(repositoryRoot, env, {
        job_id: jobId, profile, model: String(requestedModel),
        registered: registeredRepo(repositoryRoot, env), lockTimeoutMs: stateLockTimeoutMs(env),
      });
    } catch (error) {
      latchRecordFailure(repositoryRoot, state, { job_id: jobId, message: `run start not recorded: ${errorText(error)}` });
    }
    try {
      for (const [attemptIndex, attemptModel] of modelCandidates.entries()) {
        model = attemptModel;
        const argv = buildClaudeArgs({
          profile,
          model: attemptModel,
          effort,
          fallbackModels: modelCandidates.slice(attemptIndex + 1),
          resumable,
          resumeSessionId: session?.provider_session_id,
          systemPrompt,
          mcpConfig,
        });
        const isolatedCommand = wrapIsolatedCommand({
          repoRoot: repositoryRoot,
          isolationLayout,
          repositoryAccess: "read-write",
          environmentMode: "subscription-only",
          bridgeDepth: depth,
          bwrapBin: runtime(env).bwrapBin,
          command: {
            provider: "claude",
            bin: claudeBin(env),
            argv,
            stdin: prompt,
            env,
          },
        });
        run = await runBoundedProcess({
          bin: isolatedCommand.bin,
          argv: isolatedCommand.argv,
          cwd,
          env: isolatedCommand.env,
          stdin: prompt,
          stdoutLimit: limits.stdoutBytes,
          stderrLimit: limits.stderrBytes,
          signal,
          onChild: (child) => {
            state.activeChild = child;
          },
        });
        state.activeChild = undefined;

        const selectionDetails = () => modelSelectionPayload({
          requestedModel,
          attemptModel,
          selectedModel: undefined,
          fallbackModels,
          modelAttempts,
        });
        if (run.kind === "spawn_failed") {
          throw new BridgeFault(
            "spawn_failed",
            `Claude Code could not be started: ${run.error instanceof Error ? run.error.message : String(run.error)}`,
            { model_selection: selectionDetails() },
          );
        }
        if (run.kind !== "closed") {
          throw new BridgeFault(run.kind, `Claude delegate ended with ${run.kind}.`, {
            exit_code: run.exitCode,
            model_selection: selectionDetails(),
            ...delegateStreamMetadata(run),
          });
        }

        const failureDetails = () => ({
          model: attemptModel,
          model_selection: selectionDetails(),
          ...effortPayload(effort, effortRequested),
          ...delegateStreamMetadata(run),
          stdout_metadata: claudeFailureStdoutMetadata(run.stdout),
        });
        const allUnavailable = () => runError({
          ok: false,
          is_error: true,
          error_code: "model_unavailable",
          error_message: "All configured Claude subscription models were unavailable for this turn.",
          ...failureDetails(),
        });
        const availabilityFailure = isModelAvailabilityFailureRun(run, attemptModel);
        if (run.exitCode !== 0) {
          if (availabilityFailure) {
            modelAttempts.push({ model: attemptModel, outcome: "unavailable" });
            if (attemptIndex < modelCandidates.length - 1) continue;
            return await allUnavailable();
          }
          modelAttempts.push({ model: attemptModel, outcome: "error" });
          throw new BridgeFault("nonzero_exit", `Claude exited with code ${String(run.exitCode)}.`, {
            exit_code: run.exitCode,
            model_selection: selectionDetails(),
            ...delegateStreamMetadata(run),
            stdout_metadata: claudeFailureStdoutMetadata(run.stdout),
          });
        }

        envelope = parseClaudeEnvelope(run.stdout);
        if (envelope.is_error) {
          if (isModelAvailabilityFailureMessage(envelope.result_text, attemptModel)) {
            modelAttempts.push({ model: attemptModel, outcome: "unavailable" });
            if (attemptIndex < modelCandidates.length - 1) continue;
            return await allUnavailable();
          }
          modelAttempts.push({ model: attemptModel, outcome: "error" });
          return await runError({
            ok: false,
            is_error: true,
            error_code: "claude_error",
            error_message: "Claude returned an error result.",
            ...failureDetails(),
          });
        }

        completedAttemptModel = attemptModel;
        // The attempt model ran when the provider reports it, whatever side models it also reports. A
        // configured fallback counts as selected only when the attempt model is absent and it is present.
        const reportedModels = envelope.provider_models ?? [];
        const nativeFallback = modelCandidates.slice(attemptIndex + 1).find((candidate) => reportedModels.includes(candidate));
        selectedModel = reportedModels.includes(attemptModel) || nativeFallback === undefined ? attemptModel : nativeFallback;
        modelAttempts.push({
          model: attemptModel,
          outcome: "completed",
          ...(selectedModel !== attemptModel ? { selected_model: selectedModel } : {}),
        });
        break;
      }

      if (run === undefined || envelope === undefined
        || completedAttemptModel === undefined || selectedModel === undefined) {
        throw new BridgeFault("internal_error", "Claude Bridge model selection ended without a result.");
      }

      if (resume) {
        sessionHandle = args.session_handle.trim();
        if (envelope.session_id !== undefined) session.provider_session_id = envelope.session_id;
        session.model = selectedModel;
      } else if (resumable) {
        if (envelope.session_id === undefined) {
          throw new BridgeFault(
            "invalid_envelope",
            "A resumable Claude task did not return a session_id.",
          );
        }
        sessionHandle = randomBytes(24).toString("base64url");
        if (state.sessions.size >= 32) {
          const oldest = state.sessions.keys().next().value;
          const oldestSession = state.sessions.get(oldest);
          state.sessions.delete(oldest);
          if (oldestSession?.isolation_authority_root) {
            cleanupIsolationLayout({ authorityRoot: oldestSession.isolation_authority_root });
          }
        }
        state.sessions.set(sessionHandle, {
          provider_session_id: envelope.session_id,
          cwd,
          model: selectedModel,
          effort,
          profile,
          in_use: false,
          isolation_session_key: isolationSessionKey,
          isolation_authority_root: isolationLayout.authorityRoot,
        });
        preserveIsolationAuthority = true;
      }
    } catch (error) {
      if (error instanceof BridgeFault && RUN_ERROR_CODES.has(error.code)) {
        return await runError(failurePayload(error.code, error.message, error.details));
      }
      throw error;
    }
    const parsed = parseVerdict({ structured_output: envelope.structured_output, result_text: envelope.result_text, prompt });
    const bound = recordBindingVerdict(repositoryRoot, state, parsed, jobMetadata(selectedModel), { unprotected });
    if (bound.record === undefined) {
      return toolResult(failurePayload(
        "verdict_record_failed",
        "Claude Bridge could not record a verdict for this job, so it returns no result. Read the verdict state with claude_verdict.",
        { record_error: bound.recordError, fallback_record_error: bound.fallbackRecordError },
      ), true);
    }
    const { record } = bound;
    const recordError = bound.recordError !== undefined ? { record_error: bound.recordError } : {};
    const logPath = writeJobLog(record, {
      model: selectedModel,
      result_text: envelope.result_text,
      verdict: bound.verdict,
      verdict_parse: bound.parse,
      ...recordError,
    });
    const payload = successPayload(envelope, {
      model: selectedModel,
      requestedModel,
      attemptModel: completedAttemptModel,
      fallbackModels,
      modelAttempts,
      effort,
      effortRequested,
      resultBytes: limits.resultBytes,
      sessionHandle,
    });
    return toolResult({
      ...payload,
      verdict: bound.verdict,
      verdict_id: record.id,
      verdict_parse: bound.parse,
      ...recordError,
      protection: protection.status,
      protection_reasons: protection.reasons,
      session_evidence: {
        match: evidence.session.match,
        path: evidence.session.path,
        messages: evidence.conversation.messages,
        verified_messages: evidence.conversation.verified ?? 0,
        truncated: evidence.conversation.truncated,
        ledger: evidence.ledger,
      },
      log_path: logPath,
      instructions_for_codex: "This verdict binds this session. Read operator_readback to the operator verbatim as the message that ends your turn (the hook confirms it only from that message; interim commentary does not count), then comply with required_of_codex.",
    });
  } finally {
    state.activeChild = undefined;
    if (session !== undefined) session.in_use = false;
    if (isolationLayout !== undefined) {
      cleanupIsolationLayout(isolationLayout, {
        preserveAuthority: preserveIsolationAuthority,
      });
    }
  }
}

function failureResultFromError(error) {
  const fault = error instanceof BridgeFault
    ? error
    : new BridgeFault("internal_error", error instanceof Error ? error.message : String(error));
  return toolResult(failurePayload(fault.code, fault.message, fault.details), true);
}

function runningJobResult(jobHandle, status = "running") {
  return toolResult({
    ok: true,
    is_error: false,
    status,
    job_handle: jobHandle,
    automatic_deadline: false,
  });
}

function launchDelegateJob({ profile, args, state, resume }) {
  const toolName = resume ? "claude_continue" : profile === "review" ? "claude_review" : "claude_task";
  let resolved;
  try {
    // The model and effort are checked before anything starts, so a refusal is immediate.
    if (resume) {
      const session = state.sessions.get(String(args.session_handle ?? "").trim());
      if (session !== undefined) continuationSettings(session);
    } else {
      resolveModelAndEffort(args);
    }
    const cwd = resume
      ? state.sessions.get(String(args.session_handle ?? "").trim())?.cwd
      : resolveWorkingDirectory(args.cwd, state.env);
    resolved = cwd ? bridgeRepository(cwd, state, toolName) : { root: undefined };
  } catch (error) {
    return failureResultFromError(error);
  }
  if (resolved.refusal !== undefined) return resolved.refusal;
  if (profile === "task") {
    const refusal = resolved.root ? taskRefusal(resolved.root, state, toolName) : undefined;
    if (refusal !== undefined) return refusal;
  }
  if (state.activeJobHandle !== undefined) {
    return toolResult(
      failurePayload("busy", "Claude Bridge already has an active delegate turn."),
      true,
    );
  }
  if (state.jobs.size >= 32) {
    for (const [handle, job] of state.jobs) {
      if (job.status === "completed") {
        state.jobs.delete(handle);
        break;
      }
    }
  }
  if (state.jobs.size >= 32) {
    return toolResult(
      failurePayload("job_store_full", "Claude Bridge has too many retained delegate results."),
      true,
    );
  }

  const jobHandle = randomBytes(24).toString("base64url");
  const controller = new globalThis.AbortController();
  const job = { status: "running", controller, result: undefined };
  state.jobs.set(jobHandle, job);
  state.activeJobHandle = jobHandle;

  void executeDelegate({ profile, args, state, signal: controller.signal, resume })
    .catch((error) => failureResultFromError(error))
    .then((result) => {
      job.status = "completed";
      job.result = result;
    })
    .finally(() => {
      if (state.activeJobHandle === jobHandle) state.activeJobHandle = undefined;
    });

  return runningJobResult(jobHandle);
}

function readDelegateJob(args, state) {
  const jobHandle = requireString(args.job_handle, "job_handle").trim();
  const job = state.jobs.get(jobHandle);
  if (job === undefined) {
    throw new BridgeFault(
      "unknown_job_handle",
      "The delegate job handle is unknown or expired; handles are valid only in this MCP server process.",
    );
  }
  const cancel = requireBoolean(args.cancel, "cancel", false);
  if (cancel && job.status === "running") {
    job.controller.abort();
    return runningJobResult(jobHandle, "cancelling");
  }
  if (job.status === "running") return runningJobResult(jobHandle);
  return job.result;
}

async function executeStatus(state, args) {
  if (state.activeJobHandle !== undefined || state.activeChild !== undefined) {
    throw new BridgeFault("busy", "Claude Bridge already has an active operation.");
  }
  const limits = outputLimits(state.env);
  const cwd = resolveWorkingDirectory(args.cwd ?? process.cwd(), state.env);
  const depth = assertInvocationAllowed({ env: state.env, cwd });
  const controller = new globalThis.AbortController();
  state.activeStatusController = controller;
  let isolationLayout;
  try {
    isolationLayout = prepareBridgeIsolationLayout({
      repoRoot: cwd,
      sessionKey: "status",
      includeProviderCredentials: false,
      env: state.env,
    });
    const isolatedCommand = wrapIsolatedCommand({
      repoRoot: cwd,
      isolationLayout,
      repositoryAccess: "read-only",
      environmentMode: "subscription-only",
      bridgeDepth: depth,
      bwrapBin: runtime(state.env).bwrapBin,
      command: {
        provider: "claude",
        bin: claudeBin(state.env),
        argv: ["--version"],
        stdin: "",
        env: state.env,
      },
    });
    const versionRun = await runBoundedProcess({
      bin: isolatedCommand.bin,
      argv: isolatedCommand.argv,
      cwd,
      env: isolatedCommand.env,
      stdin: "",
      stdoutLimit: Math.min(limits.stdoutBytes, 128 * 1024),
      stderrLimit: Math.min(limits.stderrBytes, 8 * 1024),
      signal: controller.signal,
      onChild: (child) => {
        state.activeChild = child;
      },
    });
    if (versionRun.kind === "spawn_failed") {
      throw new BridgeFault(
        "spawn_failed",
        `Claude Code could not be started: ${versionRun.error instanceof Error ? versionRun.error.message : String(versionRun.error)}`,
      );
    }
    if (versionRun.kind !== "closed" || versionRun.exitCode !== 0) {
      throw new BridgeFault("status_failed", "claude --version failed.", {
        ...delegateStreamMetadata(versionRun),
      });
    }
    return toolResult({
      ok: true,
      is_error: false,
      version: versionRun.stdout.trim(),
      subscription_mode: "existing_claude_code_session",
      isolation: "bubblewrap",
      protection: bridgeProtection(state.env).status,
    });
  } finally {
    state.activeChild = undefined;
    state.activeStatusController = undefined;
    if (isolationLayout !== undefined) cleanupIsolationLayout(isolationLayout);
  }
}

export async function executeBridgeTool(name, rawArgs, state) {
  try {
    const args = requireObject(rawArgs);
    if (name === "claude_bridge_status") return await executeStatus(state, args);
    if (name === "claude_result") return readDelegateJob(args, state);
    if (name === "claude_task") {
      return launchDelegateJob({ profile: "task", args, state, resume: false });
    }
    if (name === "claude_review") {
      return launchDelegateJob({ profile: "review", args, state, resume: false });
    }
    if (name === "claude_continue") {
      return launchDelegateJob({ profile: "task", args, state, resume: true });
    }
    if (name === "claude_verdict") {
      const cwd = resolveWorkingDirectory(args.cwd ?? process.cwd(), state.env);
      const repoRoot = verdictRepository(cwd, state.env);
      if (repoRoot === undefined) throw new BridgeFault("invalid_arguments", "cwd must be inside a Git repository.");
      return toolResult({
        ok: true,
        is_error: false,
        ...bridgeVerdictState(repoRoot, state.env),
        protection: bridgeProtection(state.env).status,
        hooks: bridgeHooks(state.env),
        record_failure: recordFailureStatus(repoRoot, state),
      });
    }
    throw new BridgeFault("unknown_tool", `Unknown tool: ${String(name)}.`);
  } catch (error) {
    return failureResultFromError(error);
  }
}

const sharedPromptSchema = {
  prompt: {
    type: "string",
    minLength: 1,
    description: "The complete task or review prompt. It is sent to Claude only on child stdin.",
  },
  cwd: {
    type: "string",
    minLength: 1,
    description: "Absolute existing working directory for the Claude delegate.",
  },
  model: {
    type: "string",
    enum: [...ALLOWED_MODELS],
    default: DEFAULT_MODEL,
    description: "Claude Fable 5.1 (the default), which falls back to Claude Opus 5.5 when Fable is unavailable, or Opus 5.5 with no fallback. Codex cannot choose another model.",
  },
  effort: {
    type: "string",
    enum: [...ALLOWED_EFFORTS],
    default: DEFAULT_EFFORT,
    description: "Effort high at the least; a lower effort runs as high.",
  },
};

export const BRIDGE_TOOLS = [
  {
    name: "claude_bridge_status",
    title: "Claude Bridge Status",
    description: "Check the isolated Claude Code binary without starting a model turn.",
    inputSchema: { type: "object", properties: { cwd: sharedPromptSchema.cwd }, additionalProperties: false },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "claude_task",
    title: "Delegate Task to Claude Code",
    description: "Only when the operator explicitly asks for Claude: delegate write-capable work to Claude through the existing subscription session, in an isolated workspace. Claude holds corrective authority delegated by the operator and returns a binding verdict. Refused while a verdict is open.",
    inputSchema: {
      type: "object",
      properties: {
        ...sharedPromptSchema,
        resumable: {
          type: "boolean",
          default: false,
          description: "Persist the Claude session and return an opaque same-process continuation handle.",
        },
      },
      required: ["prompt", "cwd"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: "claude_review",
    title: "Request Adversarial Claude Review",
    description: "Only when the operator explicitly asks for Claude: adversarial review with corrective authority delegated by the operator. Claude sees the operator's full conversation, may alter the submitted work, and may use the shell and web. The verdict binds this session: read operator_readback to the operator verbatim and comply with required_of_codex.",
    inputSchema: {
      type: "object",
      properties: { ...sharedPromptSchema },
      required: ["prompt", "cwd"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: "claude_continue",
    title: "Continue Claude Task",
    description: "Start a no-deadline continuation job on the session's model and effort, with bridge-managed rollover from Fable 5.1 to Opus 5.5, using only the opaque session handle returned by a completed resumable task, then poll claude_result. Refused while a verdict is open.",
    inputSchema: {
      type: "object",
      properties: {
        prompt: sharedPromptSchema.prompt,
        session_handle: {
          type: "string",
          minLength: 1,
          description: "Opaque handle returned by a resumable claude_task call.",
        },
      },
      required: ["prompt", "session_handle"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: "claude_result",
    title: "Read Or Cancel Claude Job",
    description: "Poll a background Claude job until it completes, or explicitly cancel it. Provider jobs have no elapsed-time deadline.",
    inputSchema: {
      type: "object",
      properties: {
        job_handle: {
          type: "string",
          minLength: 1,
          description: "Opaque handle returned by claude_task, claude_review, or claude_continue.",
        },
        cancel: {
          type: "boolean",
          default: false,
          description: "Explicitly cancel a running provider job instead of waiting for natural completion.",
        },
      },
      required: ["job_handle"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "claude_verdict",
    title: "Read Claude Bridge Verdict State",
    description: "Read the open verdict, protection status and hook integrity for the repository at cwd. Read-only.",
    inputSchema: { type: "object", properties: { cwd: sharedPromptSchema.cwd }, additionalProperties: false },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function sendResult(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

function sendError(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

export function startStdioServer({ env = process.env } = {}) {
  const state = createBridgeState(env);
  let closing = false;

  const terminateActiveChild = () => {
    if (state.activeChild === undefined) return;
    try {
      signalProcessGroup(state.activeChild, "SIGTERM");
    } catch {
      // Shutdown remains best-effort after the MCP transport disappears.
    }
    setTimeout(() => {
      try {
        signalProcessGroup(state.activeChild, "SIGKILL");
      } catch {
        // The child group already exited.
      }
    }, 500).unref?.();
  };

  const close = () => {
    if (closing) return;
    closing = true;
    for (const job of state.jobs.values()) job.controller.abort();
    state.activeStatusController?.abort();
    terminateActiveChild();
    for (const session of state.sessions.values()) {
      if (session.isolation_authority_root) {
        cleanupIsolationLayout({ authorityRoot: session.isolation_authority_root });
      }
    }
    state.sessions.clear();
    state.jobs.clear();
    state.activeJobHandle = undefined;
  };

  const handleMessage = async (message) => {
    if (message === null || typeof message !== "object" || Array.isArray(message)) {
      sendError(null, JsonRpcError.INVALID_PARAMS, "JSON-RPC message must be an object.");
      return;
    }
    const { id, method, params } = message;

    if (closing) {
      if (method === "exit" || id === undefined) return;
      sendError(id, JsonRpcError.INTERNAL_ERROR, "Claude Bridge is shutting down.");
      return;
    }

    if (method === "notifications/initialized") return;
    if (method === "notifications/cancelled") return;
    if (method === "exit") {
      close();
      return;
    }
    if (method === "initialize") {
      sendResult(id, {
        protocolVersion: params?.protocolVersion ?? "2025-11-25",
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        instructions: "Use Claude Bridge only after an explicit operator request to invoke Claude. Claude holds corrective authority delegated by the operator: reviews may alter the submitted work; a run that finishes carries a binding verdict and a run that errors records a blocked verdict; task and continuation calls are refused while a verdict is open or a record failure is latched. Read operator_readback to the operator verbatim. Poll claude_result until completion.",
      });
      return;
    }
    if (method === "ping") {
      sendResult(id, {});
      return;
    }
    if (method === "tools/list") {
      sendResult(id, { tools: BRIDGE_TOOLS });
      return;
    }
    if (method === "shutdown") {
      sendResult(id, {});
      close();
      return;
    }
    if (method === "tools/call") {
      try {
        const result = await executeBridgeTool(
          params?.name,
          params?.arguments,
          state,
        );
        sendResult(id, result);
      } catch (error) {
        sendError(
          id,
          JsonRpcError.INTERNAL_ERROR,
          error instanceof Error ? error.message : String(error),
        );
      }
      return;
    }
    if (id !== undefined) sendError(id, JsonRpcError.METHOD_NOT_FOUND, `Method not found: ${String(method)}`);
  };

  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  lines.on("line", (line) => {
    if (line.trim().length === 0) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      sendError(null, JsonRpcError.PARSE_ERROR, "Invalid JSON.");
      return;
    }
    void handleMessage(message);
  });
  lines.on("close", close);
  process.stdout.on("error", (error) => {
    if (error?.code === "EPIPE") close();
  });
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.once(signal, () => {
      close();
      setTimeout(() => process.exit(0), 750).unref?.();
    });
  }
  return { state, close };
}

/**
 * True when this module is the program Node was started with. Node resolves the main module through links, so a
 * launch via /opt/claude-bridge/current/... runs the module at its real <version> path: compare real paths.
 */
export function isCliEntry(argv = process.argv, url = import.meta.url) {
  if (!argv[1]) return false;
  try {
    return realpathSync(path.resolve(argv[1])) === realpathSync(fileURLToPath(url));
  } catch {
    return false;
  }
}

if (isCliEntry()) {
  // Installed, the isolation masks follow os.homedir(), which reads HOME: point it at the passwd home.
  const defaults = runtime(process.env);
  if (defaults.installed) process.env.HOME = defaults.home;
  startStdioServer({ env: bridgeEnvironmentFromArgs() });
}
