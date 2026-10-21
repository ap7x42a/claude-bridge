#!/usr/bin/env python3
"""Claude Bridge hooks for Codex.

Five events, one script: SessionStart, UserPromptSubmit, PreToolUse, PostToolUse
and Stop. Reads the hook JSON on stdin and answers on stdout. Standard library only.

The verdict chain is shared with plugins/claude-bridge/mcp/verdict.mjs, which is
the authority on its format. Every function here that reads or appends the chain
mirrors that module: canonical JSON, the hash links, head.json, the state lock and
the replay. Canonical key order is JavaScript's (array-index keys first, then
UTF-16 code-unit order), which equals json.dumps(sort_keys=True) for every key the
bridge writes and still agrees with Node on any other key.

The context and Stop handlers read the verdict state through the bridge's own
state CLI (mcp/state-cli.mjs under the protected root, run with /usr/bin/node),
which verifies owner clears against the installed public key. When it is absent
or fails they fall back to the replay here, which does not verify owner clears,
and say so.

Time budget, against Codex's hook timeouts (10 s, Stop 15 s): each event runs the
state CLI at most once, capped at 5 s. UserPromptSubmit waits at most 2 s for the
lock to ledger the prompt (under 8 s in all); PreToolUse on a bridge call waits at
most 2 s to ledger the call (under 8 s); Stop waits at most 3 s to ledger the
message and at most 3 s for the readback append (under 12 s).

The hook also keeps the turns ledger (turns.jsonl), chained like the verdicts:
the owner's prompts, Codex's final messages and each bridge call's transcript
path, as the Codex app hands them over. The bridge labels conversation messages
verified only against it, and Stop confirms a readback only from it.
"""
import datetime
import hashlib
import json
import math
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - only on an old interpreter
    tomllib = None

STANDING = ("Claude Bridge holds corrective authority delegated by the operator. "
            "Its verdicts bind this session: read operator_readback to the operator verbatim and comply with required_of_codex.")
RECORD_FAILURE = ("A Claude Bridge verdict could not be recorded; task and continuation calls are refused "
                  "until a review records a verdict.")
INTEGRITY = "Claude Bridge verdict state failed its integrity check"
NOT_INTACT = "Claude Bridge hook registration is not intact"
CACHE_LAUNCH_CONFIG_MISMATCH = "Codex cache launch config is not the installed one"  # protection.mjs
FALLBACK = "Claude Bridge verdict state read by the hook's own replay; owner clears unverified."
STATE_CLI_TIMEOUT_S = 5
# The interpreter for the state CLI: root-owned, never looked up on PATH.
NODE = "/usr/bin/node"
EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop")
MAX_BLOCKS = 3
TRANSCRIPT_TAIL_BYTES = 400_000
LOCK_TIMEOUT_MS = 3000
LEDGER_LOCK_TIMEOUT_MS = 2000  # the prompt and bridge-call ledger appends, inside a 10 s hook
LOCK_RETRY_MS = 25
LOCK_STALE_MS = 30_000
MAX_SAFE_INTEGER = 2 ** 53 - 1
# String.prototype.trim(): ECMAScript white space and line terminators.
JS_WHITESPACE = ("\t\n\v\f\r              "
                 "    　﻿")
LONE_SURROGATE = re.compile("[\ud800-\udfff]")
MISSING = object()  # JavaScript undefined: a key that is absent


class CanonicalError(ValueError):
    pass


class LockTimeout(Exception):
    pass


# ---- canonical JSON (canonical.mjs) ----

def _is_array_index(key):
    return key.isascii() and key.isdigit() and (key == "0" or key[0] != "0") and int(key) <= 2 ** 32 - 2


def _key_order(keys):
    # Object.keys().sort() orders by UTF-16 code unit; the object rebuilt from the sorted
    # entries then lists array-index keys first, ascending, which is what JSON.stringify emits.
    indexes = sorted((key for key in keys if _is_array_index(key)), key=int)
    names = sorted((key for key in keys if not _is_array_index(key)), key=lambda key: key.encode("utf-16-be"))
    return indexes + names


def _canonical_value(value):
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError("canonical JSON refuses non-string keys")
            if LONE_SURROGATE.search(key):
                raise CanonicalError("canonical JSON refuses lone surrogates")
        return {key: _canonical_value(value[key]) for key in _key_order(list(value))}
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalError("canonical JSON refuses numbers that are not safe integers")
        return value
    if isinstance(value, str):
        if LONE_SURROGATE.search(value):
            raise CanonicalError("canonical JSON refuses lone surrogates")
        return value
    raise CanonicalError("canonical JSON refuses numbers that are not safe integers")


def canonical(value):
    return json.dumps(_canonical_value(value), ensure_ascii=False, separators=(",", ":"))


def _js_order(value):
    """The key order JSON.parse leaves: array-index keys first, ascending, then the rest as written."""
    if isinstance(value, dict):
        keys = list(value)
        indexes = sorted((key for key in keys if _is_array_index(key)), key=int)
        return {key: _js_order(value[key]) for key in indexes + [key for key in keys if not _is_array_index(key)]}
    if isinstance(value, list):
        return [_js_order(item) for item in value]
    return value


def node_compact(record):
    """JSON.stringify(JSON.parse(line)) for a parsed record: equal to the line for every record the bridge writes."""
    return json.dumps(_js_order(record), ensure_ascii=False, separators=(",", ":"))


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---- JavaScript value semantics for values parsed from JSON ----

def _reject_constant(name):
    raise ValueError("JSON.parse rejects " + name)


def _parse(text):
    """JSON.parse: NaN and Infinity are syntax errors."""
    return json.loads(text, parse_constant=_reject_constant)


def _get(value, key):
    return value.get(key, MISSING) if isinstance(value, dict) else MISSING


def _same(a, b):
    """JavaScript ===."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return False
    return type(a) is type(b) and a == b


def _is(value, text):
    return isinstance(value, str) and value == text


def _truthy(value):
    if value is MISSING or value is None or value is False:
        return False
    if isinstance(value, (int, float, str)):
        return bool(value)
    return True


def _plain(value):
    """JSON.stringify drops keys whose value is undefined."""
    return {key: item for key, item in value.items() if item is not MISSING}


def _text(value):
    return "" if value is MISSING or value is None else str(value)


# ---- locations ----

INSTALL_ROOT = "/opt/claude-bridge"
INSTALL_ETC = "/etc/claude-bridge"


def _passwd_home():
    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        return os.path.expanduser("~")


def _number_at_least_one(text):
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 1 else None


def runtime_defaults(self_path=None):
    """protection.mjs runtimeDefaults. A hook running from the literal /opt/claude-bridge ignores the environment:
    the roots are /opt/claude-bridge and /etc/claude-bridge, HOME is the passwd entry of the process uid, and no
    test knob applies. Anywhere else every value comes from the environment."""
    path = os.path.normpath(os.path.abspath(__file__ if self_path is None else self_path))
    if path == INSTALL_ROOT or path.startswith(INSTALL_ROOT + os.sep):
        user_home = _passwd_home()
        codex = os.path.join(user_home, ".codex")
        return {"installed": True, "home": user_home, "codex_home": codex,
                "state_root": os.path.join(user_home, ".local", "state", "claude-bridge"),
                "sessions_root": os.path.join(codex, "sessions"), "protected_root": INSTALL_ROOT, "etc_dir": INSTALL_ETC,
                "test_mode": False, "state_cli": os.path.join(INSTALL_ROOT, "current", "mcp", "state-cli.mjs"),
                "lock_timeout_ms": LOCK_TIMEOUT_MS}
    environ = os.environ
    user_home = environ.get("HOME") or os.path.expanduser("~")
    codex = environ.get("CODEX_HOME") or os.path.join(user_home, ".codex")
    root = environ.get("CLAUDE_BRIDGE_PROTECTED_ROOT") or INSTALL_ROOT
    test_mode = environ.get("CLAUDE_BRIDGE_TEST_MODE") == "1"
    state_cli = environ.get("CLAUDE_BRIDGE_STATE_CLI") if test_mode else None
    lock_timeout = _number_at_least_one(environ.get("CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS")) if test_mode else None
    return {"installed": False, "home": user_home, "codex_home": codex,
            "state_root": environ.get("CLAUDE_BRIDGE_STATE_DIR") or os.path.join(user_home, ".local", "state", "claude-bridge"),
            "sessions_root": environ.get("CLAUDE_BRIDGE_SESSIONS_ROOT") or os.path.join(codex, "sessions"),
            "protected_root": root, "etc_dir": environ.get("CLAUDE_BRIDGE_ETC_DIR") or INSTALL_ETC,
            "test_mode": test_mode, "state_cli": state_cli or os.path.join(root, "current", "mcp", "state-cli.mjs"),
            "lock_timeout_ms": LOCK_TIMEOUT_MS if lock_timeout is None else lock_timeout}


def codex_home():
    return runtime_defaults()["codex_home"]


def state_root():
    return runtime_defaults()["state_root"]


def protected_root():
    return runtime_defaults()["protected_root"]


def etc_dir():
    return runtime_defaults()["etc_dir"]


def hook_command():
    """protection.mjs expectedHookCommand: an isolated interpreter, so user site-packages cannot alter the hook."""
    return "/usr/bin/python3 -I " + os.path.normpath(os.path.join(protected_root(), "current", "hooks", "bridge_hook.py"))


def working_dir(data):
    cwd = data.get("cwd")
    return os.path.realpath(cwd if isinstance(cwd, str) and cwd else os.getcwd())


def repo_root(cwd):
    """The bridge's repository for the resolved cwd, as server.mjs bridgeRepository keys it: the nearest directory
    holding .git. Where the protected install exists, a .git nested inside a registered repository is keyed to the
    outermost registered one, unless the nested root is registered itself and that outer repository is clean (no
    record failure, state clear), in which case it is keyed to itself."""
    nearest = None
    outer = None
    current = cwd
    while True:
        if os.path.exists(os.path.join(current, ".git")):
            if nearest is None:
                nearest = current
            if is_registered(current):
                outer = current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    if outer is None or outer == nearest or not os.path.exists(protected_root()):
        return nearest
    if is_registered(nearest) and _repository_clean(outer):
        return nearest
    return outer


def _repository_clean(root):
    """No record failure is latched and the verdict state reads clear. Read with the hook's own replay, which starts no
    process, so an event still runs the state CLI at most once; it does not verify owner clears, so a forged clear in
    the outer repository can key the hook to the nested root where the server refuses the call."""
    if os.path.exists(os.path.join(state_dir(root), "record-failure.json")):
        return False
    return current_state(root, is_registered(root)).get("status") == "clear"


def repo_key(root):
    return sha256_hex(root)[:20]


def state_dir(root):
    return os.path.join(state_root(), repo_key(root))


def _read_text(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", errors="replace")


def is_registered(root):
    try:
        text = _read_text(os.path.join(etc_dir(), "repos", repo_key(root)))
    except OSError:
        return False
    return text.strip(JS_WHITESPACE) == root


# ---- verdict chain (verdict.mjs) ----

class Chain:
    def __init__(self, records, intact, exists, head):
        self.records = records
        self.intact = intact
        self.exists = exists
        self.head = head  # hash of the last record; "" for an empty file, None when there is no file


# The two hash-chained ledgers in a state directory (verdict.mjs VERDICTS_LEDGER and TURNS_LEDGER): the chain file and
# its head. The turns ledger is written only here, from what the Codex app hands the hook.
VERDICTS = ("verdicts.jsonl", "head.json")
TURNS = ("turns.jsonl", "turns-head.json")


def read_chain(directory, ledger=VERDICTS):
    path = os.path.join(directory, ledger[0])
    if not os.path.exists(path):
        return Chain([], True, False, None)
    records = []
    prev_hash = ""
    intact = True
    try:
        text = _read_text(path)
    except OSError:
        return Chain([], False, True, "")
    for line in text.split("\n"):
        if not line.strip(JS_WHITESPACE):
            continue
        try:
            record = _parse(line)
        except (ValueError, RecursionError):
            intact = False
            break
        if not isinstance(record, dict):
            intact = False
            break
        # The bridge writes each record in Node's compact form; anything else is a non-canonical line.
        try:
            compact = node_compact(record)
        except (ValueError, RecursionError):
            intact = False
            break
        if compact != line:
            intact = False
            break
        prev = record.get("prev")
        if not _is("" if prev is None else prev, prev_hash):
            intact = False
        records.append(record)
        # A record with no canonical form was not written by the bridge.
        try:
            prev_hash = sha256_hex(canonical(record))
        except (CanonicalError, RecursionError):
            intact = False
            break
    return Chain(records, intact, True, prev_hash)


def _read_json(path):
    try:
        return _parse(_read_text(path))
    except (OSError, ValueError, RecursionError):
        return None


def head_consistent(directory, chain, ledger=VERDICTS):
    """head.json matches the chain, or neither exists."""
    path = os.path.join(directory, ledger[1])
    if not chain.exists:
        return not os.path.exists(path)
    head = _read_json(path)
    return isinstance(head, dict) and _same(_get(head, "hash"), chain.head) and _same(_get(head, "count"), len(chain.records))


def chain_consistent(directory, chain, ledger=VERDICTS):
    return chain.intact and head_consistent(directory, chain, ledger)


def _write_file(path, text, flags):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(text.encode("utf-8"))


def write_record(directory, body, ledger=VERDICTS):
    chain = read_chain(directory, ledger)
    consistent = chain_consistent(directory, chain, ledger)
    record = dict(body)
    record["prev"] = "" if chain.head is None else chain.head
    if record.get("id") is None:
        record["id"] = sha256_hex(canonical(record))[:16]
    digest = sha256_hex(canonical(record))  # raises before anything is written if the record has no canonical form
    _write_file(os.path.join(directory, ledger[0]), json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n", os.O_APPEND)
    # An append must not hide tampering: the head moves only on a consistent chain.
    if consistent:
        head = json.dumps({"hash": digest, "count": len(chain.records) + 1}, separators=(",", ":")) + "\n"
        _write_file(os.path.join(directory, ledger[1]), head, os.O_TRUNC)
    return record


def append_record(directory, body, registered, ledger=VERDICTS):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if ledger != VERDICTS:
        return write_record(directory, body, ledger)
    if registered and not read_chain(directory).exists:
        # A registered repo always has a chain; a missing one was deleted.
        write_record(directory, {"type": "state_reset_detected", "recorded_at": now_iso(), "note": "registered repository had no verdict chain"})
    return write_record(directory, body)


def _remove(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except FileNotFoundError:
        pass


def _now_ms():
    return time.time_ns() / 1e6


def _lock_age_ms(lock):
    try:
        return (time.time_ns() - os.stat(lock).st_mtime_ns) / 1e6
    except FileNotFoundError:
        return None


def lock_timeout_ms():
    """3 s, or CLAUDE_BRIDGE_TEST_LOCK_TIMEOUT_MS (a number >= 1) in test mode outside /opt/claude-bridge, as in server.mjs."""
    return runtime_defaults()["lock_timeout_ms"]


def with_state_lock(directory, fn, registered, timeout_ms=None):
    """The bridge's advisory lock: a .lock directory, 25 ms retries for 3 s (or `timeout_ms`), broken after 30 s."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    lock = os.path.join(directory, ".lock")
    deadline = _now_ms() + (lock_timeout_ms() if timeout_ms is None else timeout_ms)
    broken_age_ms = None
    while True:
        try:
            os.mkdir(lock, 0o700)
            break
        except FileExistsError:
            pass
        age_ms = _lock_age_ms(lock)
        if age_ms is not None and age_ms > LOCK_STALE_MS:
            _remove(lock)
            broken_age_ms = math.floor(age_ms + 0.5)  # Math.round, an integer
            continue
        if _now_ms() >= deadline:
            raise LockTimeout(lock)
        if age_ms is not None:
            time.sleep(LOCK_RETRY_MS / 1000)
    try:
        if broken_age_ms is not None:
            append_record(directory, {"type": "lock_broken", "recorded_at": now_iso(), "stale_ms": broken_age_ms}, registered)
        return fn()
    finally:
        _remove(lock)


RUN_STARTED_READBACK = ("Claude Bridge: a review run started and never recorded a verdict. "
                        "Work is blocked until a review completes.")  # verdict.mjs
RUN_STARTED_REQUIRED = "Rerun the review; a run started and never recorded a verdict."


def replay_chain(records):
    """The chain is the authority: the open verdict from the records alone. A run_started whose job has no later
    verdict acts as a blocked verdict, as in verdict.mjs."""
    last_verdict_at = {}
    for index, record in enumerate(records):
        if _is(record.get("type"), "verdict") and isinstance(record.get("job_id"), str):
            last_verdict_at[record["job_id"]] = index
    opened = None
    opened_profile = MISSING  # the profile of the record that opened `opened`
    reset = False

    def covered_by_review(record):
        # A task's verdict, or its run_started, never replaces (and so never lifts) an open verdict from a review.
        return opened is not None and _is(opened_profile, "review") and _is(record.get("profile", MISSING), "task")

    for index, record in enumerate(records):
        kind = record.get("type")
        if _is(kind, "run_started"):
            job = record.get("job_id")
            if isinstance(job, str) and last_verdict_at.get(job, -1) > index:
                continue
            if covered_by_review(record):
                continue
            opened_profile = record.get("profile", MISSING)
            opened = {"id": record.get("id", MISSING), "verdict": "blocked", "operator_readback": RUN_STARTED_READBACK,
                      "required_of_codex": [RUN_STARTED_REQUIRED], "reprimand": None,
                      "recorded_at": record.get("recorded_at", MISSING), "readback_confirmed": False, "run_started": True}
        elif _is(kind, "verdict"):
            if covered_by_review(record):
                continue
            opened_profile = record.get("profile", MISSING)
            body = record.get("verdict")
            body = {} if body is None else body
            opened = None if _is(_get(body, "verdict"), "clear") else {
                "id": record.get("id", MISSING), "verdict": _get(body, "verdict"),
                "operator_readback": _get(body, "operator_readback"), "required_of_codex": _get(body, "required_of_codex"),
                "reprimand": _get(body, "reprimand"), "recorded_at": record.get("recorded_at", MISSING), "readback_confirmed": False,
            }
        elif _is(kind, "readback_confirmed") and opened is not None and _same(record.get("verdict_id", MISSING), opened["id"]):
            opened = None if _is(opened["verdict"], "corrected") else {**opened, "readback_confirmed": True}
        elif _is(kind, "state_reset_detected"):
            reset = True
        elif _is(kind, "owner_clear"):
            target = record.get("verdict_id", MISSING)
            if _is(target, "*"):
                reset = False
            if opened is not None and (_same(target, opened["id"]) or _is(target, "*")):
                opened = None
    return opened, reset


def read_open(directory):
    path = os.path.join(directory, "open.json")
    if not os.path.exists(path):
        return None
    try:
        return _parse(_read_text(path))
    except (OSError, ValueError, RecursionError):
        return {"corrupt": True}


def write_open(directory, value):
    path = os.path.join(directory, "open.json")
    if value is None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return
    _write_file(path, json.dumps(_plain(value), indent=2, ensure_ascii=False) + "\n", os.O_TRUNC)


def current_state(root, registered):
    """verdict.mjs currentState: tampered, open (chain fields win over open.json) or clear."""
    directory = state_dir(root)
    chain = read_chain(directory)
    cached = read_open(directory)

    def tampered(reason):
        return {"status": "tampered", "open": None, "reason": reason}

    if not chain.intact or (isinstance(cached, dict) and _truthy(cached.get("corrupt", MISSING))):
        return tampered("verdict chain or open record unreadable")
    if registered and not chain.exists:
        return tampered("registered repository has no verdict state; owner clear required")
    if not chain_consistent(directory, chain):
        return tampered("chain head missing or does not match")
    replayed, reset = replay_chain(chain.records)
    if reset:
        return tampered("verdict state was reset; owner clear required")
    if replayed is not None and (not _truthy(cached) or not _same(_get(cached, "id"), replayed["id"])):
        return tampered("open record missing or does not match the chain")
    if replayed is None and _truthy(cached):
        return tampered("open record present but the chain shows no open verdict")
    if replayed is not None:
        return {"status": "open", "open": {**(cached if isinstance(cached, dict) else {}), **replayed}}
    return {"status": "clear", "open": None}


def state_cli_path():
    """The bridge's state CLI under the protected root; CLAUDE_BRIDGE_STATE_CLI replaces it in test mode only."""
    return runtime_defaults()["state_cli"]


def _valid_state(state):
    if not isinstance(state, dict):
        return False
    status = state.get("status")
    if _is(status, "open"):
        return isinstance(state.get("open"), dict)
    if _is(status, "tampered"):
        return isinstance(state.get("reason"), str)
    return _is(status, "clear")


def state_cli_env():
    """The state CLI's whole environment: a fixed PATH and the passwd HOME, no NODE_OPTIONS or anything else the
    caller set. Outside /opt/claude-bridge the CLI takes its locations from the environment, so they are passed on."""
    defaults = runtime_defaults()
    env = {"PATH": "/usr/bin:/bin", "HOME": defaults["home"]}
    if not defaults["installed"]:
        env.update({"CODEX_HOME": defaults["codex_home"], "CLAUDE_BRIDGE_STATE_DIR": defaults["state_root"],
                    "CLAUDE_BRIDGE_SESSIONS_ROOT": defaults["sessions_root"],
                    "CLAUDE_BRIDGE_PROTECTED_ROOT": defaults["protected_root"], "CLAUDE_BRIDGE_ETC_DIR": defaults["etc_dir"]})
    return env


def run_state_cli(*args):
    """The state CLI's JSON answer, run under /usr/bin/node; None when it is absent or fails."""
    path = state_cli_path()
    if not os.path.isfile(NODE) or not os.path.isfile(path):
        return None
    try:
        result = subprocess.run([NODE, path, *args], stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=STATE_CLI_TIMEOUT_S, check=False, env=state_cli_env())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return _parse(result.stdout.decode("utf-8"))
    except (ValueError, RecursionError):
        return None


def protection_from_cli():
    """The installed bridge's protectionStatus and hook trust state from the state CLI; None when it cannot run."""
    protection = run_state_cli("protection")
    return protection if isinstance(protection, dict) else None


def state_from_cli(root):
    """verdict.mjs currentState through the state CLI, owner clears verified; None when it is absent or fails."""
    state = run_state_cli("current-state", root)
    return state if _valid_state(state) else None


def read_state(root, registered):
    """(state, verified): the state CLI's answer when it runs, else this module's replay, which does not verify owner clears."""
    state = state_from_cli(root)
    if state is not None:
        return state, True
    return current_state(root, registered), False


# ---- turns ledger: what the app hands the hook, recorded as it happens ----

TURN_TEXT_LIMIT = 16_000


def _safe_text(text):
    """Lone surrogates become U+FFFD, as Node's UTF-8 encoding of them does, so hashes and records agree."""
    return LONE_SURROGATE.sub("\ufffd", text)


def text_sha256(text):
    return sha256_hex(_safe_text(text))


def _optional_text(value):
    return _safe_text(value) if isinstance(value, str) else None


def turn_text(key, text):
    """The sha256 of the whole text and the text itself, cut at TURN_TEXT_LIMIT characters with truncated: true."""
    safe = _safe_text(text)
    fields = {"sha256": sha256_hex(safe), key: safe[:TURN_TEXT_LIMIT]}
    if len(safe) > TURN_TEXT_LIMIT:
        fields["truncated"] = True
    return fields


def keeps_turns(root, registered):
    """The ledger is kept for a registered repository, and for one the bridge already holds state for."""
    return registered or os.path.isdir(state_dir(root))


def record_turn(root, registered, body, timeout_ms=None):
    """Appends to the turns ledger under the state lock; a turn that cannot be recorded is left out."""
    directory = state_dir(root)
    try:
        with_state_lock(directory, lambda: append_record(directory, body, registered, TURNS), registered, timeout_ms)
    except (LockTimeout, OSError, CanonicalError):
        return False
    return True


def record_bridge_call(data, root):
    """The app-supplied transcript path of the session making a bridge call, with its inode, for the bridge to bind to."""
    path = data.get("transcript_path")
    inode = None
    if isinstance(path, str) and path:
        try:
            inode = str(os.stat(path).st_ino)
        except (OSError, ValueError):
            inode = None
    record_turn(root, is_registered(root), {"type": "bridge_call", "session_id": _optional_text(data.get("session_id")),
                                            "transcript_path": _optional_text(path), "inode": inode, "recorded_at": now_iso()},
                min(LEDGER_LOCK_TIMEOUT_MS, lock_timeout_ms()))


def now_iso():
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


# ---- events ----

def normalise(text):
    text = re.sub(r"[*_`>#]", "", text or "")
    return re.sub(r"\s+", " ", text).strip().lower()


def _hook_registered(groups, command):
    if not isinstance(groups, list):
        return False
    return any(isinstance(group, dict) and isinstance(group.get("hooks"), list)
               and any(isinstance(hook, dict) and hook.get("command") == command for hook in group["hooks"])
               for group in groups)


def registration_intact():
    hooks = _get(_read_json(os.path.join(codex_home(), "hooks.json")), "hooks")
    if not isinstance(hooks, dict):
        return False
    command = hook_command()
    return all(_hook_registered(hooks.get(event), command) for event in EVENTS)


# protection.mjs EXPECTED_HOOKS: one group per event holding exactly our command, with a matcher only where listed.
EXPECTED_HOOKS = {"SessionStart": {"matcher": "startup|resume|clear|compact", "timeout": 10}, "UserPromptSubmit": {"timeout": 10},
                  "PreToolUse": {"timeout": 10}, "PostToolUse": {"timeout": 10}, "Stop": {"timeout": 15}}
TRUSTED_HASH = re.compile(r"(?:sha256:)?[0-9a-f]{64}")


def _snake_case(event):
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", event).lower()


def _hook_index(groups, command, expected):
    """protection.mjs hookIndex: (group, hook) when our command is registered once in the expected shape,
    "unexpected" for any other shape, None when absent."""
    found = []
    for g, group in enumerate(groups if isinstance(groups, list) else []):
        hooks = group.get("hooks") if isinstance(group, dict) and isinstance(group.get("hooks"), list) else []
        for h, hook in enumerate(hooks):
            if isinstance(hook, dict) and _is(hook.get("command", MISSING), command):
                found.append((g, h, group, hook))
    if not found:
        return None
    if len(found) > 1:
        return "unexpected"
    g, h, group, hook = found[0]
    if "matcher" in expected:
        group_ok = sorted(group) == ["hooks", "matcher"] and _is(group.get("matcher"), expected["matcher"])
    else:
        group_ok = sorted(group) == ["hooks"]
    hook_ok = (sorted(hook) == ["command", "timeout", "type"] and _is(hook.get("type"), "command")
               and _same(hook.get("timeout"), expected["timeout"]))
    return (g, h) if group_ok and hook_ok else "unexpected"


def trust_entry_state(state_table, key):
    """protection.mjs trustEntryState over the tomllib-parsed hooks.state table."""
    if state_table is None:
        return "untrusted"
    if not isinstance(state_table, dict):
        return "unexpected"
    if key not in state_table:
        return "untrusted"
    entry = state_table[key]
    if not isinstance(entry, dict):
        return "unexpected"
    if any(name not in ("trusted_hash", "enabled") for name in entry):
        return "unexpected"
    if "enabled" in entry and not isinstance(entry["enabled"], bool):
        return "unexpected"
    if "trusted_hash" in entry and not (isinstance(entry["trusted_hash"], str) and TRUSTED_HASH.fullmatch(entry["trusted_hash"])):
        return "unexpected"
    if entry.get("enabled") is False:
        return "disabled"
    if not entry:
        return "untrusted"
    return "trusted" if "trusted_hash" in entry else "unexpected"


def hooks_intact():
    """protection.mjs hooksIntact: (intact, reasons) for our registration in hooks.json and its trust entries in
    config.toml, read with tomllib as Codex reads them."""
    hooks_path = os.path.join(codex_home(), "hooks.json")
    data = _read_json(hooks_path)
    if not isinstance(data, dict):
        return False, [f"{hooks_path} missing or unreadable"]
    hooks = data.get("hooks")
    hooks = hooks if isinstance(hooks, dict) else {}
    command = hook_command()
    if tomllib is None:
        return False, ["python3 lacks tomllib (needs 3.11+); cannot read Codex trust"]
    state_table = None
    try:
        config = _read_text(os.path.join(codex_home(), "config.toml"))
    except OSError:
        config = None  # no config means nothing is trusted yet
    if config is not None:
        try:
            doc = tomllib.loads(config)
        except (tomllib.TOMLDecodeError, ValueError, RecursionError) as error:
            return False, [f"cannot parse config.toml: {type(error).__name__}: {error}"]
        features = doc.get("features")
        if isinstance(features, dict) and features.get("codex_hooks") is False:
            return False, ["hooks disabled by features.codex_hooks"]
        table = doc.get("hooks")
        state_table = "not a table" if table is not None and not isinstance(table, dict) else (table or {}).get("state")
    reasons = []
    for event, expected in EXPECTED_HOOKS.items():
        at = _hook_index(hooks.get(event), command, expected)
        if at is None:
            reasons.append(f"{event} hook not registered for {command}")
            continue
        if at == "unexpected":
            reasons.append(f"{event} hook is registered with an unexpected shape")
            continue
        state = trust_entry_state(state_table, f"{hooks_path}:{_snake_case(event)}:{at[0]}:{at[1]}")
        if state == "untrusted":
            reasons.append(f"{event} hook is not yet trusted in Codex")
        elif state == "disabled":
            reasons.append(f"{event} hook is disabled in Codex config")
        elif state == "unexpected":
            reasons.append(f"{event} hook is not intact: unexpected trust state")
    return not reasons, reasons


def context_block(root):
    lines = [STANDING]
    installed = os.path.exists(protected_root())
    protection = None
    if root is not None:
        if os.path.exists(os.path.join(state_dir(root), "record-failure.json")):
            lines.append(RECORD_FAILURE)
        # One run of the state CLI gives both the verdict state and the protection.
        answer = run_state_cli("context", root)
        protection = _get(answer, "protection")
        cli_state = _get(answer, "state")
        if _valid_state(cli_state):
            state, verified = cli_state, True
        else:
            state, verified = current_state(root, is_registered(root)), False
        if not verified:
            lines.append(FALLBACK)
        if state["status"] == "tampered":
            lines.append(f"{INTEGRITY}: {state['reason']}. Task and continuation calls are refused until the owner clears it.")
        elif state["status"] == "open" and _truthy(state["open"].get("run_started")):
            # Either a job still running or one whose bridge died: no readback, but task work is refused.
            opened = state["open"]
            lines.append(f"A Claude Bridge run ({_text(opened.get('id'))}) started at {_text(opened.get('recorded_at'))} and has not recorded a verdict. "
                         "Task and continuation calls are refused until a review completes; if no bridge job is running, rerun claude_review.")
        elif state["status"] == "open":
            opened = state["open"]
            lines.append(f"Open Claude Bridge verdict {_text(opened.get('id'))} ({_text(opened.get('verdict'))}).")
            lines.append("operator_readback: " + _text(opened.get("operator_readback")))
            required = opened.get("required_of_codex")
            for item in required if isinstance(required, list) else []:
                lines.append("required_of_codex: " + _text(item))
            if _truthy(opened.get("reprimand")):
                lines.append("reprimand: " + _text(opened.get("reprimand")))
            if not _truthy(opened.get("readback_confirmed")):
                lines.append("Readback not yet confirmed. Say operator_readback to the operator verbatim as the message that ends your turn. "
                             "The hook confirms it only from the message that ends a turn; interim commentary is never handed to the hook "
                             "and cannot confirm it, however often it is repeated.")
    elif installed:
        protection = protection_from_cli()
    if installed:
        hooks = _get(protection, "hooks")
        if isinstance(hooks, dict) and isinstance(hooks.get("intact"), bool):
            if not hooks["intact"]:
                reasons = hooks.get("reasons") if isinstance(hooks.get("reasons"), list) else []
                lines.append(f"{NOT_INTACT}: {'; '.join(_text(reason) for reason in reasons)}. "
                             "The bridge refuses to serve until the owner re-trusts or reinstalls its hooks.")
        else:
            # The state CLI cannot run: the hook reads the registration and trust itself.
            intact, reasons = hooks_intact()
            if not intact:
                lines.append(f"{NOT_INTACT}: {'; '.join(reasons)}. The bridge refuses to serve until the owner re-trusts or reinstalls its hooks.")
    return "\n".join(lines)


def handle_context(event, root):
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": context_block(root)}}


def _deny(reason):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}


def is_bridge_call(data):
    """A call to the bridge itself, known by its tool name alone. Codex hands each call a code-mode exec script makes
    to the hooks under that call's own name, so a bridge tool named inside some other call's arguments never counts."""
    name = data.get("tool_name")
    return isinstance(name, str) and name.startswith("mcp__claude_bridge__")


def handle_pre_tool_use(data, root):
    """Bridge calls only. The hook guards no files; the root-owned, immutable install does."""
    if os.path.exists(protected_root()):
        # Best effort: code preloaded into this hook could make it say anything, so it does not vouch for a bridge call.
        if os.environ.get("LD_PRELOAD") or os.environ.get("LD_LIBRARY_PATH"):
            return _deny("Claude Bridge refuses: this hook runs with LD_PRELOAD or LD_LIBRARY_PATH set, so it cannot vouch for the bridge.")
        if not registration_intact():
            return _deny("Claude Bridge registration is not intact. The owner must reinstall the bridge before it can be used.")
        # Codex launches the bridge from its plugin cache entry: refuse when that is not the installed launch config.
        protection = protection_from_cli()
        reasons = _get(protection, "reasons")
        if not isinstance(reasons, list):
            return _deny("Claude Bridge could not check its protected install. The owner must repair or reinstall the bridge.")
        if CACHE_LAUNCH_CONFIG_MISMATCH in reasons:
            return _deny(f"Claude Bridge refuses: {CACHE_LAUNCH_CONFIG_MISMATCH}, so Codex may be launching some other server. "
                         "The owner must reinstall the bridge.")
    if root is not None:
        record_bridge_call(data, root)
    return None


def handle_post_tool_use(data):
    """The readback reminder, only after a bridge result call whose response carries a verdict readback."""
    if data.get("tool_name") != "mcp__claude_bridge__claude_result":
        return None
    response = json.dumps(data.get("tool_response", ""), ensure_ascii=False)
    if "operator_readback" in response:
        return {"systemMessage": "Claude Bridge verdict received. Read operator_readback to the operator verbatim as the message that ends your turn, "
                                 "then comply with required_of_codex. Only the message that ends a turn reaches the hook; interim commentary does not confirm the readback."}
    return None


def transcript_assistant_texts(path):
    """The text of each assistant message in the transcript tail. Its timestamps are the agent's to write and are
    not read."""
    if not isinstance(path, str) or not path:
        return
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - TRANSCRIPT_TAIL_BYTES))
            raw = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return
    for line in raw.split("\n"):
        if '"assistant"' not in line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            continue
        payload = _get(entry, "payload")
        if not _is(_get(entry, "type"), "response_item") or not isinstance(payload, dict):
            continue
        if not _is(payload.get("type"), "message") or not _is(payload.get("role"), "assistant"):
            continue
        parts = payload.get("content") if isinstance(payload.get("content"), list) else []
        yield "\n".join(_text(part.get("text")) for part in parts if isinstance(part, dict))


def ledgered_hashes(root, kind, since):
    """The sha256 of every `kind` record the hook recorded at or after `since` (by the ledger's own recorded_at) in an
    intact turns ledger; empty when the ledger is absent or broken, or `since` is not a timestamp."""
    directory = state_dir(root)
    chain = read_chain(directory, TURNS)
    if not isinstance(since, str) or not chain.exists or not chain_consistent(directory, chain, TURNS):
        return set()
    return {record["sha256"] for record in chain.records
            if _is(record.get("type"), kind) and isinstance(record.get("sha256"), str)
            and isinstance(record.get("recorded_at"), str) and record["recorded_at"] >= since}


def ledgered_readback(root, path, needle, since):
    """A transcript assistant message that carries the readback counts only when its text is one the hook recorded
    from the app (an assistant_message in the turns ledger) at or after the verdict was recorded. A line the agent
    wrote into the session file was never recorded, so it confirms nothing."""
    hashes = ledgered_hashes(root, "assistant_message", since)
    return bool(hashes) and any(needle in normalise(text) and text_sha256(text) in hashes
                                for text in transcript_assistant_texts(path))


def _attempts(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _awaits_readback(state):
    """An open verdict whose readback is not confirmed. A run that never recorded a verdict has nothing to read back."""
    opened = state.get("open") if state.get("status") == "open" else None
    return isinstance(opened, dict) and not _truthy(opened.get("readback_confirmed")) and not _truthy(opened.get("run_started"))


def settle_stop(root, registered, verdict_id, spoken):
    """Under the lock, only the append. The chain is checked again with the hook's own replay, which starts no
    process; anything but the same open verdict awaiting readback is left alone."""
    directory = state_dir(root)
    state = current_state(root, registered)
    if not _awaits_readback(state) or not _same(state["open"].get("id", MISSING), verdict_id):
        return None
    opened = state["open"]
    readback = _text(opened.get("operator_readback"))
    if spoken:
        append_record(directory, _plain({"type": "readback_confirmed", "verdict_id": opened.get("id", MISSING),
                                         "recorded_at": now_iso(), "by": "stop_hook"}), registered)
        if _is(opened.get("verdict"), "corrected"):
            write_open(directory, None)
        else:
            write_open(directory, {**opened, "readback_confirmed": True})
        return None
    attempts = _attempts(opened.get("readback_attempts")) + 1
    write_open(directory, {**opened, "readback_attempts": attempts})
    shown_id = _text(opened.get("id"))
    if attempts <= MAX_BLOCKS:
        return {"decision": "block",
                "reason": f"Claude Bridge verdict {shown_id} has not been read back. Say this to the operator, verbatim, as the message that ends this turn:\n\n"
                          f"{readback}\n\nThen comply with required_of_codex."}
    return {"systemMessage": f"Claude Bridge verdict {shown_id} remains open and unread after {MAX_BLOCKS} blocked stops. "
                             "The bridge refuses further task work until it is read back or the owner clears it."}


def handle_stop(data, root):
    if root is None:
        return None
    registered = is_registered(root)
    message = data.get("last_assistant_message")
    message = message if isinstance(message, str) else ""
    if message and keeps_turns(root, registered):
        record_turn(root, registered, {"type": "assistant_message", "session_id": _optional_text(data.get("session_id")),
                                       "recorded_at": now_iso(), **turn_text("text", message)})
    # The state CLI runs with no lock held. A broken, reset or mismatched chain, or one holding a forged owner
    # clear, is left alone: the bridge refuses work and the owner clears it.
    state, _verified = read_state(root, registered)
    if not _awaits_readback(state):
        return None
    opened = state["open"]
    needle = normalise(_text(opened.get("operator_readback")))
    # Only text the app handed the hook counts: the last assistant message, or a transcript line it recorded.
    spoken = bool(needle) and (needle in normalise(message)
                               or ledgered_readback(root, data.get("transcript_path"), needle, opened.get("recorded_at")))
    try:
        return with_state_lock(state_dir(root), lambda: settle_stop(root, registered, opened.get("id", MISSING), spoken), registered)
    except LockTimeout:
        # Nothing can be recorded, so no attempt is counted: block once, then let the stop through.
        if data.get("stop_hook_active") is True:
            return {"systemMessage": f"Claude Bridge verdict {_text(opened.get('id'))} remains open: its state is locked and the readback "
                                     "could not be recorded. The bridge refuses further task work until it is read back or the owner clears it."}
        return {"decision": "block",
                "reason": "Claude Bridge verdict state is locked; say operator_readback again. Say this to the operator, verbatim, as your reply:\n\n"
                          + _text(opened.get("operator_readback"))}


def handle_user_prompt(data, root):
    """The owner's prompt, as the app hands it, goes into the turns ledger before the context is built."""
    prompt = data.get("prompt")
    if root is not None and isinstance(prompt, str) and prompt:
        registered = is_registered(root)
        if keeps_turns(root, registered):
            body = {"type": "owner_prompt", "session_id": _optional_text(data.get("session_id"))}
            turn = data.get("turn_id")
            if isinstance(turn, str):
                body["turn_id"] = _safe_text(turn)
            body["recorded_at"] = now_iso()
            body.update(turn_text("prompt", prompt))
            record_turn(root, registered, body, min(LEDGER_LOCK_TIMEOUT_MS, lock_timeout_ms()))
    return handle_context("UserPromptSubmit", root)


def dispatch(event, data):
    if event == "PostToolUse":
        return handle_post_tool_use(data)
    if event not in ("SessionStart", "UserPromptSubmit", "PreToolUse", "Stop"):
        return None
    if event == "PreToolUse" and not is_bridge_call(data):
        return None  # every other tool call is Codex's own business
    root = repo_root(working_dir(data))
    if event == "PreToolUse":
        return handle_pre_tool_use(data, root)
    if event == "Stop":
        return handle_stop(data, root)
    if event == "UserPromptSubmit":
        return handle_user_prompt(data, root)
    return handle_context(event, root)


def main():
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return 0
    if not isinstance(data, dict):
        return 0
    event = data.get("hook_event_name")
    try:
        result = dispatch(event, data)
    except Exception as error:  # a bridge call fails closed; every other call and event gets no decision
        result = (_deny(f"Claude Bridge hook could not evaluate this call safely: {type(error).__name__}")
                  if event == "PreToolUse" and is_bridge_call(data) else None)
    if result is not None:
        sys.stdout.buffer.write(json.dumps(result).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
