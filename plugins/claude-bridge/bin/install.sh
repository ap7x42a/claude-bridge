#!/bin/bash
# Claude Bridge protected install. First install, as root from a repository checkout: sudo plugins/claude-bridge/bin/install.sh
# Upgrade, from the installed copy: sudo /opt/claude-bridge/current/bin/install.sh --source <checkout>
# Flags: --dry-run (no chown/chattr, prints what it would do; needs --root)  --root DIR (prefix every absolute path; --dry-run only)
#        --repo DIR (repository to register; default: the source checkout, --source or the one holding this script)
#        --no-lock-cache (leave the Codex cache copy owner-writable; the hook then denies every bridge call)  --lock-cache (the default)
#        --owner USER (the owner account, when not run through sudo)
#        --claude-bin FILE (the Claude Code binary to pin; a regular file, not a link; default: ~/.local/bin/claude, then /usr/local/bin, /usr/bin)
#        --source DIR (the repository checkout to install from; how the installed copy upgrades) --allow-dirty (install
#        although plugins/claude-bridge is not clean or the copy is not its committed tree; records clean: no)
#        --self-test-dest-scan DIR (tests only: run the copied-tree scan on DIR and exit; needs --dry-run and CLAUDE_BRIDGE_TEST_MODE=1)
set -euo pipefail
# Root runs only root-owned system binaries: a fixed PATH and interpreter, and no Node options from the caller.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
unset NODE_OPTIONS NODE_PATH
NODE=/usr/bin/node
# One collation and character set for every pattern and sort below, whatever the caller's locale.
export LC_ALL=C
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
# Physical paths: the bridge keys a repository by its realpath.
DRY=0; ROOT=""; REPO=""; LOCK_CACHE=1; OWNER_ARG=""; SELF_TEST_DEST=""; CLAUDE_ARG=""; SOURCE_ARG=""; ALLOW_DIRTY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --root) ROOT="$(cd "${2:?--root needs a directory}" && pwd -P)"; shift ;;
    --repo) REPO="$(cd "${2:?--repo needs a directory}" && pwd -P)"; shift ;;
    --owner) OWNER_ARG="${2:?--owner needs a user}"; shift ;;
    --claude-bin) CLAUDE_ARG="${2:?--claude-bin needs a file}"; case "$CLAUDE_ARG" in /*) ;; *) CLAUDE_ARG="$PWD/$CLAUDE_ARG" ;; esac; shift ;;
    --lock-cache) LOCK_CACHE=1 ;;
    --no-lock-cache) LOCK_CACHE=0 ;;
    --source) SOURCE_ARG="${2:?--source needs a repository checkout}"; shift ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --self-test-dest-scan) SELF_TEST_DEST="$(cd "${2:?--self-test-dest-scan needs a directory}" && pwd -P)"; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done
# Key generation and copies always happen, so a preview must write under its own root.
if [ "$DRY" = 1 ] && [ -z "$ROOT" ]; then echo "--dry-run needs --root DIR: the preview writes its layout under DIR" >&2; exit 2; fi
# Under --root the owner's commands run as the caller; a real install must run them as the owner, so --root is a preview.
if [ -n "$ROOT" ] && [ "$DRY" != 1 ]; then echo "--root is for --dry-run previews only: a real install writes / and runs owner commands as the owner" >&2; exit 2; fi
if [ "$LOCK_CACHE" = 0 ]; then
  echo "warning: --no-lock-cache leaves the Codex cache copy owner-writable; Codex could launch another server from it, so protection reads unprotected (Codex cache launch config is not the installed one) and the hook then denies every bridge call" >&2
fi
if [ -n "$SELF_TEST_DEST" ] && { [ "$DRY" != 1 ] || [ "${CLAUDE_BRIDGE_TEST_MODE:-}" != 1 ]; }; then
  echo "--self-test-dest-scan needs --dry-run and CLAUDE_BRIDGE_TEST_MODE=1" >&2; exit 2
fi
# --source names the checkout to install from; without it the source is the checkout holding this script. Every
# path to the plugin is physical, so no link sits between the checkout and what is copied.
SOURCE=""
if [ -n "$SOURCE_ARG" ]; then
  case "$SOURCE_ARG" in *$'\n'*) echo "refusing to install: the source path contains a newline" >&2; exit 1 ;; esac
  SOURCE="$(cd "$SOURCE_ARG" 2>/dev/null && pwd -P)" || { echo "refusing to install: --source $SOURCE_ARG is not a directory" >&2; exit 1; }
  SRC="$(cd "$SOURCE/plugins/claude-bridge" 2>/dev/null && pwd -P)" || { echo "refusing to install: $SOURCE holds no plugins/claude-bridge" >&2; exit 1; }
  if [ "$SRC" != "$SOURCE/plugins/claude-bridge" ]; then echo "refusing to install: $SOURCE/plugins/claude-bridge is reached through a link" >&2; exit 1; fi
fi
if [ -z "$REPO" ]; then REPO="$(cd "$SRC/../.." && pwd -P)"; fi
OPT="$ROOT/opt/claude-bridge"; ETC="$ROOT/etc/claude-bridge"
# The installed copy would delete its own source (rm -rf "$DEST") and default REPO to a directory under /opt: it
# installs only from a checkout named with --source.
SRC_P="$(cd "$SRC" && pwd -P)"; OPT_P="$OPT"; if [ -d "$OPT" ]; then OPT_P="$(cd "$OPT" && pwd -P)"; fi
case "$SRC_P/" in "$OPT_P"/*) echo "run the installer from a repository checkout, not from the installed copy (or pass --source <checkout>)" >&2; exit 1 ;; esac
# Root writes REPO into the registration and builds paths from strings the owner-writable source produces:
# each is validated before root uses it.
case "$REPO" in /*) ;; *) echo "refusing to install: repository path is not absolute: $REPO" >&2; exit 1 ;; esac
case "$REPO" in *$'\n'*) echo "refusing to install: repository path contains a newline" >&2; exit 1 ;; esac
if [ ! -e "$REPO/.git" ]; then echo "refusing to install: $REPO has no .git; pass --repo <repository checkout>" >&2; exit 1; fi
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then echo "install must run as root (sudo); use --dry-run --root DIR to preview" >&2; exit 1; fi
OWNER_USER="${OWNER_ARG:-${SUDO_USER:-}}"
if [ -n "$OWNER_USER" ]; then
  OWNER_HOME="$(getent passwd "$OWNER_USER" | cut -d: -f6 || true)"
  if [ -z "$OWNER_HOME" ]; then echo "unknown owner account: $OWNER_USER" >&2; exit 1; fi
elif [ "$DRY" = 0 ]; then echo "run through sudo so the owner account is known (or pass --owner USER)" >&2; exit 1
else OWNER_USER="$(id -un)"; OWNER_HOME="$HOME"; fi
if [ ! -x "$NODE" ]; then echo "refusing to install: $NODE is missing; the bridge runs only under it" >&2; exit 1; fi
# The bridge runs as the owner and writes its verdict state and Codex cache, so those are written as the owner, and
# no repository code runs as root.
as_owner() { if [ "$DRY" = 0 ] && [ -z "$ROOT" ] && [ "$OWNER_USER" != root ]; then runuser -u "$OWNER_USER" -- "$@"; else "$@"; fi; }
# Root never reads through a link in the owner-writable source: scan it before reading anything from it.
refuse_links_in() {
  local path found
  for path in "$@"; do
    [ -d "$path" ] || continue
    found="$(find "$path" -type l -print -quit)" || { echo "refusing to install: cannot scan $path for symbolic links" >&2; exit 1; }
    if [ -n "$found" ]; then echo "refusing to install: $found is a symbolic link; remove it and rerun" >&2; exit 1; fi
  done
}
# A copied tree root is about to read: no symlink, and nothing that is not a regular file or directory (FIFO, device,
# socket). Links give the symlink message; everything else the not-a-regular-file message.
scan_tree() {
  local dir="$1" special
  refuse_links_in "$dir"
  special="$(find "$dir" ! -type f ! -type d -print 2>/dev/null | head -n 1 || true)"
  if [ -n "$special" ]; then echo "refusing to install: $special is not a regular file or directory; remove it and rerun" >&2; exit 1; fi
}
refuse_links_in "$SRC"
# Single files root needs from the owner-writable source are read as the owner, so a link swapped in
# after the scan cannot make root read a file the owner could not.
read_source() { as_owner cat -- "$1"; }
VERSION="$(read_source "$SRC/.codex-plugin/plugin.json" | "$NODE" -e 'let s="";process.stdin.on("data",(c)=>{s+=c;}).on("end",()=>console.log(JSON.parse(s).version))')"
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "refusing to install: plugin version is not MAJOR.MINOR.PATCH" >&2; exit 1; fi
if [ -n "$ROOT" ]; then CODEX="$ROOT/.codex"; else CODEX="$OWNER_HOME/.codex"; fi
if [ -n "$ROOT" ]; then STATE="$ROOT/state"; else STATE="$OWNER_HOME/.local/state/claude-bridge"; fi
DEST="$OPT/$VERSION"
OPT_SED="$(printf '%s' "$OPT" | sed 's/[#&\\]/\\&/g')"

run_root() { if [ "$DRY" = 1 ]; then echo "dry-run: skipped $*"; else "$@"; fi; }
unlock() { [ -e "$1" ] && run_root chattr -R -i "$1" 2>/dev/null || true; }
# lock_tree fails as a whole when any step fails, and LOCK_ERROR names the step.
LOCK_ERROR=""
lock_step() { run_root "$@" || { LOCK_ERROR="$* failed"; return 1; }; }
# Files keep an executable bit they carry (the programs, install.sh, the pinned Claude binary): 755; the rest 644.
lock_tree() { lock_step chown -R root:root "$1" && lock_step find "$1" -type d -exec chmod 755 {} + && lock_step find "$1" -type f ! -perm -u+x -exec chmod 644 {} + && lock_step find "$1" -type f -perm -u+x -exec chmod 755 {} + && lock_step find "$1" -type f -exec chattr +i {} +; }
# Root computes the repository key itself (the first 20 hex digits of the SHA-256 of the physical path) and
# refuses when the repository code, which the bridge runs, would key the repository differently.
REPO_KEY="$(printf '%s' "$REPO" | sha256sum | cut -c1-20)"
CODE_KEY="$(as_owner "$NODE" -e 'import(require("url").pathToFileURL(process.argv[1]).href).then(({ repoKey }) => process.stdout.write(repoKey(process.argv[2])))' "$SRC/mcp/verdict.mjs" "$REPO")"
if ! [[ $CODE_KEY =~ ^[0-9a-f]{20}$ ]]; then echo "refusing to install: repository key is not a 20-hex-digit string" >&2; exit 1; fi
if [ "$CODE_KEY" != "$REPO_KEY" ]; then echo "refusing to install: repository key mismatch: the repository code gives $CODE_KEY, root computes $REPO_KEY" >&2; exit 1; fi
# Where the install comes from, read as the owner with --no-replace-objects (so a refs/replace or a corrupted object
# cannot make git report a tree the working files do not have): the checkout's HEAD and the tree of
# plugins/claude-bridge. Every install, first or upgrade, must come from a clean plugin directory: nothing
# uncommitted, untracked or ignored, and no file git status is told to skip (skip-worktree, assume-unchanged). After
# the copy, root checks what it copied against that tree, file by file. --allow-dirty installs anyway, clean: no.
CHECKOUT="${SOURCE:-$(cd "$SRC/../.." && pwd -P)}"
owner_git() { as_owner /usr/bin/git --no-replace-objects -C "$CHECKOUT" "$@"; }
HEAD_SHA="$(owner_git rev-parse --verify --quiet HEAD 2>/dev/null || true)"
TREE_SHA="$(owner_git rev-parse --verify --quiet HEAD:plugins/claude-bridge 2>/dev/null || true)"
OBJECT_FORMAT="$(owner_git rev-parse --show-object-format 2>/dev/null || true)"
if [ "$OBJECT_FORMAT" = sha256 ]; then echo "refusing to install: sha256 repositories are not supported" >&2; exit 1; fi
[[ $HEAD_SHA =~ ^[0-9a-f]{40}$ ]] || HEAD_SHA=""
[[ $TREE_SHA =~ ^[0-9a-f]{40}$ ]] || TREE_SHA=""
case "$OBJECT_FORMAT" in sha1) ;; *) OBJECT_FORMAT="" ;; esac
GIT_OK=1; DIRTY=""; HIDDEN=""; LS_TREE=""; CLEAN="yes"
DIRTY="$(owner_git status --porcelain --ignored -- plugins/claude-bridge 2>/dev/null)" || GIT_OK=0
LS_FILES="$(owner_git ls-files -v -- plugins/claude-bridge 2>/dev/null)" || GIT_OK=0
HIDDEN="$(printf '%s\n' "$LS_FILES" | grep -v -e '^H ' -e '^$' || true)"
LS_TREE="$(owner_git ls-tree -r HEAD:plugins/claude-bridge 2>/dev/null)" || GIT_OK=0
if [ -z "$HEAD_SHA" ] || [ -z "$TREE_SHA" ] || [ -z "$OBJECT_FORMAT" ]; then GIT_OK=0; fi
dirty_or_refuse() {
  if [ "$ALLOW_DIRTY" = 1 ]; then CLEAN="no"; echo "warning: --allow-dirty: $1" >&2; return; fi
  echo "refusing to install: $1; commit or fix them, or pass --allow-dirty:" >&2
  printf '%s\n' "$2" >&2; exit 1
}
if [ "$GIT_OK" = 0 ]; then
  if [ "$ALLOW_DIRTY" != 1 ]; then
    echo "refusing to install: cannot read the Git state of $CHECKOUT as $OWNER_USER; install from a committed checkout, or pass --allow-dirty" >&2; exit 1
  fi
  CLEAN="no"; echo "warning: --allow-dirty: the Git state of $CHECKOUT cannot be read; the install is not verified" >&2
else
  if [ -n "$DIRTY" ]; then dirty_or_refuse "$CHECKOUT has uncommitted, untracked or ignored files in plugins/claude-bridge" "$DIRTY"; fi
  if [ -n "$HIDDEN" ]; then dirty_or_refuse "$CHECKOUT has files in plugins/claude-bridge hidden from git status (skip-worktree or assume-unchanged)" "$HIDDEN"; fi
  echo "installing from $CHECKOUT at $HEAD_SHA (plugins/claude-bridge tree $TREE_SHA)"
fi
# Root's own git, reading no configuration and honouring no replace objects, over its verified copy.
root_git() { env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git --no-replace-objects "$@"; }
# Root never writes through a link: $CODEX and $SRC are owner-writable, so Codex could plant one there. Checked before
# each block that writes, so a link planted mid-install is still caught. $OPT/current is our own link.
refuse_symlinks() {
  local path
  for path in "$CODEX" "$CODEX/hooks.json" "$CODEX/hooks.json.tmp.$$" "$CODEX/plugins" "$CODEX/plugins/cache" \
    "$CODEX/plugins/cache/claude-bridge-local" "$CODEX/plugins/cache/claude-bridge-local/claude-bridge" \
    "$OPT" "$DEST" "$ETC" "$ETC/repos" "$ETC/repos/$REPO_KEY" "$ETC/owner.key" "$ETC/owner.pub"; do
    if [ -L "$path" ]; then echo "refusing to install: $path is a symbolic link; remove it and rerun" >&2; exit 1; fi
  done
  # Inside the source, the cache entry and the live install (cp -R copies a link as a link).
  refuse_links_in "$SRC" "$CODEX/plugins/cache/claude-bridge-local/claude-bridge" "$DEST"
}
# The self-test runs the copied-tree scan on a given directory, where a test can plant a link or a special file.
if [ -n "$SELF_TEST_DEST" ]; then scan_tree "$SELF_TEST_DEST"; echo "install tree scan clean: $SELF_TEST_DEST"; exit 0; fi
# The bridge runs a root-owned copy of the owner's Claude binary, pinned here: exactly one regular file. --claude-bin
# names it; else the fixed candidates ~/.local/bin/claude, /usr/local/bin/claude, /usr/bin/claude, tried as the owner.
# No owner profile, rc file or alias is run. Every test is made as the owner and it is read as the owner, so root
# never tests, changes or reads through a path the owner controls.
CLAUDE_REAL="$CLAUDE_ARG"
if [ -z "$CLAUDE_REAL" ]; then
  for candidate in "$OWNER_HOME/.local/bin/claude" /usr/local/bin/claude /usr/bin/claude; do
    if as_owner test -e "$candidate"; then CLAUDE_REAL="$candidate"; break; fi
  done
fi
case "$CLAUDE_REAL" in *$'\n'*) CLAUDE_REAL="" ;; esac
if [ -z "$CLAUDE_REAL" ] || ! as_owner test -e "$CLAUDE_REAL"; then
  echo "refusing to install: Claude binary not found (${CLAUDE_ARG:-no claude at ~/.local/bin/claude, /usr/local/bin/claude or /usr/bin/claude for $OWNER_USER}); pass --claude-bin FILE" >&2; exit 1
fi
case "$CLAUDE_REAL" in /*) ;; *) echo "refusing to install: the Claude binary path is not absolute: $CLAUDE_REAL" >&2; exit 1 ;; esac
case "$CLAUDE_REAL/" in "$OPT_P"/*) echo "refusing to install: the Claude binary $CLAUDE_REAL is inside the install; pass the owner's own binary" >&2; exit 1 ;; esac
if as_owner test -L "$CLAUDE_REAL"; then echo "refusing to install: the Claude binary $CLAUDE_REAL is a symbolic link; pass the file it points to" >&2; exit 1; fi
if ! as_owner test -f "$CLAUDE_REAL"; then echo "refusing to install: the Claude binary $CLAUDE_REAL is not a regular file" >&2; exit 1; fi
# Never leave a tree unlocked or a staging tree behind, and always restore the owner key to 0400.
KEYGEN=""; STAGE=""; STAGE_LIVE=0; DEST_OLD=""; SWAPPED=0; TMPGIT=""
on_exit() {
  local status=$?
  set +e
  if [ -n "$KEYGEN" ]; then rm -rf "$KEYGEN"; fi
  if [ -n "$TMPGIT" ]; then rm -rf "$TMPGIT"; fi
  if [ -f "$ETC/owner.key" ] && [ ! -L "$ETC/owner.key" ]; then chmod 400 "$ETC/owner.key"; fi
  if [ "$status" = 0 ]; then exit 0; fi
  # A refusal before any staging or swap began leaves nothing to undo: the previous install, if any, is untouched.
  if [ "$STAGE_LIVE" != 1 ] && [ "$SWAPPED" != 1 ] && [ -z "$DEST_OLD" ]; then exit "$status"; fi
  # Abort: remove our staging tree, and if $DEST was moved aside before the new tree landed, restore it.
  if [ "$STAGE_LIVE" = 1 ] && [ -n "$STAGE" ] && [ -e "$STAGE" ]; then unlock "$STAGE"; rm -rf "$STAGE"; fi
  if [ "$SWAPPED" != 1 ] && [ -n "$DEST_OLD" ] && [ -d "$DEST_OLD" ] && [ ! -e "$DEST" ]; then
    mv -T "$DEST_OLD" "$DEST" && DEST_OLD=""
  fi
  # Whatever is live under $DEST is relocked and current points at it; state which tree is live.
  if [ -d "$DEST" ]; then
    lock_tree "$DEST" >/dev/null 2>&1
    ln -sfn "$DEST" "$OPT/current" 2>/dev/null
    echo "install aborted; the previous install is live at $DEST" >&2
  else
    echo "install aborted; no install is live" >&2
  fi
  exit "$status"
}
trap on_exit EXIT

refuse_symlinks
if [ -e "$ETC/owner.key" ] && [ -e "$ETC/owner.pub" ]; then KEY_PRESENT=1
elif [ -e "$ETC/owner.key" ] || [ -e "$ETC/owner.pub" ]; then
  echo "refusing to install: only one of $ETC/owner.key and $ETC/owner.pub exists; remove the half-generated pair and rerun" >&2; exit 1
else KEY_PRESENT=0; fi

echo "installing Claude Bridge $VERSION from $SRC"
mkdir -p "$OPT" "$ETC/repos"

# Build the new tree in a root-only staging directory, verify it, lock it, then swap it into place. The live install
# and $OPT/current are not touched until a verified, locked tree is ready, so a swap never exposes an unverified tree
# and an abort before the swap leaves the previous install in place.
STAGE="$OPT/.staging-$VERSION-$$"
unlock "$STAGE"; rm -rf "$STAGE"
mkdir -m 700 "$STAGE"; STAGE_LIVE=1
cp -R "$SRC/mcp" "$SRC/hooks" "$SRC/bin" "$SRC/.codex-plugin" "$SRC/skills" "$STAGE/"
# Before root reads anything in the copy: refuse a symlink or any non-regular, non-directory entry.
scan_tree "$STAGE"

# The pinned Claude binary: read as the owner into a fresh file root creates, capped so a swap to a device or an
# endless file cannot fill /opt.
mkdir "$STAGE/claude"
CLAUDE_CAP=1073741824
( set -C; as_owner head -c "$CLAUDE_CAP" -- "$CLAUDE_REAL" > "$STAGE/claude/claude" )
if [ "$(stat -c %s "$STAGE/claude/claude")" -ge "$CLAUDE_CAP" ]; then
  echo "refusing to install: the Claude binary $CLAUDE_REAL is $CLAUDE_CAP bytes or larger; pass a real binary with --claude-bin" >&2; exit 1
fi
chmod 755 "$STAGE/claude/claude"
echo "pinned Claude binary $CLAUDE_REAL"

( set -C; read_source "$SRC/.mcp.json" > "$STAGE/.mcp.json.source" )
COPIED_VERSION="$("$NODE" -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).version)' "$STAGE/.codex-plugin/plugin.json" 2>/dev/null || true)"
if [ "$COPIED_VERSION" != "$VERSION" ]; then
  echo "refusing to install: the copied manifest names version ${COPIED_VERSION:-none}, not $VERSION; the staged copy was removed" >&2; exit 1
fi

# Root computes, from its own verified copy, the id of each installed subtree in a root-owned temporary repository.
# These are recorded as installed_tree_*; a corrupted or replaced object in the owner's checkout cannot change them.
TMPGIT="$STAGE.gitdir"; rm -rf "$TMPGIT"
root_stage_git() { env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git --no-replace-objects --git-dir="$TMPGIT" --work-tree="$STAGE" "$@"; }
root_stage_git init -q >/dev/null 2>&1
root_stage_git add -A -- mcp hooks bin .codex-plugin skills
STAGE_TREE="$(root_stage_git write-tree)"
subtree_id() { root_stage_git ls-tree "$STAGE_TREE" | awk -v n="$1" '$2 == "tree" && $4 == n { print $3 }'; }
INSTALLED_MCP="$(subtree_id mcp)"; INSTALLED_HOOKS="$(subtree_id hooks)"; INSTALLED_BIN="$(subtree_id bin)"
INSTALLED_CODEX="$(subtree_id .codex-plugin)"; INSTALLED_SKILLS="$(subtree_id skills)"
MCP_JSON_SRC_ID="$(cd "$STAGE" && root_git hash-object --no-filters -- .mcp.json.source)"
rm -rf "$TMPGIT"; TMPGIT=""

# The per-file comparison against the checkout's own object store (--no-replace-objects): it catches a working-tree
# edit, a skip-worktree file and a copy race. clean: yes means exactly that the copied files matched it.
if [ "$GIT_OK" = 1 ]; then
  EXPECTED="$(printf '%s\n' "$LS_TREE" | awk -F '\t' '{ split($1, f, " "); if (f[2] == "blob" && (f[1] == "100644" || f[1] == "100755")) print f[3] " " $2; else print f[2] ":" f[1] " " $2 }' | grep -E ' (mcp|hooks|bin|\.codex-plugin|skills)/' | LC_ALL=C sort || true)"
  MCP_BLOB="$(printf '%s\n' "$LS_TREE" | awk -F '\t' '$2 == ".mcp.json" { split($1, f, " "); if (f[2] == "blob") print f[3] }')"
  COPIED="$(cd "$STAGE" && find mcp hooks bin .codex-plugin skills ! -type d -print | LC_ALL=C sort)"
  ACTUAL=""
  if [ -n "$COPIED" ]; then
    HASHED="$(cd "$STAGE" && printf '%s\n' "$COPIED" | root_git hash-object --no-filters --stdin-paths)"
    ACTUAL="$(paste -d ' ' <(printf '%s\n' "$HASHED") <(printf '%s\n' "$COPIED") | LC_ALL=C sort)"
  fi
  if [ "$EXPECTED" = "$ACTUAL" ] && [ -n "$MCP_BLOB" ] && [ "$MCP_BLOB" = "$MCP_JSON_SRC_ID" ]; then
    :
  elif [ "$ALLOW_DIRTY" = 1 ]; then
    CLEAN="no"; echo "warning: --allow-dirty: the copied files are not the committed tree; clean: no" >&2
  else
    echo "refusing to install: the copied files are not the committed tree plugins/claude-bridge at $HEAD_SHA; the staged copy was removed. Committed (<) against copied (>):" >&2
    diff <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$ACTUAL") >&2 || true
    if [ "$MCP_BLOB" != "$MCP_JSON_SRC_ID" ]; then echo ".mcp.json: committed ${MCP_BLOB:-none}, copied $MCP_JSON_SRC_ID" >&2; fi
    exit 1
  fi
fi

sed -e "s#\"./mcp/server.mjs\"#\"$OPT_SED/current/mcp/server.mjs\"#" -e "s#\"/opt/claude-bridge/current/mcp/server.mjs\"#\"$OPT_SED/current/mcp/server.mjs\"#" "$STAGE/.mcp.json.source" > "$STAGE/.mcp.json"
rm -f "$STAGE/.mcp.json.source"
# source_commit/source_tree are what the checkout's own object store reported; installed_tree_* are root-computed from
# the copied bytes. clean: yes means the copy matched the checkout's object store, file for file.
printf 'source: %s\nsource_commit: %s\nsource_tree: %s\nclean: %s\ninstalled_tree_mcp: %s\ninstalled_tree_hooks: %s\ninstalled_tree_bin: %s\ninstalled_tree_.codex-plugin: %s\ninstalled_tree_skills: %s\ninstalled_mcp_json_source: %s\n' \
  "$CHECKOUT" "${HEAD_SHA:-unknown}" "${TREE_SHA:-unknown}" "$CLEAN" \
  "$INSTALLED_MCP" "$INSTALLED_HOOKS" "$INSTALLED_BIN" "$INSTALLED_CODEX" "$INSTALLED_SKILLS" "$MCP_JSON_SRC_ID" > "$STAGE/INSTALLED-FROM"
echo "installed subtree ids: mcp $INSTALLED_MCP hooks $INSTALLED_HOOKS bin $INSTALLED_BIN .codex-plugin $INSTALLED_CODEX skills $INSTALLED_SKILLS"
echo "compare these against a trusted clone with: git rev-parse <commit>:plugins/claude-bridge/<sub>"

if [ "$KEY_PRESENT" = 1 ]; then echo "owner key present, kept"; else
  # Both halves are generated aside and moved in, so a crash never leaves a pair that looks complete.
  KEYGEN="$ETC/.keygen.$$"; rm -rf "$KEYGEN"; mkdir -m 700 "$KEYGEN"
  "$NODE" -e 'const {generateKeyPairSync}=require("crypto");const fs=require("fs");const {privateKey,publicKey}=generateKeyPairSync("ed25519");fs.writeFileSync(process.argv[1],privateKey.export({type:"pkcs8",format:"pem"}),{mode:0o400});fs.writeFileSync(process.argv[2],publicKey.export({type:"spki",format:"pem"}),{mode:0o644});' "$KEYGEN/owner.key" "$KEYGEN/owner.pub"
  chmod 400 "$KEYGEN/owner.key"
  mv "$KEYGEN/owner.pub" "$ETC/owner.pub"; mv "$KEYGEN/owner.key" "$ETC/owner.key"; rmdir "$KEYGEN"; KEYGEN=""
  echo "owner key generated at $ETC/owner.key"
fi
cp "$ETC/owner.pub" "$STAGE/owner.pub"
printf '%s\n' "$REPO" > "$ETC/repos/$REPO_KEY"; echo "registered repository $REPO as $REPO_KEY"

# Lock the staging tree, then swap it into place. $OPT/current always points at a verified, locked tree: if $DEST
# exists it is moved aside first and removed only after the new tree is in place and current points at it.
refuse_symlinks
lock_tree "$STAGE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -e "$DEST" ]; then unlock "$DEST"; DEST_OLD="$DEST.old-$STAMP-$$"; mv -T "$DEST" "$DEST_OLD"; fi
mv -T "$STAGE" "$DEST"; STAGE_LIVE=0
ln -sfn "$DEST" "$OPT/current"; SWAPPED=1
if [ -n "$DEST_OLD" ]; then unlock "$DEST_OLD"; rm -rf "$DEST_OLD"; DEST_OLD=""; fi
echo "the live install is $DEST"
# A registered repository always has a chain; start an empty one so its first review does not read as a reset. This
# runs as the owner, so it reads the live tree: the staging directory is root-only and the owner cannot open it.
as_owner /usr/bin/env CLAUDE_BRIDGE_STATE_DIR="$STATE" "$NODE" -e 'import(require("url").pathToFileURL(process.argv[1]).href).then(({ seedState }) => { const r = seedState(process.argv[2]); console.log(r.seeded ? "seeded verdict state" : r.reason ? `verdict state not seeded: ${r.reason}; an owner clear of '"'*'"' resets it` : "verdict state present, kept"); })' "$DEST/mcp/verdict.mjs" "$REPO"
run_root chown -R root:root "$ETC"; run_root chmod 755 "$ETC" "$ETC/repos"; run_root chmod 400 "$ETC/owner.key"

as_owner mkdir -p "$CODEX/plugins/cache/claude-bridge-local/claude-bridge"
# hooks.json is written to a temp file beside it and renamed over it, so a link at the target is replaced, not
# followed. The temp file is opened O_CREAT|O_EXCL|O_NOFOLLOW and written through that descriptor, so a link
# planted at the temp path makes the open fail instead of redirecting the data. Owner and mode are set before
# the rename; chattr refuses links, so a link swapped in after the rename stops the install.
refuse_symlinks
HOOKS_TMP="$CODEX/hooks.json.tmp.$$"
rm -f "$HOOKS_TMP"
"$NODE" -e 'const fs=require("fs");const c=fs.constants;JSON.parse(process.argv[2]);const fd=fs.openSync(process.argv[1],c.O_WRONLY|c.O_CREAT|c.O_EXCL|c.O_NOFOLLOW,0o644);fs.fchmodSync(fd,0o644);fs.writeSync(fd,process.argv[2]+"\n");fs.closeSync(fd);' "$HOOKS_TMP" "$(sed "s#__PROTECTED_ROOT__#$OPT_SED#g" "$DEST/hooks/hooks.template.json")"
run_root chown -h root:root "$HOOKS_TMP"
unlock "$CODEX/hooks.json"
mv -T "$HOOKS_TMP" "$CODEX/hooks.json"
run_root chattr +i "$CODEX/hooks.json"

CACHE="$CODEX/plugins/cache/claude-bridge-local/claude-bridge/$VERSION"
refuse_symlinks
unlock "$CACHE"
if [ "$LOCK_CACHE" = 1 ]; then
  rm -rf "$CACHE"; mkdir -p "$CACHE"
  cp -R "$DEST/.codex-plugin" "$DEST/skills" "$CACHE/"; cp "$DEST/.mcp.json" "$CACHE/.mcp.json"
  lock_tree "$CACHE"
else
  # A cache left root-owned by an earlier locked install: root removes it (rm -rf never follows a link).
  if [ -e "$CACHE" ] && [ "$(stat -c %U "$CACHE")" != "$OWNER_USER" ]; then rm -rf "$CACHE"; fi
  as_owner /bin/bash -c 'set -e; rm -rf "$1"; mkdir -p "$1"; cp -R "$2/.codex-plugin" "$2/skills" "$1/"; cp "$2/.mcp.json" "$1/.mcp.json"' cache "$CACHE" "$DEST"
fi
cat <<EOF
done.
next, as the owner:
  1. open Codex in "$REPO"; when it asks to trust hooks from "$CODEX/hooks.json", trust all five.
  2. run: /usr/bin/node "$OPT/current/bin/claude-bridge" verify "$REPO"
  3. in Codex: ask it to call claude_bridge_status; expect protection: protected.
to clear a verdict: sudo /usr/bin/node "$OPT/current/bin/claude-bridge" clear <verdict-id|*> --reason "<why>" "$REPO"
after the first install, always run clear from $OPT/current/bin; upgrade with: sudo $OPT/current/bin/install.sh --source "$CHECKOUT"
EOF
