#!/usr/bin/env bash
#
# check-file-integrity.sh — File integrity & encryption checker for Ubuntu/Debian Linux.
#
# Menu-driven tool that can:
#   1. Create a baseline SHA-256 manifest of a folder
#   2. Verify files against that manifest (detects changes/tampering)
#   3. Check encryption/privacy status of files (filesystem encryption + permissions)
#   4. Compute a single file's hash (e.g. to compare with a published checksum)
#
# Usage:  chmod +x check-file-integrity.sh
#         ./check-file-integrity.sh
#
# Requires: bash 4+ (stock on Ubuntu/Debian), coreutils (sha256sum, stat) — nothing else.

set -u

MANIFEST_FILE="IntegrityManifest.csv"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'
GRAY='\033[0;90m'; DARKY='\033[0;33m'; RESET='\033[0m'
# Dumb terminals (non-interactive / pipes) get no color codes
if [ -t 1 ]; then :; else GREEN=''; YELLOW=''; RED=''; CYAN=''; GRAY=''; DARKY=''; RESET=''; fi

# --- helpers -----------------------------------------------------------------

select_path() {
    local prompt="$1" p
    read -r -p "$prompt: " p
    p="${p/#\~/$HOME}"                     # expand a leading ~
    if [ ! -e "$p" ]; then
        printf "${RED}Path not found: %s${RESET}\n" "$p"
        return 1
    fi
    printf '%s\n' "$p"
}

# Relative path of "$2" under root "$1"
relpath() { printf '%s' "${2#"$1"/}"; }

is_encrypted_mount() {
    # True if the path sits on a known encrypted filesystem
    local fs
    fs="$(stat -f -c %T "$1" 2>/dev/null || true)"
    case "$fs" in
        ecryptfs|gocryptfs|f2fs_encrypted) return 0 ;;
    esac
    # Also catch ecryptfs/gocryptfs/mapper entries in the mount table
    if findmnt -no FSTYPE "$1" 2>/dev/null | grep -qE 'ecryptfs|gocryptfs|crypt'; then
        return 0
    fi
    return 1
}

# --- menu actions ------------------------------------------------------------

new_integrity_manifest() {
    local path
    path="$(select_path 'Folder to baseline')" || return 0

    local count i=0 f rel hash size mtime
    count="$(find "$path" -type f 2>/dev/null | wc -l)"

    printf 'Path,SHA256,Size,Modified\n' > "$MANIFEST_FILE"

    while IFS= read -r -d '' f; do
        i=$((i + 1))
        printf '  [%d/%d] %s\r' "$i" "$count" "$f" >&2
        rel="$(relpath "$path" "$f")"
        if ! hash="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"; then
            printf "${GRAY}  Unreadable (in use/locked or permission denied): %s${RESET}\n" "$f" >&2
            continue
        fi
        size="$(stat -c %s "$f" 2>/dev/null || echo '?')"
        mtime="$(stat -c %Y "$f" 2>/dev/null || echo '?')"
        printf '%s,%s,%s,%s\n' "$rel" "$hash" "$size" "$mtime" >> "$MANIFEST_FILE"
    done < <(find "$path" -type f -print0 2>/dev/null)
    printf '%*s\r' 40 '' >&2

    local total
    total=$(( $(wc -l < "$MANIFEST_FILE") - 1 ))
    printf "${GREEN}Baseline saved: %s (%d files).${RESET}\n" "$MANIFEST_FILE" "$total"
}

test_integrity() {
    if [ ! -f "$MANIFEST_FILE" ]; then
        printf "${RED}No manifest found. Create a baseline first (option 1).${RESET}\n"
        return 0
    fi

    local path
    path="$(select_path 'Folder to verify')" || return 0

    local ok=0
    declare -a changed=() missing=() newfiles=()
    declare -A baseline_set=()

    local line rel hash full actual
    while IFS=, read -r rel hash _; do
        [ "$rel" = "Path" ] && continue          # skip header
        full="$path/$rel"
        baseline_set["$rel"]=1
        if [ ! -e "$full" ]; then
            missing+=("$rel"); continue
        fi
        actual="$(sha256sum "$full" 2>/dev/null | cut -d' ' -f1)"
        if [ "$actual" = "$hash" ]; then
            ok=$((ok + 1))
        else
            changed+=("$rel")
        fi
    done < "$MANIFEST_FILE"

    # Reverse pass: files present now but not in the baseline
    while IFS= read -r -d '' f; do
        rel="$(relpath "$path" "$f")"
        [ -z "${baseline_set[$rel]+x}" ] && newfiles+=("$rel")
    done < <(find "$path" -type f -print0 2>/dev/null)

    printf "\n${CYAN}===== INTEGRITY REPORT =====${RESET}\n"
    printf "Verified OK : %d\n" "$ok"

    printf "Changed     : %d\n" "${#changed[@]}"
    for r in "${changed[@]}"; do printf "${YELLOW}  MODIFIED: %s${RESET}\n" "$r"; done

    printf "Missing     : %d\n" "${#missing[@]}"
    for r in "${missing[@]}"; do printf "${RED}  MISSING: %s${RESET}\n" "$r"; done

    printf "New files   : %d\n" "${#newfiles[@]}"
    for r in "${newfiles[@]}"; do printf "${DARKY}  NEW: %s${RESET}\n" "$r"; done

    if [ "${#changed[@]}" -eq 0 ] && [ "${#missing[@]}" -eq 0 ] && [ "${#newfiles[@]}" -eq 0 ]; then
        printf "${GREEN}Result: PASS - all files match the baseline.${RESET}\n"
    else
        printf "${RED}Result: FAIL - differences found above.${RESET}\n"
    fi
}

get_privacy_status() {
    local path
    path="$(select_path 'File or folder to check')" || return 0

    # Filesystem-level encryption info for the target
    local fs rootdev
    fs="$(stat -f -c %T "$path" 2>/dev/null || echo unknown)"
    rootdev="$(findmnt -no SOURCE "$path" 2>/dev/null || echo unknown)"
    printf "\n${CYAN}Filesystem: %s  (device: %s)${RESET}\n" "$fs" "$rootdev"
    if is_encrypted_mount "$path"; then
        printf "${GREEN}On an encrypted filesystem (eCryptfs/gocryptfs).${RESET}\n"
    else
        printf "${GRAY}No per-file encryption layer detected (LUKS full-disk encryption is invisible here).${RESET}\n"
    fi

    printf "\n${CYAN}%-55s %-12s %s${RESET}\n" "FILE" "PERMS" "WORLD-ACCESS"
    local -a items=()
    if [ -f "$path" ]; then
        items=("$path")
    else
        mapfile -d '' items < <(find "$path" -type f -print0 2>/dev/null)
    fi
    local f perms world
    for f in "${items[@]}"; do
        perms="$(stat -c %A "$f")"
        world="$(stat -c %a "$f")"
        if [ "$(( ${world: -1} & 4 ))" -ne 0 ]; then
            printf "${YELLOW}%-55s %-12s world-readable${RESET}\n" "${f:0:55}" "$perms"
        else
            printf "%-55s %-12s ${GRAY}restricted${RESET}\n" "${f:0:55}" "$perms"
        fi
    done
}

get_single_hash() {
    local path hash expected
    path="$(select_path 'File to hash')" || return 0
    if ! hash="$(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)"; then
        printf "${RED}Cannot read file: %s${RESET}\n" "$path"
        return 0
    fi
    printf "${GREEN}SHA-256 : %s${RESET}\n" "$hash"
    read -r -p "Expected hash (Enter to skip): " expected
    if [ -n "$expected" ]; then
        if [ "${hash,,}" = "${expected,,}" ]; then
            printf "${GREEN}MATCH - file integrity confirmed.${RESET}\n"
        else
            printf "${RED}MISMATCH - file has been modified or is not the expected version.${RESET}\n"
        fi
    fi
}

# --- main menu ----------------------------------------------------------------

while true; do
    printf "\n${CYAN}========== FILE INTEGRITY CHECKER ==========${RESET}\n"
    printf " %s | bash %s\n" "$(uname -o 2>/dev/null || uname -s)" "${BASH_VERSION:-?}"
    printf " 1. Create baseline manifest (SHA-256) for a folder\n"
    printf " 2. Verify folder against manifest\n"
    printf " 3. Check encryption/privacy status of files\n"
    printf " 4. Compute/compare a single file hash\n"
    printf " Q. Quit\n"
    read -r -p "Choose an option: " choice
    case "$choice" in
        1) new_integrity_manifest ;;
        2) test_integrity ;;
        3) get_privacy_status ;;
        4) get_single_hash ;;
        [qQ]) break ;;
        *) printf "${GRAY}Invalid option.${RESET}\n" ;;
    esac
done
