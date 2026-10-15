#!/usr/bin/env bash
# PQ-22 second pair: the real-tool differential harness.
#
# Runs BOTH reference tools (gnutls-cli-debug, sslyze) and the local pqscan
# build against TARGET PORT, captures the three outputs under
# out/differential/<host>-<port>/ and feeds the parity bridge
# (scripts/differential_bridge.go -> internal/differential.Parity). The
# script's exit code is the bridge's: non-zero = a PQ-relevant
# disagreement between pqscan and the references (a concrete Diff row).
#
# Acceptance semantics (ADR-0002; spec docs/spec.md#10.1-differential):
#   - the CI gate (.github/workflows/differential.yml) is OFFLINE: it runs
#     the bridge against the canned fixtures under
#     tests/fixtures/differential/ only — CI never touches the network;
#   - this script is the LIVE, env-gated path: it does nothing unless
#     DIFFERENTIAL_LIVE=1, and it SKIPs (verbatim SKIP lines, exit 0) any
#     reference tool missing from PATH; the workflow's live job runs it
#     only against localhost to demonstrate that SKIP on the runner;
#   - the tool versions and all three captured outputs stay on disk under
#     out/differential/ as the audit record (gitignored build artefacts —
#     the issue/PR comments carry the verbatim evidence).
#
# Tool install discipline (recording the real CLIs, not guesses):
#   gnutls-cli-debug — GnuTLS battery client; on this lane it arrives via
#     brew's `gnutls` formula (brew install gnutls); its CLI is
#     `gnutls-cli-debug [-p PORT] HOSTNAME` with `-V` for the fuller
#     battery — there is NO --priority/--logfile; the check battery is
#     fixed. (If a CLT/Xcode-beta license gate blocks brew, the standard
#     reversible hold is: move ~/Applications/Xcode-beta.app aside, install,
#     move it back EXACTLY as found — never delete it.)
#   sslyze — `pipx install sslyze` (a Python with prebuilt nassl wheels is
#     required — the cp3.15 resolver falls back to ancient sslyze that
#     crashes on import; pi 3.13 works); the scan needs
#     `--certinfo --elliptic_curves --tlsv1_2 --tlsv1_3 --json_out FILE`
#     (there is no --cert_in; --cert is a CLIENT certificate flag).
#   sslyze reports its version inside the JSON document (sslyze_version);
#   gnutls-cli-debug reports its banner on stdout.
#
# Usage: scripts/differential_run.sh TARGET [PORT]   (PORT defaults 443)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:?usage: scripts/differential_run.sh TARGET [PORT]}"
port="${2:-443}"

# Env gate: the live harness never runs by default (offline everywhere).
if [ "${DIFFERENTIAL_LIVE:-0}" != "1" ]; then
  echo "SKIP: differential live harness is env-gated — set DIFFERENTIAL_LIVE=1 to run it (offline is the default)"
  exit 0
fi

# Tool-present gates: every reference tool is gated individually, with a
# verbatim SKIP line (exit 0 — absence of a tool is not a failure).
if ! command -v gnutls-cli-debug >/dev/null 2>&1; then
  echo "SKIP: gnutls-cli-debug not found in PATH — differential live harness skipped (install: brew install gnutls)"
  exit 0
fi
if ! command -v sslyze >/dev/null 2>&1; then
  echo "SKIP: sslyze not found in PATH — differential live harness skipped (install: pipx install sslyze)"
  exit 0
fi

outdir="$root/out/differential/${target}-${port}"
mkdir -p "$outdir"

echo "== [1/3] gnutls-cli-debug fixed battery vs ${target}:${port} (stdout -> gnutls-cli-debug.txt)"
gnutls-cli-debug "$target" -p "$port" > "$outdir/gnutls-cli-debug.txt" 2> "$outdir/gnutls-cli-debug.stderr.txt"
gnutls_self_report="$(head -1 "$outdir/gnutls-cli-debug.txt" | tr -d '\n')"
echo "    gnutls-cli-debug: ${gnutls_self_report} (${target}:${port})"

echo "== [2/3] sslyze --certinfo --elliptic_curves --tlsv1_2 --tlsv1_3 --json_out (vs ${target}:${port})"
sslyze --certinfo --elliptic_curves --tlsv1_2 --tlsv1_3 --json_out "$outdir/sslyze.json" \
    "${target}:${port}" > "$outdir/sslyze.console.log" 2>&1
sslyze_ver="$(python3 - "$outdir/sslyze.json" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("sslyze_version", "unknown"))
except Exception:
    print("unknown")
PY
)"
echo "    sslyze: ${sslyze_ver} (${target}:${port})"

echo "== [3/3] pqscan (local build, schema-1 JSONL) vs ${target}:${port}"
go -C "$root" build -o "$root/out/pqscan" "$root/cmd/pqscan"
"$root/out/pqscan" -u "${target}:${port}" -jsonl > "$outdir/pqscan.jsonl" 2> "$outdir/pqscan.stderr.txt"

echo "== [4/4] parity bridge (internal/differential.Parity) — exit non-zero on any PQ-relevant disagreement"
bridge_rc=0
go -C "$root" run ./scripts -pqscan "$outdir/pqscan.jsonl" \
    -gnutls "$outdir/gnutls-cli-debug.txt" -sslyze "$outdir/sslyze.json" \
    | tee "$outdir/parity-rows.txt" || bridge_rc=$?
printf 'versions: %s | sslyze %s\n' "$gnutls_self_report" "$sslyze_ver" > "$outdir/versions.txt"
echo "captured under out/differential/${target}-${port}/ (exit ${bridge_rc})"
exit "$bridge_rc"
