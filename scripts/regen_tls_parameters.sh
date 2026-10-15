#!/usr/bin/env bash
# pqscan PQ-18 — IANA TLS Supported Groups regen / drift gate.
#
# Refreshes the committed registry snapshot tests/fixtures/iana/
# tls-parameters-8.csv from the IANA source export. The snapshot is
# versioned data and is never hand-edited (AGENTS.md, registry rule);
# codepoint drift is fixed by running this script, never by surveying
# iana.org. Regenerating touches ONLY tls-parameters-8.csv — the
# malformed-row fixture is a hand-authored test artifact and is never
# machine-replaced.
#
# Usage:
#   scripts/regen_tls_parameters.sh
#       Offline summary of the committed fixture. Default mode: no
#       network, no writes.
#
#   IANA_REGEN=1 scripts/regen_tls_parameters.sh
#       Download the source export, replace the snapshot, print a diff
#       summary. Review and commit the change yourself.
#
#   scripts/regen_tls_parameters.sh --check
#       CI drift gate: download the source export and compare against
#       the committed fixture; exit 1 on drift, 2 on download failure.
#       Exit 0 (fixture current) otherwise.
#
# The drift comparison is data-only: IANA's CRLF line endings and the
# committed provenance '# ' header (which carries the snapshot date) are
# normalized on both sides before comparing, so a stale date line is not
# drift — only changed registry content is.
#
# Source of record:
#   https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
readonly ROOT
readonly FIXTURE="$ROOT/tests/fixtures/iana/tls-parameters-8.csv"
readonly SOURCE_URL="https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv"
readonly PROVENANCE=(
	'# pqscan IANA TLS Supported Groups snapshot (PQ-18).'
	"# Source: $SOURCE_URL"
	'# Snapshot: --SNAP-DATE-- (UTC). Regenerate: IANA_REGEN=1 scripts/regen_tls_parameters.sh'
	'# Format: IANA tls-parameters-8 export (Value,Description,DTLS-OK,Recommended,Reference[,Comment]).'
	'# The loader reads columns 1-5; # comment, blank and header lines and N-M range rows are skipped.'
)

# normalize prints a CSV's data lines in snapshot form: CRLF stripped,
# comment lines dropped. Use "-" to read stdin.
normalize() {
	local src="$1"
	if [[ "$src" == "-" ]]; then
		awk '{ sub(/\r$/, ""); if ($0 !~ /^#/) print }'
	else
		awk '{ sub(/\r$/, ""); if ($0 !~ /^#/) print }' "$src"
	fi
}

# fetch downloads the source export into $1; returns 2 on failure.
fetch() {
	local dest="$1"
	if ! curl -fsSL --retry 3 --connect-timeout 30 -o "$dest" "$SOURCE_URL"; then
		echo "regen_tls_parameters: cannot download $SOURCE_URL" >&2
		return 2
	fi
}

# summarize prints the offline snapshot inventory. No network, no writes.
summarize() {
	echo "IANA TLS Supported Groups — committed snapshot summary (offline)"
	echo "  fixture:      tests/fixtures/iana/tls-parameters-8.csv"
	grep -m1 '^# Source:' "$FIXTURE" | sed 's/^# /  /'
	grep -m1 '^# Snapshot:' "$FIXTURE" | sed 's/^# /  /'
	local header rows entries ranges
	header="$(grep -m1 -E '^Value,' "$FIXTURE")"
	rows="$(normalize "$FIXTURE" | grep -vc -E '^(Value,|$)')"
	entries="$(normalize "$FIXTURE" | grep -c -E '^[0-9]+,')"
	ranges="$(normalize "$FIXTURE" | grep -c -E '^[0-9]+-[0-9]+,')"
	echo "  header:       ${header#Value,}"
	echo "  rows:         $rows data rows ($entries entries + $ranges N-M range rows)"
	echo "  modes:        default = this summary | IANA_REGEN=1 = regen from iana.org | --check = CI drift gate"
}

# check runs the CI drift gate; exits 0 (current), 1 (drift), 2 (download).
check() {
	local tmp difffile
	tmp="$(mktemp)"
	difffile="$(mktemp)"
	trap 'rm -f "$tmp" "$difffile"' EXIT
	fetch "$tmp"
	if diff <(normalize "$tmp") <(normalize "$FIXTURE") >"$difffile"; then
		echo "IANA drift check: OK — committed fixture matches a fresh download (data lines)"
		exit 0
	fi
	echo "IANA drift detected: committed fixture differs from a fresh download of $SOURCE_URL" >&2
	sed -n '1,40p' "$difffile" >&2
	echo "regen: run IANA_REGEN=1 scripts/regen_tls_parameters.sh, review, then commit the snapshot" >&2
	exit 1
}

# regen downloads and replaces the snapshot, printing a diff summary.
regen() {
	local tmp snapshot
	tmp="$(mktemp)"
	snapshot="$(mktemp)"
	trap 'rm -f "$tmp" "$snapshot"' EXIT
	fetch "$tmp"
	if diff -q <(normalize "$tmp") <(normalize "$FIXTURE") >/dev/null; then
		echo "IANA regen: snapshot already current — source data unchanged, fixture untouched"
		exit 0
	fi
	local rows_before rows_after
	rows_before="$(normalize "$FIXTURE" | grep -vc -E '^(Value,|$)')"
	rows_after="$(normalize "$tmp" | grep -vc -E '^(Value,|$)')"

	local snap_date line
	snap_date="$(date -u +%Y-%m-%d)"
	{
		for line in "${PROVENANCE[@]}"; do
			printf '%s\n' "${line/--SNAP-DATE--/$snap_date}"
		done
		normalize "$tmp"
	} >"$snapshot"
	mv "$snapshot" "$FIXTURE"

	echo "IANA regen: replaced $FIXTURE"
	echo "  data rows: $rows_before -> $rows_after"
	echo "  diff summary (review, then commit the snapshot):"
	git -C "$ROOT" diff --stat -- tests/fixtures/iana/tls-parameters-8.csv | sed 's/^/  /'
	{
		git -C "$ROOT" diff -U0 -- tests/fixtures/iana/tls-parameters-8.csv \
			| grep -E '^[+-][0-9A-Za-z]' | sed -n '1,8p' | sed 's/^/    /'
	} || true
	if [[ "$(git -C "$ROOT" diff -U0 -- tests/fixtures/iana/tls-parameters-8.csv | grep -E -c '^[+-][0-9A-Za-z]')" -gt 8 ]]; then
		echo "    ... (truncated; run git -C $ROOT diff -- $FIXTURE for the full change)"
	fi
}

main() {
	case "${1:-}" in
	--check)
		check
		;;
	"" | "-h" | "--help")
		if [[ "${IANA_REGEN:-0}" == "1" ]]; then
			regen
		else
			summarize
		fi
		;;
	*)
		echo "usage: scripts/regen_tls_parameters.sh [--check] (or: IANA_REGEN=1 $0)" >&2
		exit 64
		;;
	esac
}

main "$@"
