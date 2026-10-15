#!/usr/bin/env bash
# PQ-17 usage-drift gate: the CLI surface documented in USAGE.md and the
# flags defined in cmd/pqscan/*.go must stay reconciled.
#
# Semantics (spec docs/spec.md#8-cli-surface; USAGE.md is authored ahead of
# the engine, so the planned surface lives on an allowlist):
#   1. every flag DEFINED in source must have a row in USAGE.md OPTIONS;
#   2. every row in USAGE.md OPTIONS must be either an implemented flag or
#      a planned flag (scripts/usage-planned-flags.txt — a flag leaves the
#      list when it is implemented);
#   3. anything outside the union = drift, listed verbatim, exit 1.
# The literal `--` row (stdin marker) is documented, not an fs flag; it maps
# to the synthetic token `stdin`.
#
# Usage: scripts/check_usage_drift.sh [repo-root]
# Exit 0 = aligned; exit 1 = drift (rows printed); exit 2 = internal error.
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
usage="$root/USAGE.md"
srcdir="$root/cmd/pqscan"
planned_file="$root/scripts/usage-planned-flags.txt"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# implemented flags, dash-less
src_flags="$(grep -hE 'fs\.(Bool|String|Float64|Int)\(' "$srcdir"/*.go |
  sed -E 's/.*fs\.(Bool|String|Float64|Int)\("([^"]+)".*/\2/' | sort -u)"
printf '%s\n' "$src_flags" | grep . > "$tmp/src" || true

# documented flags from the man-page OPTIONS block; `--` -> `stdin`
awk '
  /^[[:space:]]*OPTIONS/ { on = 1; next }
  on && /^[A-Z#]/        { on = 0 }
  on {
    line = $0
    gsub(/^[ \t]+/, "", line)
    if (line ~ /^--([ \t]|$)/) { print "stdin"; next }
    if (line !~ /^-/) next            # continuation/prose lines are not rows
    n = split(line, toks, /[ \t]+/)
    first = toks[1]
    if (first ~ /,$/) {               # comma-list row: "-json, -jsonl, -csv..."
      gsub(/,$/, "", first); if (first ~ /^-/) print first
      j = 2
      while (j <= n && toks[j] ~ /^-/) {
        gsub(/,$/, "", toks[j]); if (toks[j] ~ /^-/) print toks[j]
        if (toks[j] !~ /,$/) break
        j++
      }
    } else {
      print first
    }
  }
' "$usage" > "$tmp/usage_raw" || true
sed -E 's/^-*//; s/,$//' "$tmp/usage_raw" | sed '/^stdin$/d' | sort -u > "$tmp/usage" || true

# planned-flags allowlist, dash-less
sed -E 's/^-*//; s/,$//' "$planned_file" | grep -vE '^[[:space:]]*(#|$)' |
  grep . | sort -u > "$tmp/planned" 2>/dev/null || true


drift=0

# 1) src -> usage
missing_in_usage="$(comm -23 "$tmp/src" "$tmp/usage")"
if printf '%s' "$missing_in_usage" | grep -q .; then
  echo "FLAGS DEFINED IN SOURCE, MISSING IN USAGE.md:"
  printf '%s\n' "$missing_in_usage"
  drift=1
fi

# 2) usage -> (src | planned)
{ cat "$tmp/src"; cat "$tmp/planned"; } | sort -u > "$tmp/allow"
missing_in_src="$(comm -13 "$tmp/allow" "$tmp/usage")"
if printf '%s' "$missing_in_src" | grep -q .; then
  echo "USAGE.md ROWS OUTSIDE source+planned (unauthorized drift):"
  printf '%s\n' "$missing_in_src"
  drift=1
fi

src_count="$(grep -c . "$tmp/src" || true)"
if [ "${drift:-0}" = 0 ]; then
  echo "usage-drift: clean (${src_count} implemented flags documented; usage = src + planned)"
fi
exit "${drift:-1}"
