#!/usr/bin/env bash
# PQ-52 spec-parity gate: docs/spec.md §8 (CLI surface) <=> the USAGE.md flag
# surface (implemented ∪ planned — the union check_usage_drift.sh polices).
#
# Semantics:
#   1. a spec §8 flag token OUTSIDE the union = the spec names a surface the
#      union does not carry -> listed verbatim, exit 1 (drift);
#   2. a union member ABSENT from §8 = INFO line only: the USAGE surface may
#      lead the spec — that is the documented-ahead convention; §8's §9
#      M-milestone criteria decide when a planned flag's row lands.
#
# Spec token extraction: backticked spans beginning with a dash, over the §8
# block (from the "## 8. CLI surface" heading to the next "## " heading); every
# dash-word inside such a span is a token. The exclusion set below holds §8's
# negative rows (tokens documented as NEVER-needed — parse no flag today by
# design); each hit prints as an exclusion, never as a union member.
#
# Keep the source/planned extraction shapes in sync with
# scripts/check_usage_drift.sh — one parser change lands in both.
#
# Usage: scripts/check_spec_usage_parity.sh [repo-root]
# Exit 0 = aligned (exclusion + INFO lines may print); exit 1 = drift;
# exit 2 = internal error.
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
spec="$root/docs/spec.md"
srcdir="$root/cmd/pqscan"
planned_file="$root/scripts/usage-planned-flags.txt"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# excluded §8 tokens: the never-needed negative rows on the Config line
# (-h2c/-http2, "never needed (ALPN is automatic)")
excluded_tokens=(h2c http2)

# --- spec §8 block
awk '
  /^## 8\. CLI surface/ { on = 1; next }
  on && /^## /           { exit }
  on { print }
' "$spec" > "$tmp/spec8" || true

if [ ! -s "$tmp/spec8" ]; then
  echo "spec-usage-parity: internal error — §8 block not found in $spec" >&2
  exit 2
fi

# flag tokens from §8: dash-word(s) inside backticked spans starting with a dash
awk '
  {
    n = split($0, segs, /`/)
    for (i = 2; i <= n; i += 2) {
      seg = segs[i]
      if (seg !~ /^-/) continue
      m = split(seg, words, /[ \t]+/)
      for (j = 1; j <= m; j++)
        if (words[j] ~ /^-/) print words[j]
    }
  }
' "$tmp/spec8" | sed -E 's/^-*//; s/,$//' | sort -u > "$tmp/spec8_all" || true

# --- the union: implemented ∪ planned (the drift gate's own extraction shapes)
src_flags="$(grep -hE 'fs\.(Bool|String|Float64|Int)\(' "$srcdir"/*.go |
  sed -E 's/.*fs\.(Bool|String|Float64|Int)\("([^"]+)".*/\2/' | sort -u)"
printf '%s\n' "$src_flags" | grep . > "$tmp/src" || true

sed -E 's/^-*//; s/,$//' "$planned_file" | grep -vE '^[[:space:]]*(#|$)' |
  grep . | sort -u > "$tmp/planned" 2>/dev/null || true

{ cat "$tmp/src"; cat "$tmp/planned"; } | sort -u > "$tmp/union"

# --- report exclusions first (never drift): every excluded token §8 carries
printf '%s\n' "${excluded_tokens[@]}" | sort -u > "$tmp/excluded"
comm -12 "$tmp/spec8_all" "$tmp/excluded" > "$tmp/excluded_hits" || true
if [ -s "$tmp/excluded_hits" ]; then
  while IFS= read -r tok; do
    echo "spec-parity: excluded §8 token (never-needed negative row): -$tok"
  done < "$tmp/excluded_hits"
fi
comm -23 "$tmp/spec8_all" "$tmp/excluded" > "$tmp/spec8" || true

drift=0

# 1) spec §8 -> union
spec_outside="$(comm -23 "$tmp/spec8" "$tmp/union")"
if printf '%s' "$spec_outside" | grep -q .; then
  echo "SPEC §8 FLAT TOKENS OUTSIDE source+planned (spec names a surface the union does not carry):"
  printf '%s\n' "$spec_outside"
  drift=1
fi

# 2) union -> spec §8: INFO only (documented-ahead convention)
union_leads="$(comm -13 "$tmp/spec8" "$tmp/union")"
if printf '%s' "$union_leads" | grep -q .; then
  echo "union rows §8 does not name yet (documented-ahead, INFO):"
  printf '%s\n' "$union_leads" | sed 's/^/  - /'
fi

if [ "$drift" = 0 ]; then
  spec_count="$(grep -c . "$tmp/spec8" || true)"
  printf 'spec-usage-parity: clean (§8 = %s flag tokens inside the implemented∪planned union)\n' \
    "$spec_count"
fi
exit "$drift"
