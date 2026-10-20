#!/usr/bin/env bash
# PQ-34 release gate: verify a release cut against the repo's own consistency.
# Run standalone (the cut's dry run) AND as the publish job's pre-flight.
#
#   usage: scripts/check_release_consistency.sh <tag> [repo-root]
#   exit 0 = consistent; 1 = drift listed; 2 = usage error
#
# Checks, in order:
#   1. TAG SIGNED: git tag -v <tag> (GPG verification; the OWASP key contract).
#   2. REPO-WIDE STALE-REFERENCE SWEEP: tag-shaped strings across README.md,
#      INSTALL.md, USAGE.md, site/*.qmd and the rendered _site (informational).
#      Any reference to a DIFFERENT tag = stale = listed, exit 1. Whitelists:
#        - docs/release-notes-<other>.md (files pin their own version)
#        - the checker's own history comment block
#        - reference-tool capture pins: a bare three-component vx.y.z
#          (digits at the tail) is the version-stamp convention of the
#          captured help surfaces in site/recipes.qmd, not a repo tag
#   3. NOTES FILE PRESENT: docs/release-notes-<tag>.md exists in the tree.
#   4. SITE STATE: quarto render site --quiet succeeds and the rendered
#      index carries the tag where the source does (install examples).
set -euo pipefail

usage() {
  echo "usage: $0 <tag> [repo-root]  # e.g. v0.0.2-alpha" >&2
  exit 2
}
[ $# -ge 1 ] || usage
TAG="$1"; shift || true
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$root"

fail=0

echo "== release gate: $TAG =="

# ---- 1. signed tag -----------------------------------------------------------
# Runner mode (PQSCAN_GATE_SKIP_TAG_VERIFY=1): the CI runner holds no release
# key, so the GPG verification is skipped — precondition for any publish=true
# dispatch is a FULL gate run (this section included) at the key-holding cut
# machine, recorded in the release issue. Default remains strict: local runs
# verify the signature or fail.
if [ "${PQSCAN_GATE_SKIP_TAG_VERIFY:-0}" = "1" ]; then
  echo "1. tag signature: SKIPPED (runner mode — the full gate verified it at the cut machine)"
else
  if git -C "$root" tag -v "$TAG" >/tmp/gate_tag.log 2>&1; then
    echo "1. tag signature: verified ($(grep -m1 -E 'Good signature' /tmp/gate_tag.log || echo 'ok'))"
  else
    echo "1. tag signature: FAILED ($(head -2 /tmp/gate_tag.log | tr '\n' ' '))"
    fail=1
  fi
fi

# ---- 2. stale-reference sweep ------------------------------------------------
# tag-shaped token: vX.Y[.Z][-...]*|YYYY.NN(-...)*|YYYY.MM(.N)*
pattern='(v[0-9]+\.[0-9]+(\.[0-9]+)?[A-Za-z0-9.-]*|[0-9]{4}\.[0-9]{2}([.\-][A-Za-z0-9.]+)*)'
targets=(README.md INSTALL.md USAGE.md)
targets+=(site/*.qmd)
stale="$(mktemp)"
for f in "${targets[@]}"; do
  [ -f "$f" ] || continue
  { grep -oE "$pattern" "$f" 2>/dev/null || true; } | sort -u | while IFS= read -r ref; do
    case "$ref" in
      "$TAG"|*"$TAG"*) : ;;
      # Reference-tool capture pins (site/recipes.qmd version-stamps the
      # captured help surfaces: subfinder v2.16.0 / httpx v1.12.0 /
      # nuclei v3.11.1) are tag-SHAPED but not repo tags: a bare
      # three-component vx.y.z with a digit tail is the capture
      # convention. Annotated repo tags (v0.0.2-alpha) do not match this
      # shape and stay swept.
      v[0-9]*.[0-9]*.[0-9]) : ;;
      *) printf '%s\t%s\n' "$f" "$ref" >> "$stale" ;;
    esac
  done
  # per-line grouping: report (file, ref) pairs only when the ref is not the tag
done
# de-duplicate pairs
if [ -s "$stale" ]; then sort -u "$stale" -o "$stale"; fi
stale_count="$(wc -l < "$stale" | tr -d ' ')"
if [ "${stale_count:-0}" -gt 0 ]; then
  echo "2. stale tag references (file -> old tag):"
  cat "$stale"
  fail=1
else
  echo "2. stale references: none ($TAG is the only tag-shaped string in the release surfaces)"
fi
rm -f "$stale"

# ---- 3. notes file -----------------------------------------------------------
notes="docs/release-notes-$TAG.md"
if [ -f "$notes" ]; then
  echo "3. notes file: $notes present"
else
  echo "3. notes file: MISSING ($notes)"
  fail=1
fi

# ---- 4. site state -----------------------------------------------------------
if command -v quarto >/dev/null; then
  if quarto render site --quiet >/tmp/gate_quarto.log 2>&1; then
    echo "4. site render: clean"
    src_tag_hits="$(grep -roE "$pattern" site/*.qmd 2>/dev/null | grep -c "$TAG" || true)"
    site_tag_hits="$(grep -oE "$pattern" site/_site/index.html 2>/dev/null | grep -c "$TAG" || true)"
    if [ "${src_tag_hits:-0}" -gt 0 ] && [ "${site_tag_hits:-0}" -eq 0 ]; then
      echo "4. site mismatch: source carries $TAG ${src_tag_hits}x, rendered index carries it 0x -- render stale or version dropped"
      fail=1
    else
      echo "4. site/version consistency: source ${src_tag_hits}x, rendered ${site_tag_hits}x"
    fi
  else
    echo "4. site render: FAILED ($(tail -1 /tmp/gate_quarto.log))"
    fail=1
  fi
else
  echo "4. site check: skipped (no quarto on PATH; CI job must provide it)"
fi

# ---- 5. performance freshness (README + site + ledger vs a live re-run) ------
if command -v go >/dev/null; then
  echo "5. performance freshness: re-running the SLO + size suite"
  perf_log="/tmp/gate_perf.log"
  if go test ./internal/microbench/ -run 'SLO|TestSizeSLO|Benchmark' -v > "$perf_log" 2>&1; then
    echo "5. SLO/size suite: PASS"
    # parse the canonical bench line ("-: N negotiated in X.XXs = RATE h/s")
    # for ANY digit count: the previous two patterns assumed a 4+ digit rate
    # (the M0-era machine) — a filtered/taxed host prints a 3-digit rate,
    # both primaries miss, and the old final fallback (the largest 4-6 digit
    # number anywhere in the log) then handed back a size-test byte count
    # (756547) as the "fresh h/s" — demonstrated verbatim in this commit's
    # catch run. No junk fallback: an absent canonical line refuses honestly.
    fresh="$(grep -aoE 'negotiated in [0-9.]+s = [0-9,]+ h/s' "$perf_log" | head -1 | sed -E 's/.*= ([0-9,]+) h\/s/\1/' | tr -d ',' || true)"
    # documented = the SLO row's MEASURED cell (3rd column) in README + site;
    # both surfaces must carry the same number
    readme_perf="$(awk -F'|' '/^\|/ && /handshakes\/s/ {print $4; exit}' README.md | grep -oE '[0-9]([0-9,]+)?[0-9]' | head -1 | tr -d ',' || true)"
    # the site surface carries the measured cell in EITHER of two shapes:
    # the perf TABLE row (the #99 shape) or the info-rich pstat CARD (the
    # #100 shape — the .pnum div whose unit names per-core handshakes).
    # Site-shape PRs silently break the extractor until the next cut (the
    # gate only runs at publish) — so both shapes are understood.
    site_perf="$(awk -F'|' '/^\|/ && /handshakes\/s/ {print $4; exit}' site/index.qmd | grep -oE '[0-9]([0-9,]+)?[0-9]' | head -1 | tr -d ',' || true)"
    if [ -z "${site_perf:-}" ]; then
      site_perf="$(awk '/class="pnum"/ && (/\/s/ || /per core/) { if (match($0, /[0-9][0-9,]*[0-9]/)) { print substr($0, RSTART, RLENGTH); exit } }' site/index.qmd | tr -d ',' || true)"
    fi
    if [ -n "$readme_perf" ] && [ -n "$fresh" ]; then
      lo=$(( readme_perf / 2 )); hi=$(( readme_perf * 2 ))
      if [ "$fresh" -lt "$lo" ] || [ "$fresh" -gt "$hi" ]; then
        echo "5. perf drift: README documents ${readme_perf} h/s, the live re-run measured ${fresh} -- update README + site + ledger (a PR) before the cut can publish"
        fail=1
      else
        echo "5. perf within tolerance: documented ${readme_perf} h/s vs fresh ${fresh}"
      fi
      if [ "$readme_perf" != "$site_perf" ]; then
        echo "5. perf surfaces out of SYNC: README=${readme_perf} site=${site_perf:-MISSING} -- keep the README table and site Performance section on the same numbers"
        fail=1
      else
        echo "5. perf surfaces in sync (README = site)"
      fi
    else
      echo "5. perf surfaces: no documented h/s cell found in README (the SLO row must exist) -- refuse"
      fail=1
    fi
  else
    echo "5. SLO/size suite: FAILED ($(grep -E '^(--- FAIL|FAIL)' "$perf_log" | head -2 | tr '\n' ' '))"
    fail=1
  fi
else
  echo "5. perf check: skipped (no go on PATH; CI job must provide it)"
fi

if [ "$fail" = 0 ]; then
  echo "release gate: PASS ($TAG)"
fi
exit "$fail"
