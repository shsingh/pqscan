#!/usr/bin/env bash
# schema-v1 sync: the published schema == the shipped golden contract, forever.
set -euo pipefail
cp docs/schema-v1.json /tmp/schema-v1.published.$$
python3 scripts/schema_v1_gen.py > /dev/null
if ! cmp -s docs/schema-v1.json /tmp/schema-v1.published.$$; then
  echo "FAIL: docs/schema-v1.json drifted from the golden record — re-run scripts/schema_v1_gen.py or fix the encoders" >&2
  diff <(jq -S . /tmp/schema-v1.published.$$) <(jq -S . docs/schema-v1.json) | head -20 >&2 || true
  rm -f /tmp/schema-v1.published.$$; exit 1
fi
rm -f /tmp/schema-v1.published.$$
# every golden record validates: required blocks present, no undeclared blocks
python3 - <<'PYEOF'
import json
REQ = ["schema","mode","target","handshake","quic","cert","pq","error"]
DECL = set(REQ + ["ts","deep"])
for i, ln in enumerate(open("tests/goldens/record.jsonl"), 1):
    rec = json.loads(ln)
    missing = [k for k in REQ if k not in rec]
    undeclared = sorted(set(rec) - DECL)
    if missing or undeclared:
        raise SystemExit(f"FAIL: golden line {i}: missing={missing} undeclared={undeclared}")
print("schema-sync: golden records match the published schema")
PYEOF
