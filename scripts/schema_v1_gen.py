#!/usr/bin/env python3
"""Generate docs/schema-v1.json from the golden record — the machine truth.

The published schema is DERIVED from tests/goldens/record.jsonl (the shipped
contract the encoders are pinned to). The sync check regenerates this file
and requires byte equality, so the published schema can never drift from
what the binary actually emits.
"""
import json, sys, collections

GOLDEN = "tests/goldens/record.jsonl"
OUT = "docs/schema-v1.json"

# documented block order (the contract: this is the JSONL key order too)
BLOCK_ORDER = ["target", "handshake", "quic", "cert", "pq", "deep", "error"]


def build(ref):
    if isinstance(ref, dict):
        return {
            "type": "object",
            "properties": {k: build(v) for k, v in ref.items()},
            "required": list(ref.keys()),
        }
    if isinstance(ref, list):
        return {"type": "array", "items": build(ref[0]) if ref else {}}
    if isinstance(ref, bool):
        return {"type": "boolean"}
    if isinstance(ref, int):
        return {"type": "integer"}
    if isinstance(ref, str):
        return {"type": "string"}
    return {"type": "null" if ref is None else "string"}


def main():
    lines = [l for l in open(GOLDEN).read().strip().splitlines() if l.strip()]
    rec = json.loads(lines[-1], object_pairs_hook=collections.OrderedDict)

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://pqscan.kalatopi.sh/schema-v1.json",
        "title": "pqscan schema-1 record",
        "description": ("One record per target per pass. Block order is the "
                        "encoders' contract: " + " -> ".join(BLOCK_ORDER) +
                        ". Generated from tests/goldens/record.jsonl; the CI "
                        "schema-sync check regenerates and requires equality."),
        "type": "object",
        "required": ["schema", "mode", "target", "handshake", "quic", "cert", "pq", "error"],
        "properties": {},
    }
    for k in BLOCK_ORDER:
        if k in rec:
            schema["properties"][k] = build(rec[k])
    schema["properties"]["schema"] = {"type": "integer", "const": 1}
    if "ts" in rec:
        schema["properties"]["ts"] = {"type": "string", "format": "date-time"}

    json.dump(schema, open(OUT, "w"), indent=2)
    open(OUT, "a").write("\n")
    print(f"wrote {OUT}: blocks={list(schema['properties'])}")


if __name__ == "__main__":
    sys.exit(main())
