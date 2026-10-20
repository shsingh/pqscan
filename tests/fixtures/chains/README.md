# Chain-cell fixtures (PQ-55, issue #149)

The pinned-capture doctrine: every adapter input dialect is exactly ONE pinned
capture command, carried + version-stamped in its file's header comments; the
fixture is THAT command's captured bytes only (one operand target — scanme.sh,
2026-10-20) — no variants; a tool upgrade re-captures with the same command and
a new stamp in the same cell.

| Fixture | Pinned command | Tool version | Consumed by |
|---|---|---|---|
| `nuclei-findings.jsonl` | `nuclei -l hosts.txt -silent -j` | nuclei v3.11.1 | `-from-nuclei` (the -j findings JSONL: matched-at/url → host:port) |
| `naabu-text.txt` | `naabu -l domains.txt -p 443,8443,465,993 -silent` | naabu 2.6.1 | `-from-naabu` (the host:port text dialect) |
| `httpx-text.txt` | `httpx -silent -ports 443,8443 -p 443,8443 -no-color` (targets on stdin) | httpx v1.12.0 | `-from-httpx` (the text dialect) |
| `httpx-csv.csv` | `httpx -silent -ports 443,8443 -p 443,8443 -no-color -csv` (targets on stdin) | httpx v1.12.0 | today's `-from-httpx` REFUSES these rows: the v1.12.0 `-csv` capture is a 50-column table (first column `timestamp`), not the `url,status` shape; the chains suite pins that documented refusal — the csv direction is out of contract by decision; the boundary stands |

Capture facts (all recorded, never invented): every capture's stderr is empty
and its exit code 0. The nuclei capture holds 28 findings that collapse to two
distinct host:ports (`scanme.sh:443`, `scanme.sh:22`) through the composition's
dedupe; the naabu capture emits two identical result lines (the same dedupe
exercised by a second tool).

Offline by construction: the chain cells in `tests/chains` feed these fixtures
to the PARSERS and feed the loopback TLS fixture to the SCANS — no cell ever
scans a capture's host. subfinder's cell is the no-adapter promise (plain names
pipe through the stdin spec path); masscan's cell stays capture-pending: the
tool is not installed on the capture host (see
[docs/surface-census.md](../../docs/surface-census.md)).
