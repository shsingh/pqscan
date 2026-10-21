# Chain-cell fixtures (PQ-55, issue #149)

The pinned-capture rule: every adapter input dialect carries exactly ONE
pinned capture command. The fixture file's header comments carry the
command and the tool version. The fixture holds that command's captured
bytes only — one operand target (scanme.sh, 2026-10-20). No variants. A
tool upgrade re-captures the bytes with the same command; a new stamp goes
into the same cell.

| Fixture | Pinned command | Tool version | Consumed by |
|---|---|---|---|
| `nuclei-findings.jsonl` | `nuclei -l hosts.txt -silent -j` | nuclei v3.11.1 | `-from-nuclei` (the -j findings JSONL: matched-at/url → host:port) |
| `naabu-text.txt` | `naabu -l domains.txt -p 443,8443,465,993 -silent` | naabu 2.6.1 | `-from-naabu` (the host:port text dialect) |
| `httpx-text.txt` | `httpx -silent -ports 443,8443 -p 443,8443 -no-color` (targets on stdin) | httpx v1.12.0 | `-from-httpx` (the text dialect) |
| `httpx-csv.csv` | `httpx -silent -ports 443,8443 -p 443,8443 -no-color -csv` (targets on stdin) | httpx v1.12.0 | today's `-from-httpx` REFUSES these rows: the v1.12.0 `-csv` capture is a 50-column table (first column `timestamp`), not the `url,status` shape; the chains suite pins that documented refusal — the csv direction is out of contract by decision; the boundary stands |

Capture facts, all recorded, none invented: every capture's stderr is
empty; every capture exits 0. The nuclei capture holds 28 findings; the
dedupe collapses them to two host:ports (`scanme.sh:443`, `scanme.sh:22`).
The naabu capture gives two identical result lines; the same dedupe runs on
the second tool's rows.

Offline by construction: the chain cells in `tests/chains` feed these
fixtures to the PARSERS; the scan cells use the loopback TLS fixture. No
cell ever scans a capture's host. The subfinder cell carries the
no-adapter promise: plain names pipe through the stdin spec path. The
masscan cell stays capture-pending: the capture host has no masscan
install (see [docs/surface-census.md](../../docs/surface-census.md)).
