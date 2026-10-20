# The surface parity census (PQ-52)

The three-way census over the CLI surface: every [spec §8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface)
row ↔ its [USAGE.md](../USAGE.md) row ↔ its implemented state (the
`fs.(Bool|String|Float64|Int)` registration shapes the usage-drift gate greps).
The USAGE↔implemented edge is policed today (`scripts/check_usage_drift.sh`);
this census closes the spec-side edge and adjudicates the planned surface
([scripts/usage-planned-flags.txt](../scripts/usage-planned-flags.txt)) row by
row. Its mechanical cross-check is the spec↔USAGE parity gate
([scripts/check_spec_usage_parity.sh](../scripts/check_spec_usage_parity.sh)).

## How verdicts read

- **EARN** — some §5/§6/§8/§9 contract row needs the flag *and* a
  reference-tool parity line or a chain contract binds it.
- **CUT** — superseded by a shipped sibling, or owned by no contract row.
  A cut leaves the allowlist, the USAGE OPTIONS block and spec §8 together.

Parity claims are **captured help surfaces only** — version-stamped per tool,
captured offline (help/version; no scans — the census never runs a tool against
a target). A missing tool is never a claim: masscan is not installed on the
capture host and its cells say so. No invented behavior anywhere.

## Captures (2026-10-20, offline help/version surfaces)

| Tool | Version | Path | Capture |
|---|---|---|---|
| naabu | 2.6.1 | `~/.go/bin/naabu` | `-version` → `INF Current Version: 2.6.1`; full `-h` |
| httpx | v1.12.0 | `~/.nix-profile/bin/httpx` | `-version` → `INF Current Version: v1.12.0`; full `-h` |
| subfinder | v2.16.0 | `~/.nix-profile/bin/subfinder` | `-version` → `INF Current Version: v2.16.0`; full `-h` |
| nuclei | v3.11.1 | `~/.nix-profile/bin/nuclei` | `-version` → `INF Nuclei Engine Version: v3.11.1`; full `-h` |
| masscan | — | — | **not installed locally — capture pending (no claims made from it)** |

Verbatim capture lines used in the tables below live in the *Reference-tool
parity* column; the full captured help files sit beside this lane's evidence
(issue [#146](https://github.com/shsingh/pqscan/issues/146) comment).

## Table A — the 21 planned rows

| Flag | Verdict | Owning contract | Reference-tool parity (captured) | Boundary / decision note |
|---|---|---|---|---|
| `-c` | EARN | [§7.3 budgets](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#73-budgets-and-fairness-the-numbers-that-make-it-fast-and-safe) + [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) | naabu 2.6.1: `-c int  general internal worker threads (default 25)` · nuclei v3.11.1: `-c, -concurrency int  maximum number of templates to be executed in parallel (default 25)` | the global in-flight ceiling — a distinct knob from the shipped `-threads`, which is the AIMD window's *ceiling*; §7.3's TCP 40k / QUIC 10k in-flight rows own the number |
| `-cidr` | EARN | [§5.1](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#51-targeting-and-discovery) single-target row + §6 masscan chain | none of the five capture a CIDR-in flag (naabu `-host` documents "hosts to scan ports for (comma-separated)"; no CIDR claim) · masscan's `-iL cidrs.txt` is the CIDR-list consumer — **not installed, capture pending** | recognition **ships today**: the grammar parses the CIDR class (internal/grammar, class `cidr` + `Prefix`); per-address expansion is the PQ-16 deferral — a CIDR spec line refuses exit 64 *as a recorded result* ("cidr expansion lands with PQ-16"). The earn case lives at the recognition/expansion boundary; PQ-16 consumes the expansion |
| `-client-fingerprint` | EARN | [§5.4](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#54-handshake-engine-capability-checklist-client-plane) uTLS-preset bullet + [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) | none of the five construct client hellos; the same plane's PD convention is captured: httpx/nuclei `-tlsi, -tls-impersonate` — "enable experimental client hello (ja3) tls impersonation (chrome, or ja3 full string)" | preset names pin the §5.4 set exactly: chrome/firefox/safari/ios/gotls — uTLS preset machinery, not ja3-string replay |
| `-config` | EARN | [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) Config row | all four PD tools carry `-config` (captured: "path to the X configuration file (default $HOME/.config/…/config.yaml)" on naabu/httpx; subfinder/nuclei same shape) | org profiles (default ports, budgets, probes, output path) + `PQSCAN_*` env overrides; precedence CLI > env > profile decides at implementation |
| `-connect-timeout` | EARN | [§7.3](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#73-budgets-and-fairness-the-numbers-that-make-it-fast-and-safe) deadline ladder (connect 2 s) | the chain tools carry the dial wait inside a single `-timeout` (naabu: "millisecond to wait before timing out" — dial-class); none carry the dial/handshake split | §7.3's ladder is three separate budget classes (connect 2 s / handshake 4 s / probe-total 8 s ±20% jitter) — the split is the product, the knob is the dial class |
| `-dns-threads` | EARN | [§5.1](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#51-targeting-and-discovery) reverse-DNS row + [§7.3](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#73-budgets-and-fairness-the-numbers-that-make-it-fast-and-safe) "DNS in-flight 256 (pooled resolver × EWMA)" + [§9](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#9-milestones) M4 | none of the five (their pools are internal) | sizes the SHIPPED PTR resolver pool (4 workers today, LRU of 1024 positives); "PTR storms must not starve handshakes — separate budget" is §7.3's own rationale |
| `-fields` | EARN | [§5.7](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#57-output-and-chainability) Flags row + [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) Output row | the chain tools' field selection rides `-lof, -list-output-fields` ("list of fields to output (comma separated)" — captured on httpx v1.12.0 and naabu 2.6.1); no bare `-fields` at these versions | the contract is output-field selection; the final spelling (bare `-fields` vs the `-lof` shape) resolves at implementation — the USAGE row and registration name must match whatever lands |
| `-http` | EARN | [§5.2](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#52-modes) fast row + [§5.3](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#53-protocol-coverage-matrix) HTTP/1.1 and HTTP/2 rows | httpx is the reference HTTP plane (§6 composes it directly); pqscan's built-in GET already ships as the hint half — the record's `quic.discovered.alt_svc_h3` | §5.3 has two HTTP-plane rows naming the optional single GET probe (status, server header, HSTS, Alt-Svc h3 hint) — an HTTP plane exists, so the flag earns. Today's shipped half is the alt-svc hint collection (internal/discovery, the PQ-25 seam); the planned row's delta: force the probe for raw-IP sweeps (§5.2's documented default leaves it off there) and elevate the response fields (status/HSTS/server header) to recorded observations |
| `-legacy` | EARN | [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) Legacy row + [§5.3](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#53-protocol-coverage-matrix) "SSLv3 via legacy module (opt-in)" | none of the five (the heartbleed/ccs/robot/sslv3 probe family is the nmap-NSE/testssl.sh class — outside the chain set) | the module family is pqscan's own; opt-in, off by default |
| `-p` | EARN | [§5.1](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#51-targeting-and-discovery) Ports row + [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) | naabu: `-port, -p string  ports to scan (80,443, 100-200)` · httpx: `-p, -ports string[]  ports to probe (nmap syntax: eg http:1,2-10,11,https:80)` · masscan `-p` — **not installed, capture pending** | comma lists + ranges; default 443; per-port handshake plan is §5.1's per-port detail |
| `-probe-group` | EARN | [§5.4](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#54-handshake-engine-capability-checklist-client-plane) groups bullet | none of the five (offer-one/observe-accept is the engine's own ladder) | forced supported-groups list — feeds the §7.4 plan from outside the DAG |
| `-probe-sigalgs` | EARN | [§5.4](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#54-handshake-engine-capability-checklist-client-plane) sig-algs bullet | none of the five | spelling cured in §8 (spec row said `-probe-sigalg`; the USAGE row + this allowlist say `-probe-sigalgs` — one spelling everywhere: the planned name, which is what an implementation registers) |
| `-probe-suite` | EARN | [§5.4](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#54-handshake-engine-capability-checklist-client-plane) suites bullet | none of the five | offer exact suite lists (single or sets) on 1.0–1.2 |
| `-probe-version` | EARN | [§5.4](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#54-handshake-engine-capability-checklist-client-plane) versions bullet | none of the five | force exact min/max; send-only-this-version (1.2-era) probes |
| `-quic` | **CUT** | — | — | superseded by the shipped `-quic-always` (override the hint gate) and `-quic-off` (skip the plane): the bare mode flag has no independent reading — the hint-gated default already runs the QUIC plane on a domain's alt-svc hint (record `quic.discovered.alt_svc_h3`, state "skipped: no alt-svc h3 hint" otherwise). No registration exists; §8 Mode row, USAGE row and allowlist row all drop it |
| `-retries` | EARN | [§7.3](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#73-budgets-and-fairness-the-numbers-that-make-it-fast-and-safe) Retries row + [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) | naabu: `-retries int  number of retries for the port scan (default 3)` · httpx: `-retries int  number of retries` · nuclei: `-retries int  number of times to retry a failed request (default 1)` | §7.3 pins semantics: 1, transient-only (RST/timeout), never for protocol rejections — rejections are results |
| `-silent` | EARN | [§5.7](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#57-output-and-chainability) dialect rule + [§8](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#8-cli-surface) Output row + §6 chains | the exact PD convention, captured: subfinder `-silent  show only subdomains in output` · httpx `-silent  silent mode` · nuclei `-silent  display findings only` · naabu `-silent  display only results in output` | scoping decision below |
| `-sorted` | EARN | [§5.7](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#57-output-and-chainability) Flags row + §6 calendar bullet ("pqscan's deterministic ordering (`-sorted`) makes diffs meaningful") | none of the five stream sorted-by-input | buffered, input-ordered output for human review and diff chains |
| `-stats` | EARN | [§9](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#9-milestones) **M1 names `-stats`** + [§5.1](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#51-targeting-and-discovery) "live rate/error view" | nuclei: `-stats  display statistics about the running scan` · subfinder: `-stats  report source statistics` · naabu's is deprecated (captured honestly) | the M1 acceptance row is the binding contract; the USAGE DIAGNOSTICS block already documents the view |
| `-timeout` | EARN | [§7.3](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#73-budgets-and-fairness-the-numbers-that-make-it-fast-and-safe) deadline ladder (handshake 4 s / probe-total 8 s ±20% jitter) | httpx: `-timeout int  timeout in seconds (default 10)` · nuclei: `-timeout int  time to wait in seconds before timeout (default 10)` · subfinder: `-timeout int  seconds to wait before timing out (default 30)` | the handshake+probe classes; today's shipped default is the 8 s per-probe budget with ±20% jitter |
| `-verify` | **CUT** | — | none of the five carries a cert-verification toggle; naabu's `-verify` is a **different flag** ("validate the ports again with TCP verification" — a name collision, not parity) | owned by no §5/§6/§9 contract row: §5.5's certificate plane is the observation chain (full chain parse, zero verification posture — no `VerifyOptions` anywhere in the tree). Re-earns if/when a verification-mode row is specced into §5.5. Leaves the allowlist, the USAGE row and §8's TLS-knobs row (with `-ca-bundle`) together |

## Table B — the §8-only anomalies (rows with no USAGE row and no registration)

Enumerated mechanically: every backticked dash-token in §8 diffed against the
implemented ∪ planned union (the parity gate's own comparison). Two tokens beyond
the five known anomalies surfaced and are adjudicated here the same way:
`-no-color` (zero color/ANSI code anywhere in the tree) and the `-probe-sigalg`
spelling (Table A).

| Flag | Verdict | Owning contract | Reference-tool parity (captured) | Boundary / decision note |
|---|---|---|---|---|
| `-stream` | **CUT** | — | naabu `-stream  stream mode (disables resume, nmap, verify, retries, shuffling, etc)` · httpx `-s, -stream  stream mode - start elaborating input targets without sorting` · nuclei `-stream  stream mode - start elaborating without sorting the input` | the chain tools *toggle into* a stream mode because their default buffers/sorts; pqscan's dialect is the inverse — unordered streaming **is the §5.7 default** (verified live: stdout is results-only, streaming, unsorted), so the flag would re-spell the default. §8 keeps only `-sorted` and documents the default in a sentence |
| `-ja4` | **CUT** | — | none of the five help surfaces carries a ja4 flag; zero ja3/ja4/jarm code anywhere in the tree | §5.4's "JA3/JA4 *of our own hello*" transparency bullet stands untouched, but it is an always-on observer contract (what was sent rides the deep findings and the diagnostics), not a toggle: no contract needs a flag, so the §8 row leaves |
| `-jarm` | EARN | [§5.4](https://github.com/shsingh/pqscan/blob/main/docs/spec.md#54-handshake-engine-capability-checklist-client-plane) "JARM of the server (optional flag)" | **httpx v1.12.0: `-jarm  display jarm fingerprint hash`** (captured); nuclei v3.11.1's help carries no jarm flag — the parity line is httpx's, honestly scoped | the one §8-ghost that earns: a server-side fingerprint hash of the TLS plane §5.4 already probes, with a captured same-semantics reference flag. **Addition**: joins the planned surface (USAGE row + allowlist row) per the documented-ahead convention |
| `-ca-bundle` | **CUT** | — | none of the five | pairs with `-verify`'s cut: one contract ("certificate verification posture"), no owning §5/§6/§9 row, no observation in §5.5 that needs it |
| `-no-ptr` | **CUT** | — | none of the five | re-spells a shipped default: the engine runs *without* PTR enrichment unless `-ptr` is given (the USAGE row documents "default off"; the record's `ptr` stays empty). A counter-spelling is owned by nothing; if `-config` org profiles ever default PTR on, the counter-override is that plane's job |
| `-no-color` | **CUT** | — | the PD convention is real but it colors THEIR tools: naabu/httpx/subfinder all carry `-no-color`/`-nc` (captured) | the pqscan engine has no color plane — captured grep over the whole tree: zero color/ANSI/escape code in the Go sources — so the flag disables nothing; re-earns the day a TTY color plane ships (§5.7's httpx-like text dialect is where it would land) |

## The `-silent` scoping decision

§5.7's dialect rule — "a `--silent` that means *only results*" — is already
true structurally: stdout is results-only, every run (the progress line, the
resume/shard notices and diagnostics ride **stderr**; captured live against the
built binary, 2026-10-20). The PD `-silent` convention, captured on all four
chain tools, is the operator-facing meaning: *only results* on stdout. So
pqscan's planned `-silent` scopes **stderr-side housekeeping only**: it
suppresses the `pqscan:` progress/shard/resume notices and any banner. It never
touches the results stream (already only-results), the per-target error
records (§5.7: an unreachable endpoint is a record, not a failure), the exit-64
usage contract, or the refusal notices a §5.7 dialect rule pins. A bare `-jsonl`
pipe today needs no `-silent` to be pipe-clean — the flag is for operators who
want the run's housekeeping chatter gone.

## The §8 exclusions (negative rows, not surface rows)

§8's Config line documents `-h2c`/`-http2` as **never needed** ("ALPN is
automatic"). Those tokens are negative contracts, not surface rows — the parity
gate excludes exactly those two tokens and prints the exclusion on every run.

## Union-leads-spec (INFO, not drift)

Three implemented rows lead the spec's §8 surface and stay there under the
documented-ahead convention: `-debug`, `-debug-out` (the §8 prose names
diagnostics only indirectly) and `-version`. The parity gate prints them as
INFO lines on every run; §9 M-milestones decide when §8's list grows a row.

## Counts and the cut list (the array lanes' input)

- Planned surface: **21 rows → 19 earned, 2 cut** (`-quic`, `-verify`).
- §8-only anomalies: 6 confirmed → **1 earned** (`-jarm`, added to the planned
  surface), **5 cut** (`-stream`, `-ja4`, `-ca-bundle`, `-no-ptr`, `-no-color`).
- Additions into the planned surface: `-from-nuclei` (the pinned-capture
  doctrine — `nuclei -l hosts.txt -silent -j`, §8 Targeting row + §6 chain) and
  `-jarm` (capture-evidenced, Table B).
- Allowlist arithmetic: 21 − 2 cuts + 2 additions = **21 rows**.
- The final cut list (`-quic`, `-verify`/`-ca-bundle`, `-stream`, `-ja4`,
  `-no-ptr`, `-no-color`) is the input the array lanes (PQ-53/PQ-55, issues
  [#147](https://github.com/shsingh/pqscan/issues/147)–[#150](https://github.com/shsingh/pqscan/issues/150))
  consume for their domain tables' prereq/conflict edges.
