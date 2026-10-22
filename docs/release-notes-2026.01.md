# pqscan 2026.01 — the release cut

`2026.01` is the first general-availability cut. The rc series (2026.01-rc1,
rc2, rc3) stays the historical record. One release page carries this cut; the
rc pages remain for the record.

## What this cut carries

- **The QUIC census grows two rungs (PQ-69, merged through the #182 estate).**
  The deep census dials the RFC 9369 (QUIC v2) transport version and completes
  one real HTTP/3 GET through the pinned quic-go stack. The record's
  `h3_direct` claim = the handshake's ALPN answer; the deep findings carry the
  functional h3 verdict beside it. `quic/v2` and `quic/h3-exchange` ride the
  existing QUIC rung gate (-quic-off and an unhinted target stay QUIC-free).
- **The binary size bound = 10,000,000 bytes (10 MB) on both planes
  (PQ-70, PR #186's ledger cure).** The measured rows: linux/amd64 7,581,858 B
  (the CI-pinned go1.26.0 chain), 8,085,664 B (the go1.27.2 host),
  darwin/arm64 7,644,994 B — every row measured live on the merge tree
  `ba89d23`; the gate, the ledger and the site card read one bound.
- **The measured performance: 2,750 h/s aggregate** (W=8, loopback fixture,
  the runner's same-day reading at the census tip; the SLO ≥ 2,500/s/core
  stays green with every run). The site card and this README carry the same
  number.
- **The sites live on their own domains:** pqscan.kalatopi.sh,
  opensase.kalatopi.sh, ai-sec-lab.kalatopi.sh — HTTPS enforced, per-domain
  certificates, the DNS records live.
- **The writing standard (ASD-STE100) rides every user-facing surface:**
  the CLI's help and refusal strings, the -explain prose, the repository
  documents, the site pages. The rendered pages carry no tracking ids.

## The install

The release page carries the per-platform binaries, CHECKSUMS-sha256.txt, and
per-asset attestations. The install paths read INSTALL.md; the examples pin
`2026.01`.

- Homebrew: the tap formula bumps with this cut.
- Source: `go install github.com/shsingh/pqscan/cmd/pqscan@2026.01`

The tag carries a signed annotated object; the publish gate ran the full
strict consistency check at the tagged tree before the dispatch.
