# PQ-22 differential fixtures — canned reference-tool records (offline CI gate)

Canned outputs of the two reference tools and of pqscan, consumed by the
parity bridge (scripts/differential_bridge.go -> internal/differential.Parity)
through the offline CI gate (.github/workflows/differential.yml). Nothing in
offline CI executes the tools or touches the network — the fixtures ARE the
tool outputs. The live runs that produced them are recorded on issue #45.

## Canonical set (parity holds — bridge exit 0)

Captured live against cloudflare.com:443 on 2026-10-15:

- `gnutls-cli-debug-cloudflare.txt` — gnutls-cli-debug 3.8.13, its fixed
  check battery, verbatim (no `Protocols:`/`Ciphersuites:` summary lines in
  this battery build: the check-verdict table alone carries the parity
  evidence; gnutls contributes no suite observations here).
- `sslyze-cloudflare.json` — sslyze 6.3.1
  (`--certinfo --elliptic_curves --tlsv1_2 --tlsv1_3 --json_out`), distilled
  from the 477 KB live document: NOT_SCHEDULED command keys other than the
  three kept examples dropped, `tls_1_2`'s 136-entry `rejected_cipher_suites`
  list truncated, `certificate_info` trimmed to the leaf of the first
  deployment, `received_certificate_chain` kept verbatim for that leaf; the
  kept keys (versions/suites/curves) are verbatim. Schema-conformant:
  all kept shapes come unchanged from the release output.
- `pqscan-cloudflare.jsonl` — the local build's schema-1 record, verbatim
  (X25519MLKEM768 pq_hybrid, TLS_AES_128_GCM_SHA256, tls-1.3).

Expected parity outcome (exit 0, no Diff rows):

- protocol: all three top out at TLS1.3;
- suite: the negotiated TLS_AES_128_GCM_SHA256 is in sslyze's accepted
  TLS 1.3 list (gnutls contributes no suite evidence in this battery);
- group X25519MLKEM768: pqscan-only probe observation — documented
  exception (spec §10.1: the reference tools cannot construct PQ groups;
  sslyze 6.3.1's EllipticCurves probe never offers the hybrid);
- note rows (exit unaffected): `secp256r1`/`secp384r1`/`x25519` coverage
  gaps — fast mode negotiates one group, so the classical curves sslyze
  accepts have no pqscan-side observation (gnutls's battery additionally
  probes them via its own plane, saying "no" for P-256/P-384 — a
  probe-plane difference between the references, not a pqscan defect);
  `secp521r1` — reference semantic unknown (the taxonomy deliberately does
  not classify P-521; parity never invents a verdict).

## Divergent set (the gate must catch — bridge exit non-zero)

- `sslyze-divergent-hybrid-rejected.json` — same canonical capture with ONE
  edit: the X25519MLKEM768 hybrid moved from `supported_curves` to the front
  of `rejected_curves` (a realistic "server rejects the PQ hybrid" answer:
  gnutls battery and the pqscan record unchanged). The bridge must exit
  non-zero with the row
  `pqscan: X25519MLKEM768 (pq_hybrid) vs sslyze: not accepted` — CI asserts
  that non-exit-0; a zero exit there fails the job (the gate cannot catch).

## The workflow assertions

1. canonical set -> bridge exit 0 (parity holds);
2. divergent set -> bridge exit NON-zero (the gate catches); the workflow
   inverts the check so a zero exit fails the job.
