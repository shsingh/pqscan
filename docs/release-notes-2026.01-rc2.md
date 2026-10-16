# pqscan 2026.01-rc2

The successor release candidate to [`2026.01-rc1`](2026.01-rc1.md). rc2 carries the post-rc1 operator wave: the CLI now speaks for itself, the record's human line tells the same story the machine formats carry, the input grammar works the way the Project Discovery chains actually hand off, and the forced PQ ladder is finally visible.

## The CLI speaks for itself

- `-version` prints the stamp and nothing else — no status words, no internal document references: `pqscan 2026.01-rc2`.
- `-h` is a real help for the practitioner: what the tool observes on both planes, the readiness verdict and its HNDL consequence in plain language, the whole implemented surface grouped (descriptions read straight off the registration surface — one source), runnable examples, the real exit codes (0/1/64), and the reading-the-output glossary. Every flag also parses under two dashes (`--word` ≡ `-word`), and the completions + the man page say so.
- `-explain` adds a plain-language block under each target line: the verdict in words (zero-signal scans state that scoring is an error state, not a grade), what the negotiated group means (PQ hybrid / classical / obsolete draft, with the harvest-now-decrypt-later consequence), the certificate layer with the rotation that closes the gap, the QUIC plane, and an error-class hint when nothing negotiated. Deep mode adds the executed plan's reading — counts, the matrix yield rolled up by probe family, and the accepted rows **named** — and pq mode's ladder carries the same reading for the forced offers.

## The record's human line tells the whole truth

The default `-text` line carries the same facts as the machine formats, suffix-appended (existing fields byte-stable):

- `pq=<label>(<score>)` — the readiness verdict on the line
- `deep=<plan>:<N>p/<N>ok/<N>rej` — the executed plan (or forced ladder) counts
- `cert=<sigAlg>/<keyAlg>` with `+pq-sig`/`+pq-key`/`+dual` markers when true — the certificate layer in every mode
- `ptr=` / `sni=` enrichment when present

Rejections stay observations: a refused probe is a result, never an error.

## The input grammar works the way the chains do

- **Implicit piped stdin** — `subfinder -d example.com | pqscan --` still works, and `cat targets.txt | pqscan -jsonl` now works with no marker at all: piped input is the default target source when no `-u`/`-l`/`--`/adapters are given.
- `-l -` — the universal stdin-file alias.
- `scheme://host[:port]` lines parse everywhere the host:port grammar does — the `httpx -silent` handoff flows through the pipe unstripped.
- The full documented chain now runs end to end: `subfinder -d example.com -silent | httpx -silent -p 443 | pqscan -jsonl`.

## The forced PQ ladder is visible

`-mode pq` records what the ladder did: a ladder block in the record (`mode: "pq"`, attempted/ok/rejected + one finding per forced offer — the same shape the deep executor uses) and the counts on the line (`deep=pq:…p/…ok/…rej`). `-mode fast` and `-mode pq` no longer look identical.

## Shell completions

`pqscan -completion bash|zsh` emits deterministic completion scripts covering every implemented flag, the choice values, and file completion where a flag takes a path — install one-liners ride the help, `USAGE.md` and `INSTALL.md`.

## The audit that guards all of the above

`go test ./cmd/pqscan/ -run TestCLISurfaceContract -v` re-checks the whole human-facing surface on every change — per-flag help/man-page/completion coverage, the meta paths, the exit-code table, a live scan with `-explain`, and the gate verdicts — so verifying the CLI never requires cutting a binary.

## Labels and hygiene

Repository labels are `area:*` (the primary axis — every issue files the right area) + `bug` (a genuine operator-facing defect, kept after closure) + the milestone/effort slices; the board's status stays a project field.

---

*Release notes reference: `2026.01-rc1.md`. Attestation: `gh attestation verify <asset> --owner shsingh`; all assets carry SLSA provenance (ADR-0003).*
