pqscan(1)                       pqscan manual                       pqscan(1)

NAME
    pqscan - TLS / QUIC cipher-configuration and post-quantum readiness
    scanner. One static binary enumerating protocol versions, cipher suites,
    key-exchange groups, signature algorithms and certificate properties,
    classifying every observation on a PQC-readiness rubric, and chaining
    with the Project Discovery toolset (subfinder, httpx, naabu, nuclei).

SYNOPSIS
    pqscan [-mode fast|deep|pq|selftest] [-u target | -l list | -cidr range]
           [-p ports] [options]

DESCRIPTION
    pqscan observes the cipher-configuration plane of remote endpoints.
    Two handshake planes:

      TCP : crypto/tls as the negotiation core, uTLS as the
            hello-construction escape hatch (forced group lists, explicit
            key shares, browser fingerprint presets).
      UDP : quic-go carrying TLS 1.3 inside QUIC v1 (h3), with the same
            group-control story.

    Modes (spec §5.2):

      fast : one engineered handshake per target (browser-grade hello,
             hybrid ML-KEM key share preferred); negotiated parameters,
             certificate chain, ALPN, features.
      deep : computed probe plan executed per target (offer-one /
             observe-accept over suites, versions, groups, signature
             algorithms; HRR detection, resumption, 0-RTT checks).
      pq   : forced PQ-group ladder (spec Appendix A codepoints), PQ
             signature and certificate classification, readiness verdict
             with the HNDL risk flag.
      selftest : exercises the local engine stack against an embedded
             instrumented endpoint.

    Rejections are results: an offer the server refuses is recorded as an
    observation, never swallowed as an error.

OPTIONS
    TARGETING
    -u target            Single target: hostname, host:port, ip, ip:port,
                         or scheme://host[:port].
    -l file              Targets from file: newline-separated specs,
                         blank lines skipped (composes with -u; deduped
                         by host:port in order).
    --                   Read target specs from stdin (bare marker after
                         the options; composes with -u and -l; deduped
                         by host:port). CIDR specs refuse with the
                         PQ-16 deferral notice (exit 64) until
                         per-address expansion ships.
    -cidr range          CIDR expansion (e.g. 192.0.2.0/24).
    -p port[,port...]    Ports; default 443. Ranges allowed (8000-8100).
    -from-httpx          httpx-format input lines.
    -from-naabu          naabu host:port input lines.
    -shard i/n           Split the input into n shards and process only
                         shard i (zgrab2-style, for multi-box passes).
    -resume              Resume an interrupted run from the WAL.

    MODES AND PROBES
    -mode m               fast (default) | deep | pq | selftest.
    -deep standard|full   deep plan cap: default <=24 probes per target;
                          full unlocks the complete matrix (~120).
    -quic                 QUIC/h3 probing on domain workloads.
    -quic-always          QUIC probing regardless of Alt-Svc hints.
    -http                 One HTTP probe after the handshake (status,
                          hsts, Alt-Svc; default off for raw IP sweeps).
    -probe-suite suites   Force cipher-suite candidate list.
    -probe-group groups   Force supported-groups list (PQC ladder).
    -probe-sigalgs algs   Force signature-algorithms list.
    -probe-version v      Force protocol version.

    HELLO AND TLS
    -client-fingerprint p   chrome | firefox | safari | ios | gotls
                            (uTLS preset).
    -sni strategy           auto (default) | ptr-then-ip | ip-only |
                            strict-sni (non-matching certs cannot satisfy
                            verdicts, still recorded).
    -ptr / -no-ptr          PTR enrichment for IP targets (default on for
                            domain workflows).
    -timeout secs           Per-probe timeout (default 8s with +-20%% jitter).
    -connect-timeout secs   TCP/UDP connect timeout (default 2s).
    -retries n              Transient-only retries (default 1; protocol
                            rejections never retried).
    -verify / -ca-bundle f  Certificate verification posture.

    PERFORMANCE
    -threads n        Engine worker count.
    -c n              Global in-flight budget (TCP 40k / QUIC 10k ceilings
                      per spec §7.3).
    -rate r           Global rate cap, handshakes/s (default 20k).
    -dns-threads n    DNS resolver pool size.
    -stats            Live progress + rate/error view.

    DIAGNOSTICS
    -debug            Full diagnostics: live human stream on STDERR
                      (engine ladder steps, QUIC handshakes, refusals,
                      classifications, timeouts) + a final readable
                      block; stdout (results) stays clean for pipes.
    -debug-out file   Machine-parsable diagnostics report (schema 1,
                      JSON): run metadata, effective flags, every event.
                      Bug reports and feature requests touching scans
                      REQUIRE this attachment (see the issue templates).

    OUTPUT
    -json, -jsonl, -csv, -urls, -text
                      Output formats (default text, single line per
                      target; JSONL is streaming).
    -o file           Output file (stdout default).
    -fields a,b,c     Field selection.
    -certs-dir dir    Write end-entity PEMs for downstream tools.
    -silent           Only results (no banners/logging).
    -sorted           Buffered, input-ordered output (default streams
                      unordered as targets complete).

    LEGACY MODULE (opt-in; spec §5.2)
    -legacy modules   heartbleed,ccs,robot,sslv3-class probes; off by
                      default.

    CONFIG
    -config file      pqscan.yaml profile (budgets, probes, output).
                      Environment overrides: PQSCAN_*.

EXAMPLES
    subfinder -d example.com -silent | pqscan -mode fast -jsonl -o assets.jsonl

    naabu -l domains.txt -p 443,8443,993 -silent | pqscan -from-naabu -mode fast -jsonl

    masscan -p 443 -iL cidrs.txt --rate=100000 --open-only -oX - \
        | pqscan -shard 1/4 -mode fast -ptr -rate 20000 -jsonl -o shard1.jsonl

    pqscan -l estate.txt -mode pq -jsonl \
        | jq -r 'select(.pq.verdict != "A+" and .pq.verdict != "A") | [.target.host, .pq.verdict] | @tsv'

    cat targets.txt | pqscan -l known.txt -jsonl -o scan.jsonl --

    pqscan -l assets.txt -mode fast -urls | nuclei -silent -tags tls

    Full chaining walk-throughs: see the Recipes page on the site and
    docs/spec.md#6-chaining-reference-implementations.

EXIT STATUS
    0     Scan completed (empty or not; results in the output stream).
    1     Runtime error (engine or system failure).
    2     Flag-parse error.
    64    EX_USAGE: no targets to scan.
    130   Interrupted (Ctrl-C drains before exit; WAL retained).

ENVIRONMENT
    PQSCAN_INTEGRATION=1   Enables the live-network test suite (never
                           enabled in CI).
    PQSCAN_*               Config overrides mirroring -config keys.
    GOMAXPROCS             Engine sizing is read-but-respected; startup
                           probes tune budgets to the machine (spec §7.3).

FILES
    pqscan.yaml     Optional profile: default ports, budgets, probe
                    selections, output path.
    <output>.wal*   Append-only run journal (resume + crash safety;
                    fsync-batched, spec §7.6).

DIAGNOSTICS
    -stats prints: engine rate (handshakes/s), in-flight per plane, error
    taxonomy (timeouts / rejections / alerts), DNS-pool health, breaker
    states (cooled subnets with reasons). A cooled bucket's targets emit
    skipped records with reason - never silent.

    -debug prints the complete decision log: every probe (ladder step,
    QUIC handshake, refusal, classification, timeout, alert) as a line on
    stderr, then a human-readable summary block. -debug-out writes the
    same run as schema-1 JSON (machine triage: jq '.summary', jq '.events'
    filters). Anything wrong with a run - engine errors, odd server
    behaviour, packets/ciphers you did not expect - is IN that record.
    Issue templates REQUIRE `-debug -debug-out diag.json` attachments for
    bugs; feature requests touching scans attach them too.

SEE ALSO
    docs/spec.md (canonical specification), naabu(1), subfinder(1),
    httpx(1), nuclei(1), masscan(8).

AUTHOR
    Shain Singh <shain.singh@owasp.org>

pqscan 0.0.1 (pre-alpha)                                  October 2026
