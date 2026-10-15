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
    GENERAL
    -version          Print the build's version stamp and exit (the
                      release stamp; source builds print the default).

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
    -resume              Resume an interrupted run from the WAL
                         (<output basename>.wal beside -o; targets the
                         journal already holds a record for, keyed by
                         host:port, skip rescanning and their records
                         replay out of the WAL into the output; requires
                         -o because the journal path derives from it).

    MODES AND PROBES
    -mode m               Scan mode: fast (default) | deep | pq.
                          fast = today's single profile handshake.
                          deep = the executed deep plan (spec §7.4): the
                          profile handshake runs first and prunes the
                          plan (a suite/group/version already negotiating
                          is never re-probed), then every planned probe
                          dispatches offer-one (one suite/group/version
                          per handshake) and the executed plan lands in
                          the record's deep block: mode/attempted/ok/
                          rejected + findings[] (probe, result:
                          accepted|rejected|refused|error, detail —
                          rejections are results, verbatim alerts).
                          pq = the forced PQ ladder (4585–4590 RFC 10024
                          hybrids + the obsolete Kyber drafts): the
                          ladder's observations land in the record's
                          handshake block (the first accepted hybrid) and
                          the pq verdict (a draft acceptance = HNDL).
                          (selftest is a planned mode.)
    -deep standard|full   Deep plan cap (-mode deep only): standard
                          (default) caps the plan at <=24 probes per
                          target with the documented prune priority;
                          full unlocks the complete offer-one matrix
                          (~120+): every stdlib suite × version pair
                          (secure AND insecure lists), the forced-group
                          ladders, the full signature-scheme ladder and
                          the feature probes — observed facts never prune
                          it.
    -quic                 QUIC/h3 probing on domain workloads.
    -quic-always          QUIC probing regardless of Alt-Svc hints.
    -quic-off             Skip the QUIC plane probe entirely (TCP-only
                          runs; IP targets).
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
    -threads n        AIMD window ceiling: max target probes in flight;
                      default 1 = the sequential engine (the pre-PQ-23
                      dispatch). The shared window grows one per
                      successful target and halves per probe timeout
                      (spec §7.3).
    -c n              Global in-flight budget (TCP 40k / QUIC 10k ceilings
                      per spec §7.3).
    -rate rps         Probe launches per second through the token-bucket
                      limiter (burst 1; 0 = uncapped, the default: the
                      pre-congestion engine pace. Spec §7.3's 20k/s
                      global cap arrives with the perf suite).
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
    -jsonl, -json        One schema-1 JSON record per line, keys in the
                         pinned order, hand-rolled (no reflection, no
                         encoding/json on the encode path; streaming).
    -csv                 CSV: header row on the first line, then per row
                         target, host, port, ptr, sni, negotiated
                         (codepoint), group_name, group_class, suite,
                         version, alpn, quic_state, quic_group,
                         udp_blocked, cert_sig_alg, cert_sig_pq,
                         cert_key_alg, cert_key_pq, cert_dual, pq_score,
                         pq_label, pq_hndl, pq_summary, error, ts (RFC
                         4180 quoting).
    -urls                The endpoint list: https://host:port, one line
                         per target (chainable into nuclei/httpx).
    -text                One human line per target (the default format:
                         group= class= suite= version= alpn= ...).
    -o file           Output file (stdout default). The run journal rides
                      beside it as <basename>.wal (see FILES).
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
    Scan one host; the default text form (both planes probed):

        $ pqscan -u cloudflare.com
        cloudflare.com:443 group=X25519MLKEM768 class=pq_hybrid \
            suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 alpn=h2 \
            quic_neg=X25519MLKEM768 quic_class=pq_hybrid

    One schema-1 record per line, chain-ready (the verdict and the
    certificate analytics ride every record):

        $ pqscan -u cloudflare.com -jsonl
        {"schema":1,"mode":"fast","target":{"input":"cloudflare.com","host":"cloudflare.com","ip":"","port":443,"ptr":"","sni_used":""},"handshake":{"negotiated":4588,"group_name":"X25519MLKEM768","group_class":"pq_hybrid","suite":"TLS_AES_128_GCM_SHA256","version":"tls-1.3","alpn_neg":"h2"},"quic":{"attempted":true,"state":"negotiated","negotiated":4588,"group_name":"X25519MLKEM768","group_class":"pq_hybrid"},"cert":{"sig_alg":"ecdsa-with-SHA256","sig_pq":false,"key_alg":"ECDSA","key_pq":false,"dual":false},"pq":{"score":40,"label":"pq-partial","hndl":false,"summary":"negotiated_pq_hybrid(+40)"},"error":""}

    Endpoint list for a downstream scanner:

        $ pqscan -u cloudflare.com -urls 2>/dev/null
        https://cloudflare.com:443

    CSV with the full 25-column contract (first row = the header):

        $ pqscan -u cloudflare.com -csv -o assets.csv
        target,host,port,ptr,sni,negotiated,group_name,group_class,suite,version,alpn,quic_state,quic_group,udp_blocked,cert_sig_alg,cert_sig_pq,cert_key_alg,cert_key_pq,cert_dual,pq_score,pq_label,pq_hndl,pq_summary,error,ts
        cloudflare.com,cloudflare.com,443,,,4588,X25519MLKEM768,pq_hybrid,TLS_AES_128_GCM_SHA256,tls-1.3,h2,negotiated,X25519MLKEM768,false,ecdsa-with-SHA256,false,ECDSA,false,false,40,pq-partial,false,negotiated_pq_hybrid(+40),,2026-10-15T10:07:39.971835Z

    Input composition: a target, a file, and the bare -- stdin marker;
    duplicates dedupe by host:port, first occurrence wins. The bare --
    token must follow the options:

        $ echo http://example.org:8443 | pqscan -u cloudflare.com -l known.txt -- -jsonl

    Interruption is a resume point, not a loss. The WAL journal sits
    beside -o; a resume replays completed targets into the output and
    probes only the rest. A SIGKILL loses nothing but the socket:

        $ pqscan -l estate.txt -o scan.jsonl              # interrupted mid-run
        $ pqscan -l estate.txt -o scan.jsonl -resume
        pqscan: resume: WAL scan.wal: 1 of 3 targets already complete; scanning 2
        pqscan: progress: 2/2 targets scanned

    Rejections are results, not errors. An unreachable endpoint emits a
    schema-1 record with the error set; the exit stays 0 (the scan saw
    the target). Nonzero exit = a runtime failure only:

        $ pqscan -u 203.0.113.9:443
        203.0.113.9:443 group=- class=- suite=- version=- error=dial tcp 203.0.113.9:443: i/o timeout

    Diagnostics arm the human stream on stderr and optionally write the
    machine report; bug reports and scan-touching feature requests
    attach both:

        $ pqscan -u cloudflare.com -debug -debug-out diag.json
        $ jq -c '.summary' diag.json
        {"events":8,"errors":0,"warnings":0}

    The chained walk-throughs with real tool output: the site's Recipes
    page; the pipeline contract: docs/spec.md (the chaining sections).

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
