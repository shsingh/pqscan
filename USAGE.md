pqscan                       pqscan manual

NAME
    pqscan - TLS / QUIC cipher-configuration and post-quantum readiness
    scanner. One static binary. The tool reads protocol versions, cipher
    suites, key-exchange groups, signature algorithms and certificate
    properties. A fixed rubric rates every observation on the post-quantum
    readiness scale. The import toolset's forms chain with it (subfinder,
    httpx, naabu, nuclei).

SYNOPSIS
    pqscan [-mode fast|deep|pq|selftest] [-u target | -l list | -cidr range]
           [-p ports] [options]

DESCRIPTION
    pqscan reads the cipher-configuration plane of remote endpoints.
    Two handshake planes:

      TCP : crypto/tls as the negotiation core; uTLS carries the hello
            construction (forced group lists, explicit key shares, browser
            fingerprint presets).
      UDP : quic-go carries TLS 1.3 inside QUIC v1 (h3), with the same
            group control.

    Modes:

      fast : one engineered handshake per target (browser-grade hello,
             hybrid ML-KEM key share preferred); negotiated parameters,
             certificate chain, ALPN, the session features.
      deep : computed probe plan executed per target (offer-one /
             observe-accept over suites, versions, groups, signature
             algorithms; HRR detection, resumption, 0-RTT checks).
      pq   : the forced PQ-group offer set (the registered PQ codepoints),
             PQ signature and certificate classification, the readiness
             rating with the HNDL risk flag.
      selftest : exercises the local engine stack against an embedded
             instrumented endpoint.

    Rejections are results, too: a server that refuses a probe is an
    observation, never an error.

    OPTIONS
    DOUBLE-DASH EQUIVALENCE: every implemented flag parses under both
    dash spellings — a row below written "-mode" spells the same as
    "--mode" (one and two dashes read alike, never a different
    surface), and the letter flags behave identically ("--u" parses
    like "-u", likewise "--l" and "--o"). This preamble is the
    equivalence's one home: it covers every row this block's engine
    implements today (planned rows name flags no build registers yet;
    such a row parses no dash form until an implementation exists), and
    both shell completions offer both spellings for every implemented
    flag.

    GENERAL
    -version          Report the version stamp, then stop (the release
                      stamp; a source build prints the default).
    -completion shell Emit the shell completion script to stdout
                      (bash | zsh); the script comes from the same
                      surface the help renders. Install, zsh:
                      pqscan -completion zsh >
                      /usr/local/share/zsh/site-functions/_pqscan
                      (compinit picks it up on the next shell) — or,
                      for the session: eval
                      "$(pqscan -completion zsh)". Install, bash:
                      source <(pqscan -completion bash), or persist the
                      script in a bash-completion.d drop.

    TARGETING
    -u target            Single target: hostname, host:port, ip, ip:port,
                         or scheme://host[:port]. The scheme strips: here
                         and on -l/--/piped spec lines. A URL path suffix
                         is the -from-httpx adapter's decoration; the
                         plain spec path refuses it and names the
                         adapter.
    -l file              Targets from file: newline-separated specs,
                         blank lines skipped (composes with -u; deduped
                         by host:port in order). The value "-" reads
                         stdin: the explicit stdin-file alias (the
                         nmap -iL - and nuclei -l - convention). The
                         stdin read expands exactly once, even when --
                         composes beside it.
    --                   Read target specs from stdin: the bare marker
                         after the options, AND the implicit default
                         input when a pipe feeds a run with no other
                         target source given (the import-chain
                         convention, e.g. subfinder -silent |
                         pqscan -jsonl). A character device (an
                         interactive terminal, /dev/null) never
                         triggers the implicit read. An empty pipe
                         still refuses exit 64 (nothing to scan). A
                         piped-open never-terminating stdin blocks
                         until the pipe closes: the documented
                         automation hazard. A redirected regular FILE
                         does not trigger the implicit read (that is
                         what -l - and -- are for). Piped spec lines
                         accept scheme://host[:port]. CIDR specs refuse
                         (per-address expansion is not supported; exit
                         64). Deduped by host:port with -u and -l.
    -cidr range          CIDR expansion (e.g. 192.0.2.0/24).
    -p port[,port...]    Ports; default 443. Ranges parse (8000-8100).
    -from-httpx file     httpx text lines: each line is
                         scheme://host:port with an optional URL path
                         suffix — both strip to the host[:port] spec,
                         so bare host:port/host lines parse too
                         (https/443 default). Composes with -u/-l/--
                         under the one dedupe; # comments skip.
                         (a httpx -csv run refuses here per the
                         documented boundary: the pinned text command
                         is the whole httpx import.)
    -from-naabu file     naabu lines: host:port per line, or the
                         ports block — a host line followed by
                         bare-decimal port lines — or the bare host
                         (no ports block: https/443 default).
                         Composes with -u/-l/-- under the one dedupe;
                         # comments skip. A read or parse failure
                         refuses the run named by its flag (exit 64).
    -from-nuclei file    nuclei -j findings JSONL (the pinned capture
                         `nuclei -l hosts.txt -silent -j`): one JSON
                         finding per line; each finding contributes its
                         matched-at host:port (the url field is the
                         fallback where matched-at is empty), scheme and
                         path stripped to host[:port]. The findings
                         enter the ONE composition (-u, -l, -- and the
                         other adapters share), deduped by host:port
                         (findings repeat one host:port; the dedupe
                         collapses); # comments skip. A line that is
                         not a finding (no matched-at/url) or a read
                         failure refuses the run named by its flag
                         (exit 64).
    -shard i/n           Scan only shard i of n (zgrab2-style, for
                         multi-box passes; 1 <= i <= n): the composed
                         targets (post-composition, after the one
                         dedupe) filter to the shard's membership —
                         fnv1a64(host:port) % n == i-1. The n boxes'
                         shards stay disjoint and complete. A target
                         lands in the same shard at a fixed total;
                         keep the total fixed across re-runs. The run
                         notes its slice on stderr: shard i/n: N of M
                         targets.
    -resume              Resume an interrupted run from the WAL
                         (<output basename>.wal beside -o). The
                         journal's targets — keyed by host:port —
                         skip rescanning; their records replay out of
                         the WAL into the output. Requires -o: the
                         journal path derives from it.

    MODES AND PROBES
    -mode m               Scan mode: fast (default) | deep | pq.
                          fast = the single profile handshake.
                          deep = the executed deep plan. The profile
                          handshake runs first and prunes the plan (a
                          suite/group/version already negotiating is
                          never re-probed). Every probe in the plan
                          dispatches offer-one (one suite/group/version
                          per handshake). The executed plan records in
                          the record's deep block: mode/attempted/ok/
                          rejected + findings[] (probe, result:
                          accepted|rejected|refused|error, detail —
                          rejections are results, verbatim alerts).
                          pq = the forced PQ offer set (4585–4590 RFC
                          10024 hybrids + the obsolete Kyber drafts).
                          The offer set's observations record in the
                          record's handshake block (the first accepted
                          hybrid). The per-probe findings ride the
                          record's deep block (mode pq, attempt/ok/
                          rejected + findings[] — the deep executor's
                          shape). A draft acceptance sets HNDL.
                          (selftest is a planned mode.)
    -deep standard|full   Deep plan cap (-mode deep only). standard
                          (default) caps the plan at <=24 probes per
                          target with the documented prune priority.
                          full unlocks the complete offer-one matrix
                          (~120+): every stdlib suite × version pair
                          (the secure AND the insecure lists), the
                          forced-group offer sets, the full
                          signature-scheme set, the feature probes.
                          Observed facts never prune it.
    -quic-always          The QUIC probe runs regardless of the Alt-Svc
                          hints (the hint gate's override).
    -quic-off             Skip the QUIC plane probe entirely (TCP-only
                          runs; IP targets).
    -http                 One HTTP probe after the handshake (status,
                          hsts, Alt-Svc; default off for raw IP sweeps).
    -probe-suite suites   Force cipher-suite candidate list.
    -probe-group groups   Force supported-groups list (the PQ offer
                          set).
    -probe-sigalgs algs   Force signature-algorithms list.
    -probe-version v      Force protocol version.
    -jarm                 JARM server-fingerprint hash (a planned
                          optional probe; the captured convention is
                          httpx's -jarm).

    HELLO AND TLS
    -client-fingerprint p   chrome | firefox | safari | ios | gotls
                            (uTLS preset).
    -sni strategy           auto (default) | ptr-then-ip | ip-only:
                          the SNI candidate rule for the IP targets
                          when -ptr is set. ptr-then-ip/auto prefer the
                          PTR-derived name; the fallback is the literal
                          when the PTR is missing or unshaped. ip-only
                          always uses the literal. The record's
                          sni_used carries the candidate actually used.
                          strict-sni (non-matching certs cannot satisfy
                          a readiness rating; the records still carry
                          them) remains planned.
    -ptr                  PTR enrichment for IP targets: each IP
                          literal's reverse DNS resolves pre-probe (the
                          pooled system resolver: 4 workers, a 2s
                          budget, a 1024-entry LRU of positives). The
                          -sni strategy applies; the record's ptr and
                          sni_used fill. Hostname targets never consult
                          the pool (their SNI is the host). Default
                          off: an IP target's SNI stays the bare
                          literal without the flag.
    -timeout secs           Per-probe timeout (default 8s with +-20%% jitter).
    -connect-timeout secs   TCP/UDP connect timeout (default 2s).
    -retries n              Transient-only retries (default 1; protocol
                            rejections never retried).

    PERFORMANCE
    -threads n        AIMD window ceiling: max target probes in flight;
                      default 1 = the sequential engine. The shared
                      window grows one per successful target and halves
                      per probe timeout.
    -c n              Global in-flight budget (TCP 40k / QUIC 10k
                      ceilings).
    -rate rps         Probe launches per second through the token-bucket
                      limiter (burst 1; 0 = uncapped, the default). The
                      20k/s global rate cap is the perf suite's cap.
    -dns-threads n    DNS resolver pool size.
    -stats            Live progress + rate/error view.

    DIAGNOSTICS
    -debug            Full diagnostics: the human stream prints to
                      stderr (the probe events, the QUIC handshakes,
                      the refusals, the classifications, the timeouts)
                      + a final readable block; stdout (results) stays
                      clean for pipes.
    -debug-out file   Machine-parsable diagnostics report (schema 1,
                      JSON): run metadata, effective flags, every
                      event. Bug reports and scan-related feature
                      requests carry this attachment (see the issue
                      templates).

    OUTPUT
    -jsonl, -json        One schema-1 JSON record per line; keys in the
                         pinned order; the encoder carries no
                         reflection and no encoding/json; the output
                         streams.
    -csv                 CSV: header row on the first line, then per
                         row target, host, port, ptr, sni, negotiated
                         (codepoint), group_name, group_class, suite,
                         version, alpn, quic_state, quic_group,
                         udp_blocked, cert_sig_alg, cert_sig_pq,
                         cert_key_alg, cert_key_pq, cert_dual, pq_score,
                         pq_label, pq_hndl, pq_summary, error, ts (RFC
                         4180 quoting).
    -urls                The endpoint list: https://host:port, one line
                         per target (chains into nuclei/httpx).
    -text                One human line per target (the default
                        format: group= class= suite= version= alpn= ...).
                        The format-parity tails ride when present:
                        deep=<plan>:<N>p/<N>ok/<N>rej (the executed
                        plan's counts; -mode pq rides the same tail as
                        deep=pq:<N>p/<N>ok/<N>rej); cert=<sigAlg>/
                        <keyAlg> with +pq-sig/+pq-key/+dual markers
                        when true; the ptr=/sni= enrichment; and the
                        readiness rating as pq=<label>(<score>).
    -explain             Under each -text line, a plain-language
                         reading of the record: the rating in words,
                         the negotiated group and its class, the
                         certificate and the QUIC planes, and the
                         error-class hint when nothing negotiates.
                         Text output only; the machine formats refuse
                         it (exit 64).
    -o file           Output file (stdout default). The run journal
                      stays beside it as <basename>.wal (see FILES).
    -fields a,b,c     Field selection.
    -certs-dir dir    Write each scanned host's end-entity certificate
                      as PEM to <dir>/<host>.pem (the profile
                      handshake's leaf bytes). One file per host,
                      overwritten per host; best-effort: a write
                      failure warns in the diagnostics; the scan
                      continues.
    -silent           Only results (no banners/logging).
    -sorted           Buffered, input-ordered output (default streams
                      unordered as targets complete).

    LEGACY MODULE (opt-in)
    -legacy modules   heartbleed,ccs,robot,sslv3-class probes; off by
                      default.

    CONFIG
    -config file      pqscan.yaml profile (budgets, probes, output).
                      Environment overrides: PQSCAN_*.

EXAMPLES
    Scan one host; the default text form (both planes probed):

        $ pqscan -u google.com
        google.com:443 group=X25519MLKEM768 class=pq_hybrid suite=TLS_AES_128_GCM_SHA256 version=tls-1.3 alpn=h2 quic_neg=X25519MLKEM768 quic_class=pq_hybrid cert=ecdsa-with-SHA256/ECDSA pq=pq-partial(40)

    One schema-1 record per line, chain-ready (the rating and the
    certificate analytics ride every record):

        $ pqscan -u google.com -jsonl
        {"schema":1,"mode":"fast","target":{"input":"google.com","host":"google.com","ip":"","port":443,"ptr":"","sni_used":""},"handshake":{"negotiated":4588,"group_name":"X25519MLKEM768","group_class":"pq_hybrid","suite":"TLS_AES_128_GCM_SHA256","version":"tls-1.3","alpn_neg":"h2"},"quic":{"attempted":true,"state":"negotiated","negotiated":4588,"group_name":"X25519MLKEM768","group_class":"pq_hybrid","discovered":{"alt_svc_h3":true,"h3_direct":true}},"cert":{"sig_alg":"ecdsa-with-SHA256","sig_pq":false,"key_alg":"ECDSA","key_pq":false,"dual":false},"pq":{"score":40,"label":"pq-partial","hndl":false,"summary":"negotiated_pq_hybrid(+40)"},"error":""}

    Endpoint list for a downstream scanner:

        $ pqscan -u google.com -urls
        https://google.com:443

    CSV with the full 25-column contract (first row = the header):

        $ pqscan -u google.com -csv -o assets.csv
        target,host,port,ptr,sni,negotiated,group_name,group_class,suite,version,alpn,quic_state,quic_group,udp_blocked,cert_sig_alg,cert_sig_pq,cert_key_alg,cert_key_pq,cert_dual,pq_score,pq_label,pq_hndl,pq_summary,error,ts
        google.com,google.com,443,,,4588,X25519MLKEM768,pq_hybrid,TLS_AES_128_GCM_SHA256,tls-1.3,h2,negotiated,X25519MLKEM768,false,ecdsa-with-SHA256,false,ECDSA,false,false,40,pq-partial,false,negotiated_pq_hybrid(+40),,2026-10-21T10:53:17.05691Z

    Input composition: a target, a file, and the bare -- stdin marker;
    duplicates dedupe by host:port, first occurrence wins. The bare --
    token must follow the options. Piped spec lines accept
    scheme://host[:port]. The pipe is the implicit input when no other
    target source is given:

        $ echo https://example.org:8443 | pqscan -u google.com -l known.txt -jsonl --

    Interruption is a resume point, not a loss. The WAL journal stays
    beside -o; a resume replays the completed targets into the output
    and probes only the rest. A SIGKILL keeps every record; only the
    in-flight socket goes:

        $ pqscan -l targets.txt -o scan.jsonl              # interrupted mid-run
        $ pqscan -l targets.txt -o scan.jsonl -resume
        pqscan: resume: WAL scan.wal: 1 of 3 targets already complete; scanning 2
        pqscan: progress: 2/2 targets scanned

    Rejections are results, not errors. An unreachable endpoint emits a
    schema-1 record with the error set; the exit stays 0 (the scan saw
    the target). Nonzero exit = a runtime failure only:

        $ pqscan -u 203.0.113.9:443
        203.0.113.9:443 group=- class=- suite=- version=- cert=-/- error=dial tcp 203.0.113.9:443: i/o timeout

    Diagnostics arm the human stream on stderr and optionally write the
    machine report; bug reports and scan-related feature requests carry
    both:

        $ pqscan -u google.com -debug -debug-out diag.json
        $ jq -c '.summary' diag.json
        {"events":9,"errors":0,"warnings":0}

    The chained walk-throughs with real tool output: the site's Recipes
    page.

EXIT STATUS
    0     Scan completed (empty or not; results in the output stream).
    1     Runtime error (engine or system failure).
    64    EX_USAGE: a command-line mistake refused before any scan
          (flag-parse errors, no targets, unknown -mode/-deep/-sni, a
          bogus -shard spec, -resume without -o, -explain under a
          machine output format).
    130   Interrupted (Ctrl-C drains before exit; WAL retained).

ENVIRONMENT
    PQSCAN_INTEGRATION=1   Enables the live-network test suite (never
                           enabled in CI).
    PQSCAN_*               Config overrides mirroring -config keys.
    GOMAXPROCS             Engine sizing is read-but-respected; startup
                           probes tune budgets to the machine.

FILES
    pqscan.yaml     Optional profile: default ports, budgets, probe
                    selections, output path.
    <output>.wal*   Append-only run journal (resume + crash safety;
                    fsync-batched).

DIAGNOSTICS
    -stats prints: engine rate (handshakes/s), in-flight per plane, error
    taxonomy (timeouts / rejections / alerts), DNS-pool health, breaker
    states (cooled subnets with reasons). A cooled bucket's targets emit
    skipped records with reason - never silent.

    -debug prints the complete decision log. Every probe event (a
    probe, a QUIC handshake, a refusal, a classification, a timeout, an
    alert) prints as one line on stderr. The stream ends in a
    human-readable summary block. -debug-out writes the same run as
    schema-1 JSON (machine triage: jq '.summary', jq '.events'
    filters). Anything odd in a run — engine errors, an odd server
    behaviour, packets or ciphers outside the expectation — sits in
    that record. The issue templates require the `-debug -debug-out
    diag.json` attachments for bug reports; scan-related feature
    requests carry them, too.

SEE ALSO
    naabu, subfinder, httpx,
    nuclei, jq.

AUTHOR
    Shain Singh <shain.singh@owasp.org>

pqscan 2026.01-rc3                                        October 2026
