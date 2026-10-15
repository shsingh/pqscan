// Multi-target run pipeline (PQ-15, second slice): the grammar
// (internal/grammar) is wired into the run() path — composed -u / -l / --
// specs parse into []grammar.Target, the Engine scans them in order in
// fast mode, and progress reports every N targets (the 50-target
// convention). Encoders/WAL remain PQ-16.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shsingh/pqscan/internal/classify"
	"github.com/shsingh/pqscan/internal/congestion"
	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/grammar"
	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/quicx"
	"github.com/shsingh/pqscan/internal/tlsx"
)

// breakerThreshold is the consecutive per-host probe failures that open a
// host's breaker; breakerCooldown is how long an open host refuses dials
// before its half-open probe. The state is in-memory and never outlives a
// run (PQ-23); the §7.3 tuned budgets and per-/24 scoping ride the
// shard/perf-suite lanes.
const (
	breakerThreshold = 3
	breakerCooldown  = 15 * time.Second
)

// errNoTargets reports an empty composed target list to the caller.
var errNoTargets = errors.New("no targets")

// errCidrTargets refuses CIDR-class targets: the per-address expansion is
// PQ-16 scope (the CLI composes the clean message around it).
var errCidrTargets = errors.New("cidr expansion lands with PQ-16")

// progressEvery is the default progress interval: a report line every 50
// targets processed (standing user convention), plus one final report.
const progressEvery = 50

// The schema-1 record shape lives in internal/out (PQ-16); these aliases
// keep the pipeline's per-target vocabulary (scanRecord / handshake /
// quic) readable while pointing at the shape the encoders + WAL pin.
type scanRecord = out.Record

type handshakeRecord = out.HandshakeRecord

type quicRecord = out.QuicRecord

// defaultProbeTimeout is the per-plane probe budget (single-target rc1
// value, unchanged).
const defaultProbeTimeout = 8 * time.Second

// Options is the per-run pipeline configuration.
type Options struct {
	// QuicOff skips the QUIC plane (-quic-off).
	QuicOff bool
	// ProbeTimeout caps each plane probe; zero selects defaultProbeTimeout.
	ProbeTimeout time.Duration
	// Record receives every completed record as it leaves the pipeline
	// (the WAL sink appends there, so a crash keeps each completed
	// target); nil = no sink.
	Record func(*scanRecord)
	// Rate paces probe launches per second through the congestion token
	// bucket (-rate; 0 = no limit, the pre-PQ-23 engine pace). The bucket
	// starts with a single token — burst 1 — so the pace is the launch
	// cadence: one launch per 1/Rate with no burst credit.
	Rate float64
	// MaxWindow is the AIMD window's ceiling (-threads): the launch count
	// the dispatch may keep in flight. Zero (or negative) selects 1 — the
	// sequential engine, the pre-PQ-23 dispatch. The window itself starts
	// at aimd's floor and moves with the run (successes grow, probe
	// timeouts halve); MaxWindow is only its ceiling.
	MaxWindow int
	// Mode is the per-target scan mode (-mode, PQ-20): fast (the single
	// profile handshake, "" = fast for zero-value callers), deep (the
	// executed deepplan offer-one plan) or pq (the forced PQ ladder).
	Mode string
	// DeepPlan selects the -mode deep plan cap (-deep): deepplan standard
	// (default, <=24 probes per target) or full (the complete matrix).
	// It never affects the fast/pq modes.
	DeepPlan string
}

// stdin is the process stdin seam: run() reads composed "--" specs from it.
// The package variable keeps the CLI signature run(args, stdout, stderr)
// stable for every existing test.
var stdin io.Reader = os.Stdin

// Engine is the multi-target run pipeline: it scans the composed
// grammar.Targets under the PQ-23 control surfaces — the shared AIMD window
// capping the launches in flight, the launch pace when -rate set it, and the
// per-host breaker — one record per target, in composed order.
type Engine struct {
	// ProgressEvery is the progress-report interval; zero selects
	// progressEvery. The scan still reports once at completion.
	ProgressEvery int

	// aimd holds the run's shared AIMD window: re-created per Run (the
	// congestion state is in-memory and never outlives a run); nil before
	// the first Run. Package-internal tests read the final window after
	// Run returns.
	aimd *congestion.AIMD
}

// Run scans the composed targets under the PQ-23 control surfaces
// (docs/spec.md §7.3) and returns one record per target, in composed
// order: reachable targets carry their handshake, failed probes carry a
// schema-1 record with a non-empty Error (rejections are results, not
// run failures), and targets behind an open per-host breaker carry the
// "breaker open" error record without a dial. The dispatch keeps at most
// the ONE shared AIMD window's launches in flight — the window starts at
// one, grows additively per successful target toward its ceiling, and
// halves per timed-out probe (the per-target probe's timeout is the
// throttle signal; refusals are rejections, not congestion). When
// -rate set a pace, every probe launch buys its token from the burst-1
// token bucket before dialing. The congestion state is in-memory and
// never outlives a run. progress is invoked at every ProgressEvery-th
// completed target and once at completion; a nil progress callback is
// accepted. An empty target list is a caller error; CIDR-class targets
// are refused with errCidrTargets (expansion is PQ-16).
func (e *Engine) Run(targets []grammar.Target, opts Options, progress func(done, total int)) ([]*scanRecord, error) {
	if len(targets) == 0 {
		diag.Emit(diag.Warn, diag.DomEngine, "pipeline", "", "composed target list empty; refusing", nil, nil)
		return nil, errNoTargets
	}
	for _, t := range targets {
		if t.Class == "cidr" {
			diag.Emit(diag.Warn, diag.DomEngine, "pipeline", t.Input, "cidr target refused (expansion is PQ-16)", nil, nil)
			return nil, fmt.Errorf("cidr target %q: %w", t.Input, errCidrTargets)
		}
	}

	every := e.ProgressEvery
	if every <= 0 {
		every = progressEvery
	}
	total := len(targets)

	// The per-run control surfaces (PQ-23): ONE shared AIMD whose window
	// is the in-flight cap; the launch pace (burst 1: the pace is the
	// launch cadence, no burst credit); the per-host breaker. MaxWindow
	// normalizes to the pre-PQ-23 engine's 1 (the sequential dispatch).
	maxWindow := opts.MaxWindow
	if maxWindow < 1 {
		maxWindow = 1
	}
	aimd := congestion.NewAIMD(maxWindow)
	e.aimd = aimd
	var limiter *congestion.Limiter
	if opts.Rate > 0 {
		limiter = congestion.NewLimiter(opts.Rate, 1)
	}
	breaker := congestion.NewBreaker(breakerThreshold, breakerCooldown)
	diag.Emit(diag.Info, diag.DomEngine, "pipeline", "", "multi-target scan started",
		nil, map[string]string{"total": strconv.Itoa(total), "progress_every": strconv.Itoa(every),
			"rate": strconv.FormatFloat(opts.Rate, 'g', -1, 64), "max_window": strconv.Itoa(maxWindow)})

	// The window-semaphore dispatch: maxWindow workers pull dispatched
	// target indexes; the dispatcher keeps inFlight (dispatched targets
	// still unprocessed — scanning or token-waiting) under the AIMD's
	// window, processing completions singly so every window/breaker
	// decision and every Record append is made on this goroutine, in
	// completion order. Composed order survives concurrency: results
	// carry their index and recs is filled by position (the run's record
	// order contract, pinned by the multi-target tests).
	type launchResult struct {
		idx      int
		rec      *scanRecord
		failing  bool // the TCP probe never reached a handshake
		timedOut bool // the failing probe's budget expired (the throttle)
	}
	work := make(chan int)
	results := make(chan launchResult, maxWindow)
	var wg sync.WaitGroup
	for w := 0; w < maxWindow; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				if limiter != nil {
					if aerr := limiter.Acquire(context.Background()); aerr != nil {
						// The run's context never cancels; the contract
						// case is recorded in case a future caller arms
						// one (the launch proceeds ungated otherwise).
						diag.Emit(diag.Warn, diag.DomEngine, "pipeline", targets[i].Input,
							"launch pacing aborted", aerr, nil)
					}
				}
				rec, failing, timedOut := scanTarget(targets[i], opts)
				results <- launchResult{idx: i, rec: rec, failing: failing, timedOut: timedOut}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	recs := make([]*scanRecord, total)
	done, next, inFlight := 0, 0, 0
	report := func(rec *scanRecord) {
		if progress != nil && (done%every == 0 || done == total) {
			diag.Emit(diag.Info, diag.DomEngine, "pipeline", rec.Target.Input, "progress reported",
				nil, map[string]string{"done": strconv.Itoa(done), "total": strconv.Itoa(total)})
			progress(done, total)
		}
	}
	for done < total {
		switch {
		case next < total && inFlight < aimd.Window():
			t := targets[next]
			if !breaker.Allow(t.Host) {
				// The host's breaker is open: the target leaves as an
				// error record without any dial — nothing to pace,
				// nothing in flight, no window signal (it is not a
				// success nor a congestion event; the record's error is
				// the skipped-with-reason proof).
				rec := breakerOpenRecord(t)
				recs[next] = rec
				if opts.Record != nil {
					opts.Record(rec)
				}
				diag.Emit(diag.Warn, diag.DomEngine, "pipeline", t.Input, "breaker open; probe skipped", nil,
					map[string]string{"host": t.Host})
				next++
				done++
				report(rec)
				continue
			}
			// The launch's token comes off the bucket at dispatch — a
			// worker that has no token yet waits inside its scan loop,
			// still holding the in-flight slot (token-waiters do not
			// flood past the window either).
			work <- next
			next++
			inFlight++
			continue
		default:
			// A completion: the in-flight slot frees, the surfaces
			// record the outcome (breakers take failures and successes;
			// the window takes the timeout), then the freed budget
			// re-fills — this loop is the semaphore over the window.
			r := <-results
			inFlight--
			t := targets[r.idx]
			recs[r.idx] = r.rec
			if opts.Record != nil {
				opts.Record(r.rec)
			}
			switch {
			case r.failing:
				breaker.RecordFailure(t.Host)
				if r.timedOut {
					aimd.OnTimeout()
					diag.Emit(diag.Warn, diag.DomEngine, "pipeline", t.Input, "aimd window halved (probe timeout)", nil,
						map[string]string{"window": strconv.Itoa(aimd.Window())})
				}
			default:
				breaker.RecordSuccess(t.Host)
				aimd.OnSuccess()
			}
			done++
			report(r.rec)
		}
	}
	close(work) // everything dispatched and processed; workers drain and exit
	wg.Wait()
	return recs, nil
}

// scanTarget dispatches the per-target scan by run mode (PQ-20, issue
// #43): fast is the shipped single-handshake probe; pq appends the forced
// PQ ladder; deep consumes the deepplan.Build plan. Callers that leave
// Mode unset get the fast engine (zero-value compatibility).
func scanTarget(t grammar.Target, opts Options) (rec *scanRecord, failing, timedOut bool) {
	switch opts.Mode {
	case modeDeep:
		return scanTargetDeep(t, opts)
	case modePQ:
		return scanTargetPQ(t, opts)
	default:
		return scanTargetFast(t, opts)
	}
}

// scanTargetFast is the per-target fast-mode probe path (rc1 scanSingle,
// grammar-driven: the parsed Target already carries its canonical host,
// port and class, so no ad-hoc host:port splitting happens here). It
// reports the TCP plane's probe outcome beside the record — failing = the
// probe never reached a handshake (the breaker's failure signal);
// timedOut = the failure is a deadline expiry (aimd.OnTimeout, the §7.3
// throttle signal; plain refusals are rejections, not congestion). A
// scan-error record from the rubric is NOT a probe failure: the handshake
// itself succeeded.
func scanTargetFast(t grammar.Target, opts Options) (rec *scanRecord, failing, timedOut bool) {
	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	rec = &scanRecord{
		Schema: out.SchemaVersion,
		Mode:   "fast",
		Target: out.TargetRecord{Input: t.Input, Host: t.Host, Port: uint16(t.Port)},
	}
	// The record stamp is the scan's start wall clock (RFC 3339 with
	// nanoseconds, UTC — resume replay's not-rescanned proof reads it):
	// CSV rows and journal entries carry it; the JSONL line does not.
	rec.Ts = time.Now().UTC().Format(time.RFC3339Nano)

	// TCP plane: browser-grade defaults (stdlib CurvePreferences = MLKEM
	// hybrid preferred) — the negotiation is the real-world posture.
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	res, err := tlsx.ProbeNegotiated(addr, t.Host, nil, timeout)
	if err != nil && (res == nil || res.Error == "") {
		rec.Error = err.Error()
		diag.Emit(diag.Error, diag.DomTLS, "scan", t.Host, "TCP probe errored", err, nil)
		return rec, true, isTimeoutError(rec.Error)
	}
	if res != nil && res.Error != "" {
		// Refusals are records, not run failures (rejections are results):
		// an unreachable endpoint yields a schema-1 error record with a
		// zero handshake (surfaced by the dead-target RED row — the rc1
		// scanSingle dropped dial refusals into empty-error records).
		rec.Error = res.Error
		diag.Emit(diag.Error, diag.DomTLS, "scan", t.Host, "TCP probe refused", errors.New(res.Error), nil)
		// A refusal still fails the probe for the breaker's consecutive-
		// failure count; only the deadline-expiry class signals the AIMD
		// window (a refusal carries no congestion information).
		return rec, true, isTimeoutError(rec.Error)
	}
	rec.Handshake = handshakeRecord{
		Negotiated: res.Negotiated,
		GroupName:  groupName(res.Negotiated),
		Suite:      res.Suite,
		Version:    versionName(res.Version),
		ALPNNeg:    res.ALPN,
	}
	cls, clsOK := classify.GroupClass(res.Negotiated)
	if clsOK {
		rec.Handshake.GroupClass = string(cls)
	}
	diag.Emit(diag.Info, diag.DomTLS, "scan", t.Host, "TCP handshake negotiated", nil,
		map[string]string{"negotiated": u32str(res.Negotiated), "suite": res.Suite, "group_class": rec.Handshake.GroupClass})

	// PQ-19/PQ-21 record wire-in: map the observed facts onto the rubric's
	// ScoreInput and score the record with the REAL rubric (rubric_test's
	// verdict table is the same DefaultRubric). Derived facts of the fast
	// mode: OfferedPQ — the browser-grade default offer set (nil groups)
	// opens with the standards-track PQ hybrids, so PQ was offered;
	// AcceptsDraft — the negotiated class being a draft class is the
	// accepted fact; ClassicalPreferred — a classical group was negotiated
	// while PQ was offered; CertPQ/DualCert — the PQ-21 analysis of the
	// chain this same handshake delivered. The rubric's scan-error
	// behavior is the record's error path (a failed probe never reaches
	// the rubric: score 0 stays the zero value and no verdict block is
	// invented — the Error field is that record's verdict path).
	// rubricNegotiatedClass collapses the two facts into the rubric's
	// compact token. The ScoreInput contract (PQ-19) defines the compact
	// tokens: "pq", "pq_hybrid", "classic", "draft", "unknown".
	token := rubricNegotiatedClass(cls, clsOK)
	// OfferedPQ: the fast mode's browser-grade default offer set (nil
	// groups) opens with the standards-track PQ hybrids — every probe
	// negotiated here was offered PQ.
	offeredPQ := true
	in := classify.ScoreInput{
		NegotiatedClass:    token,
		OfferedPQ:          offeredPQ,
		AcceptsDraft:       token == "draft",
		ClassicalPreferred: token == "classic" && offeredPQ,
		CertPQ:             res.CertificatePQ,
		DualCert:           res.CertificateInfo != nil && res.CertificateInfo.DualCert,
	}
	verdict, serr := classify.DefaultRubric().Score(in)
	rec.Pq = &out.PqRecord{Score: verdict.Score, Label: verdict.Label, HNDL: verdict.HNDL, Summary: verdict.Summary}
	if info := res.CertificateInfo; info != nil {
		// The cert block carries the leaf's classified algorithm names
		// and flags verbatim; presence = analyzed (a classical leaf is
		// a classical row, not the absence of a row).
		rec.Cert = &out.CertRecord{SigAlg: info.SigAlgName, SigPQ: info.SigAlgPQ,
			KeyAlg: info.KeyAlg, KeyPQ: info.KeyAlgPQ, Dual: info.DualCert}
	}
	fields := map[string]string{"score": strconv.Itoa(verdict.Score), "label": verdict.Label}
	if serr != nil {
		rec.Error = serr.Error()
		diag.Emit(diag.Warn, diag.DomEngine, "scan", t.Host, "readiness verdict is a scan-error", serr, fields)
	} else {
		fields["hndl"] = strconv.FormatBool(verdict.HNDL)
		diag.Emit(diag.Info, diag.DomEngine, "scan", t.Host, "readiness verdict", nil, fields)
	}

	// QUIC plane: hostname targets only (IP targets need SNI-less QUIC, M4).
	if !opts.QuicOff && t.Class != "ip" {
		qr, qerr := quicx.ProbeQUIC(addr, t.Host, nil, timeout)
		if qerr == nil {
			rec.Quic = &quicRecord{Attempted: true, State: qr.State,
				Negotiated: qr.Group, GroupName: groupName(qr.Group),
				GroupClass: qr.GroupClass, UDPBlocked: qr.UDPBlocked}
			diag.Emit(diag.Info, diag.DomQuic, "scan", t.Host, "QUIC probe recorded", nil,
				map[string]string{"state": qr.State, "negotiated": u32str(qr.Group), "udp_blocked": fmt.Sprint(qr.UDPBlocked)})
		} else {
			rec.Quic = &quicRecord{Attempted: false}
			diag.Emit(diag.Warn, diag.DomQuic, "scan", t.Host, "QUIC probe omitted", qerr, nil)
		}
	} else {
		rec.Quic = &quicRecord{Attempted: false}
	}
	return rec, false, false
}

// breakerOpenRecord builds the breaker-skipped target's record: the
// schema-1 error shape (like any failed probe — zero handshake, no
// verdict blocks invented), its Error carrying the skip reason "breaker
// open" instead of the dial's outcome. Skipped-with-reason, never silent.
func breakerOpenRecord(t grammar.Target) *scanRecord {
	rec := &scanRecord{
		Schema: out.SchemaVersion,
		Mode:   "fast",
		Target: out.TargetRecord{Input: t.Input, Host: t.Host, Port: uint16(t.Port)},
	}
	rec.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	rec.Error = "breaker open"
	return rec
}

// isTimeoutError reports whether the probe's emitted error text carries
// one of the net stack's deadline-expiry classes. The pipeline consumes
// the probe's error STRING only: the transport package
// (internal/tlsx.ProbeNegotiated) packs every dial/handshake failure into
// ProbeResult.Error with no timeout flag of its own, so the wiring
// classifies the §7.3 throttle signal by the text the stack emits. The
// two classes observed on the real path: a net dialer budget reads
// "…: i/o timeout", and the TLS-with-dialer handshake deadline reads
// "context deadline exceeded". Resolver failures, "connection refused"
// and other refusal texts name their cause and deliberately signal
// nothing to the window.
func isTimeoutError(text string) bool {
	return strings.Contains(text, "i/o timeout") ||
		strings.Contains(text, "context deadline exceeded")
}

// rubricNegotiatedClass maps the IANA taxonomy class (classify.Class)
// onto the rubric's compact negotiated-class token (PQ-19's ScoreInput
// contract: pq / pq_hybrid / classic / draft / unknown): pq_pure → pq;
// pq_hybrid and the SM-era hybrids → pq_hybrid (a negotiated PQ hybrid
// whatever the standard's origin); the pre-standards Kyber hybrids →
// draft (the HNDL-observable class); the classical families — RSA-kex
// era included — → classic; an unrecognised codepoint → unknown (itself
// a valid rubric token: zero PQ signal, so the verdict becomes the
// scan-error state — never an invented PQ claim for unknown facts).
func rubricNegotiatedClass(c classify.Class, known bool) string {
	if !known {
		return "unknown"
	}
	switch c {
	case classify.ClassPQ:
		return "pq"
	case classify.ClassPQHybrid, classify.ClassHybridSM:
		return "pq_hybrid"
	case classify.ClassPQHybridD:
		return "draft"
	case classify.ClassClassic, classify.ClassObsolete:
		return "classic"
	default:
		return "unknown"
	}
}

// composeTargets parses the composed target sources (-u spec, -l file lines,
// and the bare "--" stdin marker) into a deduplicated []grammar.Target, in
// first-occurrence order (dedupe key: host:port).
//
// The "--" marker is detected in the RAW argument list: Go's flag package
// consumes the terminator and it never lands in fs.Args() (surfaced by the
// composition RED row — 2 of 3 records came out before the marker was
// honoured). It reaches the spec loop as the stdin-class spec grammar.Parse
// yields for "--"; -l -- composes the same way (the marker value is not
// treated as a file name). stdin expands exactly once.
//
// Refusals (exit 64, usage class): a source that fails to read, a spec the
// grammar rejects, and CIDR-class targets — a cidr spec prints the PQ-16
// deferral and refuses before anything is scanned (per-address expansion is
// PQ-16; the grammar yields one Target per network, so the loop rejects the
// class directly).
func composeTargets(uSpec, listFile string, rawArgs []string, stderr io.Writer) ([]grammar.Target, int) {
	var specs []string
	if listFile == "--" {
		listFile = "" // the marker composes via the spec loop below
	}
	if uSpec != "" {
		specs = append(specs, uSpec)
	}
	if listFile != "" {
		lines, err := readSpecFile(listFile)
		if err != nil {
			diag.Emit(diag.Error, diag.DomTarget, "compose", "", "-l read failed", err, map[string]string{"file": listFile})
			fmt.Fprintf(stderr, "pqscan: -l %s: %v\n", listFile, err)
			return nil, 64
		}
		specs = append(specs, lines...)
	}
	for _, arg := range rawArgs {
		if arg == "--" {
			specs = append(specs, "--")
			break // stdin expands once; further markers add nothing
		}
	}

	targets := make([]grammar.Target, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	stdinDrained := false
	// parseSpecs fans one batch of specs into targets (in order), expanding
	// the stdin marker exactly once.
	var parseSpecs func([]string) error
	parseSpecs = func(batch []string) error {
		for _, spec := range batch {
			parsed, err := grammar.Parse(spec)
			if err != nil {
				return err
			}
			for _, t := range parsed {
				switch t.Class {
				case "stdin":
					if stdinDrained {
						continue
					}
					stdinDrained = true
					if err := parseSpecs(readSpecs(stdin)); err != nil {
						return err
					}
				case "cidr":
					diag.Emit(diag.Warn, diag.DomTarget, "compose", t.Input, "cidr target refused (expansion is PQ-16)", nil, nil)
					fmt.Fprintf(stderr, "pqscan: -cidr target %q: %v\n", t.Input, errCidrTargets)
					return errCidrTargets
				default:
					key := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
					if seen[key] {
						continue // dedupe by host:port, first occurrence wins
					}
					seen[key] = true
					targets = append(targets, t)
				}
			}
		}
		return nil
	}
	if err := parseSpecs(specs); err != nil {
		if !errors.Is(err, errCidrTargets) {
			// the cidr refusal already printed its contextual line
			fmt.Fprintln(stderr, "pqscan:", err)
		}
		return nil, 64
	}
	return targets, 0
}

// readSpecFile reads one -l list file: newline-separated target specs,
// blank/whitespace-only lines skipped.
func readSpecFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	return readSpecs(f), nil
}

// readSpecs fans a reader into trimmed, non-empty spec lines.
func readSpecs(r io.Reader) []string {
	var specs []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			specs = append(specs, line)
		}
	}
	return specs
}
