// Multi-target run pipeline (PQ-15, second slice): the grammar
// (internal/grammar) is wired into the run() path — composed -u / -l / --
// specs parse into []grammar.Target, the Engine scans them in order in
// fast mode, and progress reports every N targets (the 50-target
// convention). Encoders/WAL remain PQ-16.
package main

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shsingh/pqscan/internal/classify"
	"github.com/shsingh/pqscan/internal/congestion"
	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/discovery"
	"github.com/shsingh/pqscan/internal/grammar"
	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/quicx"
	"github.com/shsingh/pqscan/internal/resolver"
	"github.com/shsingh/pqscan/internal/target"
	"github.com/shsingh/pqscan/internal/tlsx"
)

// certWriteMu serializes the -certs-dir PEM writes: the dispatch keeps
// window-many probes in flight and two targets can share a host; one
// file per host means the writers would otherwise race the same path.
var certWriteMu sync.Mutex

// writeCertPEM exports one scanned host's end-entity certificate as a
// CERTIFICATE-PEM block at <dir>/<host>.pem (PQ-26; -certs-dir). The
// directory is created on demand (the run's MkdirAll already built it;
// a component-level caller may not have).
func writeCertPEM(dir, host string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	certWriteMu.Lock()
	defer certWriteMu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, host+".pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0o644)
}

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
var errCidrTargets = errors.New("cidr expansion is not supported")

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
	// DeepPlan selects the -deep plan cap (-deep): deepplan standard
	// (default, <=24 probes per target) or full (the complete matrix).
	// It never affects the fast/pq modes.
	DeepPlan string

	// QuicAlways forces the QUIC lane's direct probe regardless of the
	// alt-svc hint (PQ-25's -quic-always; spec §5.3). QuicOff keeps the
	// highest precedence — a -quic-off run scans no QUIC plane at all.
	QuicAlways bool

	// PtrPool is the PQ-26 PTR/SNI pool (issue #49): when set, an IP
	// target resolves its reverse DNS PRE-PROBE — the record's ptr +
	// sni_used fill and the SNI candidate come off the pool per its
	// strategy; hostname targets never consult the pool (their SNI is
	// the host). nil = no enrichment (the pre-PQ-26 engine).
	PtrPool *resolver.Pool

	// CertsDir exports each scanned host's end-entity certificate as
	// PEM on scan (-certs-dir; <dir>/<host>.pem); "" = no export.
	CertsDir string
}

// stdin is the process stdin seam: run() reads composed "--" specs from it.
// The package variable keeps the CLI signature run(args, stdout, stderr)
// stable for every existing test.
var stdin io.Reader = os.Stdin

// stdinIsPipe reports whether the run's stdin is a piped stream — the
// implicit-input detector for PQ-41 (issue #117): the PD-chain convention
// reads target specs from a pipe when NO other target source composes.
// Character devices (the interactive terminal, /dev/null) never trigger
// the implicit read, so an automation context holding a never-terminating
// pipe is the documented contract case, not an accident. Package var:
// run(args, stdout, stderr) keeps its test signature; tests pin the class
// via setStdinPipe.
var stdinIsPipe = func() bool {
	si, err := os.Stdin.Stat()
	if err != nil {
		return false // unclassifiable stdin: the explicit forms still compose
	}
	return si.Mode()&os.ModeNamedPipe != 0 // pipes only: terminals and /dev/null are character devices
}

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
			diag.Emit(diag.Warn, diag.DomEngine, "pipeline", t.Input, "cidr target refused (expansion is not supported)", nil, nil)
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
				rec := breakerOpenRecord(t, opts.Mode)
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
		rec, failing, timedOut = scanTargetDeep(t, opts)
	case modePQ:
		rec, failing, timedOut = scanTargetPQ(t, opts)
	default:
		rec, _, failing, timedOut = scanTargetFast(t, opts)
	}
	return rec, failing, timedOut
}

// scanTargetFast is the per-target fast-mode probe path (rc1 scanSingle,
// grammar-driven: the parsed Target already carries its canonical host,
// port and class, so no ad-hoc host:port splitting happens here). It
// reports the TCP plane's probe outcome beside the record — failing = the
// probe never reached a handshake (the breaker's failure signal);
// timedOut = the failure is a deadline expiry (aimd.OnTimeout, the §7.3
// throttle signal; plain refusals are rejections, not congestion). A
// scan-error record from the rubric is NOT a probe failure: the handshake
// itself succeeded. res is the raw profile handshake (PQ-20's deep/pq
// executors consume its facts: the Observed prune input and the cert
// analytics); nil only when the probe died before any observation.
func scanTargetFast(t grammar.Target, opts Options) (rec *scanRecord, res *tlsx.ProbeResult, failing, timedOut bool) {
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

	// PQ-26 (-ptr): an IP target's reverse DNS resolves PRE-PROBE through
	// the run's pool — the resolved name (or "" on a miss, an error or a
	// malformed answer: misses are never cached) and the strategy's SNI
	// candidate land on the record (ptr + sni_used), and the candidate is
	// what the planes dial with. Hostname targets never consult the pool:
	// their SNI is the host, and nothing fills.
	sniHost := t.Host
	if opts.PtrPool != nil && t.Class == "ip" {
		if addr, perr := netip.ParseAddr(t.Host); perr == nil {
			ptrName, _ := opts.PtrPool.ResolvePTR(context.Background(), addr)
			candidate, won := opts.PtrPool.SNIFromPTR(ptrName, addr)
			rec.Target.Ptr = ptrName
			rec.Target.SNIUsed = candidate
			sniHost = candidate
			diag.Emit(diag.Info, diag.DomDNS, "scan", t.Host, "ip-target SNI resolved pre-probe", nil,
				map[string]string{"ptr": ptrName, "sni": candidate, "strategy_won": won})
		}
	}

	// TCP plane: browser-grade defaults (stdlib CurvePreferences = MLKEM
	// hybrid preferred) — the negotiation is the real-world posture.
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	res, perr := tlsx.ProbeNegotiated(addr, sniHost, nil, timeout)
	if perr != nil && (res == nil || res.Error == "") {
		rec.Error = perr.Error()
		zeroProbeBlocks(rec)
		diag.Emit(diag.Error, diag.DomTLS, "scan", t.Host, "TCP probe errored", perr, nil)
		return rec, res, true, isTimeoutError(rec.Error)
	}
	if res != nil && res.Error != "" {
		// Refusals are records, not run failures (rejections are results):
		// an unreachable endpoint yields a schema-1 error record with a
		// zero handshake (surfaced by the dead-target RED row — the rc1
		// scanSingle dropped dial refusals into empty-error records).
		rec.Error = res.Error
		zeroProbeBlocks(rec)
		diag.Emit(diag.Error, diag.DomTLS, "scan", t.Host, "TCP probe refused", errors.New(res.Error), nil)
		// A refusal still fails the probe for the breaker's consecutive-
		// failure count; only the deadline-expiry class signals the AIMD
		// window (a refusal carries no congestion information).
		return rec, res, true, isTimeoutError(rec.Error)
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
	// chain this same handshake delivered. PQ-43: the rubric's
	// scan-error verdict (score 0, the zero-PQ-signal refusal) is the
	// record's verdict STATE — it lives in the pq block (score 0 / label
	// scan-error), never in the error field: that field keeps the
	// probe-failure contract alone (a failed probe never reaches the
	// rubric: score 0 stays the zero value and no verdict block is
	// invented), and the rubric's returned error remains the classifier's
	// internal path.
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
		// PQ-43: the rubric's zero-PQ-signal refusal stays the
		// classifier's internal path (the diagnostics warning carries
		// it) — a verdict-carrying record never feeds it into
		// record.Error. The record's error field is the probe's failure
		// reason (docs/spec.md §5.7); the scan-error state's only honest
		// home is the pq block just landed (score 0 / label scan-error,
		// rendered as pq=scan-error(0) on the text line and by -explain).
		diag.Emit(diag.Warn, diag.DomEngine, "scan", t.Host, "readiness verdict is a scan-error", serr, fields)
	} else {
		fields["hndl"] = strconv.FormatBool(verdict.HNDL)
		diag.Emit(diag.Info, diag.DomEngine, "scan", t.Host, "readiness verdict", nil, fields)
	}

	// PQ-26 (-certs-dir): the profile handshake's end-entity certificate
	// exports as PEM once per scanned host (<dir>/<host>.pem) — deep/pq
	// inherit the export (they run this fast shape first, so the profile
	// handshake is the cert fetch). Best-effort: a write failure warns in
	// the diagnostics and never fails the scan (the record is already
	// complete; the export is downstream tooling convenience).
	if opts.CertsDir != "" && res != nil && res.Error == "" && len(res.LeafRaw) > 0 {
		if cerr := writeCertPEM(opts.CertsDir, t.Host, res.LeafRaw); cerr != nil {
			diag.Emit(diag.Error, diag.DomOutput, "certs-dir", t.Host, "end-entity PEM export failed", cerr,
				map[string]string{"dir": opts.CertsDir})
		} else {
			diag.Emit(diag.Info, diag.DomOutput, "certs-dir", t.Host, "end-entity PEM exported", nil,
				map[string]string{"dir": opts.CertsDir})
		}
	}

	// PQ-25 QUIC lane (spec §5.3/§5.7; issue #48): hint-gated — the
	// alt-svc h3 hint the fast pass's discovery probe collected DECIDES
	// the direct QUIC probe (hint present → attempt); an unhinted target
	// records the honest informational skip (a state token, not an error
	// — the exit code never moves on a QUIC fact); -quic-always forces
	// the direct probe regardless of the hint; -quic-off skips the plane
	// outright (highest precedence, the shipped pre-PQ-25 shape). A
	// hint/truth disagreement is a FINDING: the mismatch state + flag on
	// the record + a diagnostics finding row — the direct handshake is
	// the truth, the hint only ever a hint.
	rec.Quic = &quicRecord{Attempted: false, Discovered: &out.H3Discovery{}} // -quic-off: the plane skipped, its schema-required discovered block rides the zero halves (PQ-54: the record contract never omits a required key)
	if !opts.QuicOff {
		hint, altSvcValue, herr := discovery.ProbeHint(context.Background(), t.Host,
			uint16(t.Port), discovery.Options{Timeout: timeout})
		if herr != nil {
			// The hint's only errors are caller aborts; the lane falls
			// through to the honest skip and the diagnostics carry the
			// cause — never a run failure.
			diag.Emit(diag.Warn, diag.DomQuic, "scan", t.Host, "h3 hint collection aborted", herr, nil)
		}
		switch {
		case !hint && !opts.QuicAlways:
			rec.Quic = &quicRecord{
				Attempted:  false,
				State:      discovery.SkipStateNoHint,
				Discovered: &out.H3Discovery{AltSvcH3: hint, H3Direct: false},
			}
			diag.Emit(diag.Info, diag.DomQuic, "scan", t.Host, "QUIC lane skipped on the alt-svc gate", nil,
				map[string]string{"state": discovery.SkipStateNoHint})
		default:
			if qr, qerr := quicx.ProbeQUIC(addr, t.Host, nil, timeout); qerr == nil {
				truth := qr.H3Negotiated()
				rec.Quic = &quicRecord{
					Attempted: true, State: qr.State,
					Negotiated: qr.Group, GroupName: groupName(qr.Group),
					GroupClass: qr.GroupClass, UDPBlocked: qr.UDPBlocked,
					Discovered: &out.H3Discovery{AltSvcH3: hint, H3Direct: truth},
				}
				if state, mismatched := discovery.MismatchState(hint, truth); mismatched {
					rec.Quic.State = state
					rec.Quic.Mismatch = true
					// The mismatch finding row: the diagnostics record
					// carries the direction and the raw alt-svc value
					// (the classifier input) — never a run error.
					diag.Emit(diag.Warn, diag.DomQuic, "h3-mismatch", addr,
						"alt-svc hint vs direct QUIC truth mismatch", nil,
						map[string]string{"hint": yn(hint), "truth": yn(truth), "alt_svc": altSvcValue})
				} else {
					diag.Emit(diag.Info, diag.DomQuic, "scan", t.Host, "QUIC probe recorded", nil,
						map[string]string{"state": qr.State, "negotiated": u32str(qr.Group),
							"udp_blocked": fmt.Sprint(qr.UDPBlocked), "alt_svc_h3": yn(hint)})
				}
			} else {
				diag.Emit(diag.Warn, diag.DomQuic, "scan", t.Host, "QUIC probe omitted", qerr, nil)
			}
		}
	}
	return rec, res, false, false
}

// zeroProbeBlocks populates a failed-probe record's schema-required probe
// blocks with their zero halves (PQ-60, issue #157, cure A — the uniform
// record contract): the blocks docs/schema-v1.json requires at top level
// stand on EVERY record class, zero-populated when the handshake never
// completed — the QUIC plane made no attempt, no certificate was analyzed,
// the rubric never produced a verdict. The zero values carry the absence
// (the #155 writer discipline: zeros and empty strings, never missing
// keys); the engine invents no observation, and the record's Error field
// remains the failure class's only carrier.
func zeroProbeBlocks(rec *scanRecord) {
	rec.Quic = &quicRecord{Discovered: &out.H3Discovery{}}
	rec.Cert = &out.CertRecord{}
	rec.Pq = &out.PqRecord{}
}

// breakerOpenRecord builds the breaker-skipped target's record: the
// schema-1 error shape (like any failed probe — zero handshake, the
// schema-required probe blocks zero-populated, no invented verdict), its
// Error carrying the skip reason "breaker open" instead of the dial's
// outcome. Skipped-with-reason, never silent.
func breakerOpenRecord(t grammar.Target, mode string) *scanRecord {
	rec := &scanRecord{
		Schema: out.SchemaVersion,
		Mode:   mode,
		Target: out.TargetRecord{Input: t.Input, Host: t.Host, Port: uint16(t.Port)},
	}
	rec.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	rec.Error = "breaker open"
	zeroProbeBlocks(rec)
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

// composeTargets parses the composed target sources into a deduplicated
// []grammar.Target, in first-occurrence order (dedupe key: host:port).
//
// The spec sources stay -u / -l / the bare "--" marker; the PD-dialect
// adapter files (PQ-35, issue #80; PQ-55's nuclei import, issue #149) join
// them through internal/target: -from-httpx (httpx lines: scheme://host:port
// with an optional URL path suffix), -from-naabu (the naabu render: host:port
// lines, a host line followed by its bare-decimal ports block, or the bare
// host) and -from-nuclei (the pinned `nuclei -l hosts.txt -silent -j`
// findings JSONL: one finding per line, its matched-at — url fallback —
// contributing the host:port, scheme/path stripped) strip the dialect
// decoration and hand every line to grammar.Parse exactly as -u does — ONE
// grammar and ONE dedupe layer serve every input source.
// Source order is the flag order: -u, then -l, then the stdin marker,
// then the adapter files (-from-httpx, then -from-naabu, then -from-nuclei).
//
// The "--" marker is detected in the RAW argument list: Go's flag package
// consumes the terminator and it never lands in fs.Args() (surfaced by the
// composition RED row — 2 of 3 records came out before the marker was
// honoured). It reaches the spec loop as the stdin-class spec grammar.Parse
// yields for "--"; -l -- and -l - compose the same way (neither marker
// value is treated as a file name; PQ-41). stdin expands exactly once.
//
// The spec path (PQ-41) strips the accepted scheme://host[:port]
// decoration through target.StripScheme — the same internal/target rule
// the adapter dialects apply — before grammar.Parse; a URL path suffix
// on a spec line refuses with the adapter named (-from-httpx).
//
// Refusals (exit 64, usage class): a source that fails to read, a spec the
// grammar rejects (the adapter dialects annotate the failing line's
// number), and CIDR-class targets — a cidr spec prints the PQ-16 deferral
// and refuses before anything is scanned (per-address expansion is PQ-16;
// the grammar yields one Target per network, so the loop rejects the class
// directly). No partial list ever scans.
func composeTargets(uSpec, listFile, httpxFile, naabuFile, nucleiFile string, rawArgs []string, stderr io.Writer) ([]grammar.Target, int) {
	var specs []string
	implicitStdin := false // the piped stdin composed as the only source (PQ-41)
	if uSpec != "" {
		specs = append(specs, uSpec)
	}
	if listFile == "--" || listFile == "-" {
		// Both spellings compose stdin through the spec loop below: the
		// bare marker and, PQ-41 (issue #117), "-l -" — the explicit
		// stdin-file alias (nmap -iL - / nuclei -l -), never a file
		// name. stdin still expands exactly once: the admit layer holds
		// the stdin class, so a companion raw -- marker adds nothing.
		specs = append(specs, "--")
	} else if listFile != "" {
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

	// The adapter files (PQ-35): read in source order, parsed by
	// internal/target into the same []grammar.Target shape the spec loop
	// produces; the shared admission below treats them identically.
	var adapterBatches [][]grammar.Target
	readAdapter := func(flag, path string) ([]grammar.Target, int) {
		f, err := os.Open(path)
		if err != nil {
			diag.Emit(diag.Error, diag.DomTarget, "compose", "", flag+" read failed", err, map[string]string{"file": path})
			fmt.Fprintf(stderr, "pqscan: %s %s: %v\n", flag, path, err)
			return nil, 64
		}
		defer f.Close() //nolint:errcheck
		var ts []grammar.Target
		switch flag {
		case "-from-httpx":
			ts, err = target.FromHTTPX(f)
		case "-from-naabu":
			ts, err = target.FromNaabu(f)
		case "-from-nuclei":
			ts, err = target.FromNuclei(f)
		}
		if err != nil {
			diag.Emit(diag.Error, diag.DomTarget, "compose", "", flag+" parse failed", err, map[string]string{"file": path})
			fmt.Fprintf(stderr, "pqscan: %s %s: %v\n", flag, path, err)
			return nil, 64
		}
		return ts, 0
	}
	for _, src := range []struct{ flag, path string }{
		{"-from-httpx", httpxFile},
		{"-from-naabu", naabuFile},
		{"-from-nuclei", nucleiFile},
	} {
		if src.path == "" {
			continue
		}
		ts, code := readAdapter(src.flag, src.path)
		if code != 0 {
			return nil, code
		}
		adapterBatches = append(adapterBatches, ts)
	}

	// The implicit piped stdin (PQ-41; issue #117): with a pipe on stdin
	// and NO target source at all (-u/-l/--/adapters all absent), the
	// pipe IS the target source — httpx/naabu lines flowing into the
	// run, the PD chain's natural handoff shape. A character-device
	// stdin (the interactive terminal, /dev/null) never triggers it.
	// An EMPTY pipe still refuses exit 64 below with its own honest
	// line — nothing arrived, nothing scanned — and a piped-open
	// never-terminating stdin blocks by contract (USAGE.md).
	if len(specs) == 0 && httpxFile == "" && naabuFile == "" && nucleiFile == "" && stdinIsPipe() {
		specs = append(specs, "--")
		implicitStdin = true
	}

	targets := make([]grammar.Target, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	stdinDrained := false

	var parseSpecs func([]string) error

	// admit is the shared admission every source walks: the stdin marker
	// expands exactly once, cidr refuses with the PQ-16 deferral, and
	// everything else dedupes by host:port (first occurrence wins).
	var admit func(t grammar.Target) error
	admit = func(t grammar.Target) error {
		switch t.Class {
		case "stdin":
			if stdinDrained {
				return nil
			}
			stdinDrained = true
			return parseSpecs(readSpecs(stdin))
		case "cidr":
			diag.Emit(diag.Warn, diag.DomTarget, "compose", t.Input, "cidr target refused (expansion is not supported)", nil, nil)
			fmt.Fprintf(stderr, "pqscan: cidr target %q: %v\n", t.Input, errCidrTargets)
			return errCidrTargets
		default:
			key := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
			if seen[key] {
				return nil // dedupe by host:port, first occurrence wins
			}
			seen[key] = true
			targets = append(targets, t)
			return nil
		}
	}

	parseSpecs = func(batch []string) error {
		for _, spec := range batch {
			// The spec path strips the accepted scheme:// decoration
			// (PQ-41): the same internal/target rule the adapter
			// dialects apply, so -u/-l/-- lines accept
			// scheme://host[:port] with ONE decoration rule for every
			// input source. A URL path suffix refuses here naming the
			// adapter; an honestly-unparseable shape reaches the
			// grammar's own refusal unchanged.
			spec, err := target.StripScheme(spec)
			if err != nil {
				return err
			}
			parsed, err := grammar.Parse(spec)
			if err != nil {
				return err
			}
			for _, t := range parsed {
				if err := admit(t); err != nil {
					return err
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
	for _, batch := range adapterBatches {
		for _, t := range batch {
			if err := admit(t); err != nil {
				if !errors.Is(err, errCidrTargets) {
					// the adapter refusal already annotated its line
					fmt.Fprintln(stderr, "pqscan:", err)
				}
				return nil, 64
			}
		}
	}
	if len(targets) == 0 && implicitStdin {
		diag.Emit(diag.Warn, diag.DomTarget, "compose", "", "piped stdin held no target specs; run refuses", nil, nil)
		fmt.Fprintln(stderr, "pqscan: piped stdin held no target specs (nothing to scan; one target spec per line — -h shows the input forms)")
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

// yn renders a yes/no fact for the diagnostics fields (the hint/truth
// grammar the h3-mismatch finding row speaks; PQ-25).
func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
