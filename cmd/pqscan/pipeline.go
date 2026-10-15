// Multi-target run pipeline (PQ-15, second slice): the grammar
// (internal/grammar) is wired into the run() path — composed -u / -l / --
// specs parse into []grammar.Target, the Engine scans them in order in
// fast mode, and progress reports every N targets (the 50-target
// convention). Encoders/WAL remain PQ-16.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shsingh/pqscan/internal/classify"
	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/grammar"
	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/quicx"
	"github.com/shsingh/pqscan/internal/tlsx"
)

// errNoTargets reports an empty composed target list to the caller.
var errNoTargets = errors.New("no targets")

// errCidrTargets refuses CIDR-class targets: the per-address expansion is
// PQ-16 scope (the CLI composes the clean message around it).
var errCidrTargets = errors.New("cidr expansion lands with PQ-16")

// progressEvery is the default progress interval: a report line every 50
// targets processed (standing user convention), plus one final report.
const progressEvery = 50

// defaultProbeTimeout is the per-plane probe budget (single-target rc1
// value, unchanged).
const defaultProbeTimeout = 8 * time.Second

// Options is the per-run pipeline configuration.
type Options struct {
	// QuicOff skips the QUIC plane (-quic-off).
	QuicOff bool
	// ProbeTimeout caps each plane probe; zero selects defaultProbeTimeout.
	ProbeTimeout time.Duration
}

// stdin is the process stdin seam: run() reads composed "--" specs from it.
// The package variable keeps the CLI signature run(args, stdout, stderr)
// stable for every existing test.
var stdin io.Reader = os.Stdin

// Engine is the multi-target run pipeline: it scans every parsed
// grammar.Target in order, fast mode, one record per target.
type Engine struct {
	// ProgressEvery is the progress-report interval; zero selects
	// progressEvery. The scan still reports once at completion.
	ProgressEvery int
}

// Run scans targets in order and returns one record per target: reachable
// targets carry their handshake, failed probes carry a schema-1 record with
// a non-empty Error (rejections are results, not run failures). progress is
// invoked at every ProgressEvery-th completed target and once at
// completion; a nil progress callback is accepted. An empty target list is
// a caller error; CIDR-class targets are refused with errCidrTargets
// (expansion is PQ-16).
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
	diag.Emit(diag.Info, diag.DomEngine, "pipeline", "", "multi-target scan started",
		nil, map[string]string{"total": strconv.Itoa(total), "progress_every": strconv.Itoa(every)})

	recs := make([]*scanRecord, 0, total)
	for i, t := range targets {
		recs = append(recs, scanTarget(t, opts))
		if done := i + 1; progress != nil && (done%every == 0 || done == total) {
			diag.Emit(diag.Info, diag.DomEngine, "pipeline", t.Input, "progress reported",
				nil, map[string]string{"done": strconv.Itoa(done), "total": strconv.Itoa(total)})
			progress(done, total)
		}
	}
	return recs, nil
}

// scanTarget is the per-target fast-mode probe path (rc1 scanSingle,
// grammar-driven: the parsed Target already carries its canonical host,
// port and class, so no ad-hoc host:port splitting happens here).
func scanTarget(t grammar.Target, opts Options) *scanRecord {
	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	rec := &scanRecord{
		Schema: out.SchemaVersion,
		Mode:   "fast",
		Target: out.TargetRecord{Input: t.Input, Host: t.Host, Port: uint16(t.Port)},
	}

	// TCP plane: browser-grade defaults (stdlib CurvePreferences = MLKEM
	// hybrid preferred) — the negotiation is the real-world posture.
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	res, err := tlsx.ProbeNegotiated(addr, t.Host, nil, timeout)
	if err != nil && (res == nil || res.Error == "") {
		rec.Error = err.Error()
		diag.Emit(diag.Error, diag.DomTLS, "scan", t.Host, "TCP probe errored", err, nil)
		return rec
	}
	if res != nil && res.Error != "" {
		// Refusals are records, not run failures (rejections are results):
		// an unreachable endpoint yields a schema-1 error record with a
		// zero handshake (surfaced by the dead-target RED row — the rc1
		// scanSingle dropped dial refusals into empty-error records).
		rec.Error = res.Error
		diag.Emit(diag.Error, diag.DomTLS, "scan", t.Host, "TCP probe refused", errors.New(res.Error), nil)
		return rec
	}
	rec.Handshake = handshakeRecord{
		Negotiated: res.Negotiated,
		GroupName:  groupName(res.Negotiated),
		Suite:      res.Suite,
		Version:    versionName(res.Version),
		ALPNNeg:    res.ALPN,
	}
	if cls, ok := classify.GroupClass(res.Negotiated); ok {
		rec.Handshake.GroupClass = string(cls)
	}
	diag.Emit(diag.Info, diag.DomTLS, "scan", t.Host, "TCP handshake negotiated", nil,
		map[string]string{"negotiated": u32str(res.Negotiated), "suite": res.Suite, "group_class": rec.Handshake.GroupClass})

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
	return rec
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
