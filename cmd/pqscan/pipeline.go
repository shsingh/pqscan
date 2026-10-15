// Multi-target run pipeline (PQ-15, second slice): the grammar
// (internal/grammar) is wired into the run() path — composed -u / -l / --
// specs parse into []grammar.Target, the Engine scans them in order in
// fast mode, and progress reports every N targets (the 50-target
// convention). Encoders/WAL remain PQ-16.
package main

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/shsingh/pqscan/internal/grammar"
)

// errNotImplemented guards the watched-RED state of this slice (ADR-0002):
// the contract-carrying tests run against stub bodies first, then the GREEN
// commit fills them in.
var errNotImplemented = errors.New("not implemented: the multi-target pipeline lands with PQ-15")

// errNoTargets reports an empty composed target list to the caller.
var errNoTargets = errors.New("no targets")

// errCidrTargets refuses CIDR-class targets: the per-address expansion is
// PQ-16 scope.
var errCidrTargets = errors.New("cidr expansion lands with PQ-16")

// progressEvery is the default progress interval: a report line every 50
// targets processed (standing user convention), plus one final report.
const progressEvery = 50

// defaultProbeTimeout is the per-plane probe budget (rc1 scanSingle value).
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
	return nil, errNotImplemented
}
