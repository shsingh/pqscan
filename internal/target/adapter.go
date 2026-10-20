// Package target hosts the target input surface (spec §5.7's grammar-in
// dialect parsers): the PD-dialect adapters FromHTTPX and FromNaabu and
// the raw -l/-- wrapper FromLines. Grammar owns parsing
// (internal/grammar): every adapter line is handed to grammar.Parse the
// same way the -u composition feeds it, so one grammar — and one dedupe
// layer, applied by the run pipeline's composition (host:port, first
// occurrence wins) — serves every input source.
//
// The PQ-04-era target.Input stub is retired here: its fields duplicated
// grammar.Target and no Go code referenced the type (the reconciliation
// the pipeline lane flagged for issue #80).
package target

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/shsingh/pqscan/internal/grammar"
)

// FromHTTPX parses httpx output lines into grammar targets (issue #80 /
// PQ-35; spec §5.7). httpx text-mode lines are host-URI-ish —
// scheme://host:port with an optional URL path suffix — and its list
// lines come as bare host:port or bare host (which keeps the grammar's
// https default, port 443). The scheme and any path suffix are
// decoration: each line is stripped to its host[:port] spec and handed to
// grammar.Parse exactly as the -u composition parses a spec, so the
// composition's dedupe semantics (host:port, first occurrence wins)
// apply unchanged when the pipeline composes this result with its other
// sources — the adapter does NOT dedupe.
//
// Comment lines (#) and blank lines are skipped but still numbered. The
// first rejected spec aborts the whole stream: the composition refuses
// the run on a bad spec, so no partial list is ever scanned.
func FromHTTPX(r io.Reader) ([]grammar.Target, error) {
	return scanLines(r, func(no int, line string) ([]grammar.Target, error) {
		if isComment(line) {
			return nil, nil
		}
		targets, err := grammar.Parse(stripDialectDecor(line))
		if err != nil {
			return nil, lineErr(no, err)
		}
		return targets, nil
	}, nil)
}

// FromNaabu parses naabu output lines into grammar targets (issue #80 /
// PQ-35; spec §5.7). The text dialect is host:port per line
// (hackerone.com:443 — hostnames as naabu resolved them, bare IPs
// as-is), or the bare-host block shape: a host line followed by a ports
// list of bare decimal ports (indented or not):
//
//	example.com
//	    80
//	    443
//
// A bare host whose ports block never arrives, and a host line that
// closes after another host line with no port in between (naabu's
// host-discovery list), parses as a bare-host spec — the grammar's https
// default (443) applies. Each host:port pair goes through
// grammar.Parse, so no adapter-level dedupe: the composition's dedupe
// semantics are the same ones the -u/-l/-- specs get.
//
// Comment lines (#) and blank lines are skipped but still numbered; the
// first rejected spec aborts the whole stream (the composition refuses
// the run on a bad spec, so no partial list is scanned).
func FromNaabu(r io.Reader) ([]grammar.Target, error) {
	var (
		host     string // the open ports block's host spec ("" = none)
		hostLine int    // the physical line host came from
		consumed bool   // the block has emitted at least one port
	)
	// closePending parses a bare host whose ports block never received a
	// port line; the annotation keeps the host's own line number.
	closePending := func() ([]grammar.Target, error) {
		if host == "" || consumed {
			return nil, nil
		}
		targets, err := grammar.Parse(host)
		if err != nil {
			return nil, lineErr(hostLine, err)
		}
		return targets, nil
	}
	return scanLines(r, func(no int, line string) ([]grammar.Target, error) {
		if isComment(line) {
			return nil, nil
		}
		switch {
		case isPortLine(line):
			if host == "" {
				return nil, lineErr(no, fmt.Errorf("port %q outside a ports block: naabu output emits the host line first", line))
			}
			targets, err := grammar.Parse(host + ":" + line)
			if err != nil {
				return nil, lineErr(no, err)
			}
			consumed = true
			return targets, nil
		case strings.Contains(line, ":"):
			targets, err := grammar.Parse(line)
			if err != nil {
				return nil, lineErr(no, err)
			}
			return targets, nil
		default:
			// A bare host closes an unconsumed ports block
			// (host-discovery list) and opens the next one.
			targets, err := closePending()
			if err != nil {
				return nil, err
			}
			host, hostLine, consumed = line, no, false
			return targets, nil
		}
	}, closePending)
}

// FromLines reads newline-separated grammar specs — the raw path the
// composition reads from a -l file (and the "--" positional specs) — as
// one adapter-shaped surface, so the pipeline composes every input source
// identically. Blank and whitespace-only lines are skipped (readSpecs
// semantics); every other line is handed to grammar.Parse unchanged, so
// classes pass through untouched (a CIDR line parses as a cidr-class
// target — the composition refuses the class; the "--" marker stays a
// stdin-class target exactly as grammar.Parse yields it). The raw path
// has no comment convention — only the -from-* dialects skip # lines.
// Errors abort with the 1-based line number.
func FromLines(r io.Reader) ([]grammar.Target, error) {
	return scanLines(r, func(no int, line string) ([]grammar.Target, error) {
		targets, err := grammar.Parse(line)
		if err != nil {
			return nil, lineErr(no, err)
		}
		return targets, nil
	}, nil)
}

// scanLines fans a reader into grammar targets: every physical line is
// numbered 1-based (blanks and — where the adapter wants them — comments
// are skipped but numbered); each surviving line goes to feed in order
// and end (optional) flushes stream-tail state (naabu's trailing bare
// host) after the last line. feed and end annotate their own errors (via
// lineErr — a feed error does not know the surrounding line number, so
// nothing is double-prefixed here). The first error aborts the whole
// stream; no partial target list escapes a failed parse. The reader
// shape is the composition's (readSpecs): one line at a time,
// whitespace-trimmed.
func scanLines(r io.Reader, feed func(no int, line string) ([]grammar.Target, error), end func() ([]grammar.Target, error)) ([]grammar.Target, error) {
	var all []grammar.Target
	sc := bufio.NewScanner(r)
	no := 0
	for sc.Scan() {
		no++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		targets, err := feed(no, line)
		if err != nil {
			return nil, err
		}
		all = append(all, targets...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading targets: %w", err)
	}
	if end != nil {
		targets, err := end()
		if err != nil {
			return nil, err
		}
		all = append(all, targets...)
	}
	return all, nil
}

// lineErr annotates an adapter error with the physical 1-based line
// number (blanks and comments count toward it).
func lineErr(no int, err error) error {
	return fmt.Errorf("line %d: %w", no, err)
}

// isComment reports whether a trimmed line is a # comment. Only the
// -from-* dialects skip them: the raw -l/-- path has no comment
// convention (its lines are grammar specs).
func isComment(line string) bool {
	return strings.HasPrefix(line, "#")
}

// isPortLine reports whether a trimmed line is a bare decimal port — the
// port line of a naabu ports block (naabu emits the host line first).
func isPortLine(line string) bool {
	if line == "" {
		return false
	}
	for _, r := range line {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// stripDialectDecor strips the URL decoration an httpx line can carry: an
// optional scheme (everything through "://") and a path suffix (from the
// first "/" onwards). What remains is a host[:port] spec for
// grammar.Parse; bracketed IPv6 keeps working because the brackets close
// before any path separator. (The PD dialects carry hosts and host:port
// only — CIDRs belong to the -cidr grammar path, not these adapters.)
func stripDialectDecor(line string) string {
	if i := strings.Index(line, "://"); i >= 0 {
		line = line[i+3:]
	}
	if j := strings.Index(line, "/"); j >= 0 {
		line = line[:j]
	}
	return line
}

// StripScheme strips the accepted scheme:// prefix from one spec-path
// target line (-u/-l/-- composition; PQ-41, issue #117): "everything
// through ://" leaves — the SAME decoration rule the adapter dialects
// apply to their lines (the adapter then also handles any URL path; see
// stripDialectDecor) — so one internal/target rule serves every input
// source and the USAGE -u row's scheme://host[:port] promise is the
// engine's behavior. What remains is a host[:port] spec for
// grammar.Parse; bracketed IPv6 keeps working because the brackets close
// before any path separator.
//
// A URL path suffix stays REFUSED on the spec path, naming the adapter:
// path decoration is the -from-httpx adapter's business (pqscan
// -from-httpx FILE strips scheme AND path). A line without a scheme
// prefix — bare hosts, host:port, CIDRs, the "--" marker — passes
// through untouched (the grammar owns the "/" through the CIDR class),
// and an empty-scheme prefix ("://host") passes through too: an empty
// scheme is not a scheme, and the grammar's own refusal keeps owning the
// honestly-unparseable shapes.
func StripScheme(line string) (string, error) {
	i := strings.Index(line, "://")
	if i <= 0 {
		return line, nil
	}
	rest := line[i+3:]
	if j := strings.Index(rest, "/"); j >= 0 {
		return "", fmt.Errorf("URL path %q in target spec %q: a URL path is the -from-httpx adapter's decoration (-from-httpx FILE strips scheme and path; the spec path keeps host[:port])", rest[j:], line)
	}
	if rest == "" {
		return "", fmt.Errorf("target spec %q: nothing after the scheme prefix (want scheme://host[:port])", line)
	}
	return rest, nil
}

// FromNuclei parses nuclei -j findings JSONL into grammar targets (PQ-55,
// issue #149; spec §6's import chain). The pinned capture
// `nuclei -l hosts.txt -silent -j` (nuclei v3.11.1) emits ONE JSON finding
// per line; every finding contributes the host:port of its matched-at (the
// url field is the fallback where matched-at is empty), with the SAME
// dialect decoration rule the httpx lines walk (stripDialectDecor): a
// matched-at reads scheme://host[:port][path] or bare host[:port] — the
// scheme and any path suffix strip to a host[:port] spec, handed to
// grammar.Parse exactly as the -u composition parses a -u spec, so the
// composition's dedupe semantics (host:port, first occurrence wins) apply
// unchanged when the pipeline composes this result with its other sources.
// The adapter does NOT dedupe: nuclei findings repeat one host:port across
// many findings (the pinned capture: 28 findings → two distinct
// host:ports), and the collapse is the composition's one dedupe layer.
//
// The findings' remaining fields (the template's identity, the info/matcher
// blocks, the request/response bodies) are not target material: the parser
// consumes exactly the two host fields the pinned capture shows. Comment
// (#) and blank lines are skipped but still numbered (the -from-* dialect
// convention: every pinned fixture file carries its header comments). A
// line that is not a findings object — unparseable JSON, or a JSON object
// carrying neither matched-at nor url — is a recorded observation at its
// line number: the stream aborts, the composition refuses the run exit 64
// named by its flag, so no partial list is ever scanned.
func FromNuclei(r io.Reader) ([]grammar.Target, error) {
	return scanLines(r, func(no int, line string) ([]grammar.Target, error) {
		if isComment(line) {
			return nil, nil
		}
		var finding struct {
			MatchedAt string `json:"matched-at"`
			URL       string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			return nil, lineErr(no, fmt.Errorf("not a nuclei findings JSONL object (want the -j object per line): %w", err))
		}
		spec := finding.MatchedAt
		if spec == "" {
			spec = finding.URL
		}
		if spec == "" {
			return nil, lineErr(no, fmt.Errorf("nuclei finding with neither matched-at nor url (want the -j finding's host fields)"))
		}
		targets, err := grammar.Parse(stripDialectDecor(spec))
		if err != nil {
			return nil, lineErr(no, err)
		}
		return targets, nil
	}, nil)
}
