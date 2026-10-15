// Package differential is the PQ-22 parity engine: the gate that keeps
// pqscan's answers honest against the reference tools gnutls-cli-debug and
// sslyze (docs/spec.md#9-milestones, §10.1 Differential).
//
// Reference-tool transcripts come in through pure parsers
// (ParseGnutlsCLI, ParseSSLyze) fed by an INJECTED Runner seam — the
// real-tool exec harness is the PQ-22 second pair and never runs inside
// offline CI; tests inject canned tool outputs instead (ADR-0002).
// Parity(pqscan, refs) reduces both observation sets into per-check rows:
// protocol agreement (top TLS version), group-class agreement (the pqscan
// side classified via classify.GroupClass, the reference side via its
// textual detail), negotiated-suite agreement (pqscan's suite named by
// every observing reference tool) and — for anything not mappable — a
// NonAgreement row with a Note. Unknown shapes never crash the gate.
//
// The pqscan side is fed by the deep executor (second pair) using these
// check keys: "protocol" (detail = top observed version, e.g. "TLS1.3"),
// "suite" (detail = negotiated suite in RFC/IANA spelling), group rows
// ("group <IANA name>", see GroupCheck) and any other engine surface it
// wants surfaced (surfaced as rule-less rows).
package differential

import (
	"context"
	"errors"
)

// Obs is one observation handed to Parity: either built from pqscan's own
// engine output (Tool "pqscan") or parsed from a reference tool transcript.
// Observed detail only; classes are DERIVED here from the shared taxonomy
// (classify.GroupClass), never accepted as a tool's self-report — an
// asserted PQ flag on an obs would smuggle in the defect the gate exists
// to catch.
type Obs struct {
	Tool   string
	Check  string
	Detail string
}

// Comparison is one parity row for a check key present on either side.
// PQObs = the pqscan-side rendering of the row (the observed detail, plus
// the derived class in parentheses for group rows); Diff = the concrete
// divergence text ("" when Agree); Note = mapping note (unknown shapes,
// pqscan-only exceptions, rule-less checks).
type Comparison struct {
	Check string
	Agree bool
	PQObs string
	Diff  string
	Note  string
}

// Canonical check keys (spec: protocol / suite / group; anything else is
// rule-less and surfaced with a Note, never dropped silently).
const (
	CheckProtocol    = "protocol"
	CheckSuite       = "suite"
	CheckCertificate = "certificate"
)

// GroupCheck returns the parity row key for a group observation: the
// canonical IANA name for a group in the comparison name index (alias
// spellings collapse, e.g. OpenSSL's "prime256v1" → secp256r1), else the
// lower-cased raw token. The deep executor keys its group obs through this
// helper so both sides join on identical rows.
func GroupCheck(groupName string) string { return "" }

// Runner is the injected execution seam for the reference tools: the
// real-tool harness (second pair) supplies stdout-capturing runners; tests
// inject canned-output runners so nothing shells out in offline CI.
type Runner interface {
	Run(ctx context.Context, tool string, args ...string) (string, error)
}

// Tool/tool-name vocabulary for Scan.
const (
	ToolGnutlsCLIDebug = "gnutls-cli-debug"
	ToolSSLyze         = "sslyze"
)

// errNotImplemented is the watched-RED stub marker (ADR-0002): the RED
// commit ships these stubs so the tests compile and fail on assertions,
// never on compile errors.
var errNotImplemented = errors.New("differential engine: not implemented (watched-RED stub)")

// Scan runs the named reference tool through the INJECTED runner, parses
// the captured output into observations and returns them. Unknown tool
// names error out (never a crash); empty output errors out (never compare
// against nothing).
func Scan(ctx context.Context, tool string, r Runner, args ...string) ([]Obs, error) {
	return nil, errNotImplemented
}

// ParseGnutlsCLI parses gnutls-cli-debug's transcript into observations:
// the per-check verdict lines ("for TLS 1.3 (RFC8446) support... yes",
// "for curve X25519 (RFC8422)... yes") plus the summary shapes
// ("Protocols: TLS1.3, TLS1.2", "Ciphersuites: TLS1.3-AES128-GCM-SHA256",
// "- Version: ...", "- Ciphersuite: ..."). Protocol verdicts collapse to
// the top supported version; group verdicts become per-group rows
// ("yes" = the canonical group name, "no" = "not accepted"); suites list
// as accepted-suite rows under canonical IANA names. Non-parity checks
// (renegotiation, MACs, ciphers-family, ...) are ignored. A transcript
// with no recognizable reference-tool shape errors out.
func ParseGnutlsCLI(output string) ([]Obs, error) {
	return nil, errNotImplemented
}

// ParseSSLyze parses sslyze's JSON output into observations from its
// scan_result fields: per-version cipher-suite results (protocol evidence
// + accepted suites), the elliptic_curves result (supported/rejected
// groups) and the leaf certificate info (signature + key). Unknown JSON
// shapes error out with a recognizable message; malformed JSON errors out.
func ParseSSLyze(output string) ([]Obs, error) {
	return nil, errNotImplemented
}

// Parity compares the pqscan-side observations with the reference-tool
// observations check by check and returns one row per joined key
// (deterministic, sorted by Check):
//
//   - protocol: agreement on the top observed TLS version
//     (both = TLS1.3 = agree).
//   - suite: agreement when pqscan's negotiated suite is named by every
//     observing reference tool (suite spellings normalized through the
//     gnutls/RFC equivalence table; un-normalizable names → NonAgreement
//     with a Note).
//   - group <name>: class agreement — the pqscan side's classification
//     comes from classify.GroupClass (via the name index), the reference
//     side's semantic from its textual detail. A PQ-class mismatch is
//     flagged (NonAgreement + Diff text). A group only pqscan observed is
//     the documented exception (the reference tools cannot construct PQ
//     groups): Agree=true with an explanatory Note.
//   - anything else: NonAgreement with a Note ("no parity rule"), never a
//     crash; reference details that resolve to nothing get the same
//     treatment.
func Parity(pqscan []Obs, refs []Obs) []Comparison {
	return nil
}
