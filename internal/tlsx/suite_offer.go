package tlsx

// suite_offer.go is the PQ-20 offer-one probe surface (spec §7.4's suite
// + version matrix, --mode deep executor): one ADDITIVE helper beside the
// ladder — no change to any existing surface's shape.

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

// Suite observation states (the deep block's findings vocabulary, spec §8
// --mode: accepted | rejected | refused | error):
//
//   - accepted: the server negotiated the offered thing (a forced suite on
//     a forced version, or the browser-grade suite set on a forced
//     version — the plain version probe).
//   - rejected: the server SAW the offer and refused it (TLS alert class).
//   - refused: no TLS conversation happened (dial-class failure), or a
//     row the plane cannot offer at all (SuiteOffer's fixed-set caveat).
//   - error: any other probe-path failure (stalled reads, unknown suite).
const (
	SuiteAccepted = "accepted"
	SuiteRejected = "rejected"
	SuiteRefused  = "refused"
	SuiteError    = "error"
)

// SuiteObservation is one offer-one probe's outcome: what was offered, on
// which forced version, and the server's observed answer.
type SuiteObservation struct {
	Offered           string // offered suite name; "" = the default suite set
	WantVersion       uint16 // the FORCED protocol version (min = max)
	State             string // accepted | rejected | refused | error
	NegotiatedSuite   string // the server's answer (negotiated only)
	NegotiatedVersion uint16 // the negotiated version code (negotiated only)
	Error             string // the verbatim failure text (rejected/refused/error)
}

// SuiteOfferProbe offers ONE cipher suite on ONE forced protocol version
// and observes accept/reject (spec §7.4's offer-one row; PQ-20's suite
// dispatch). suiteName must be a stdlib-reported name (the secure list or
// the insecure list — an RC4/CBC offer is the scanner's legitimate fact);
// suiteName == "" offers the browser-grade default suite set, which makes
// the same call the VERSION probe (offer the version, default suites).
//
// The forced version is min=max (a single-version handshake: acceptance
// at one version implies nothing at another). TLS 1.3 caveat (spec §7.4's
// matrix note): crypto/tls does not restrict the 1.3 suite set — every 1.3
// offer carries the fixed set, so a 1.3 suite's per-suite accept/reject is
// NOT observable from the stdlib client; the caller records the 1.3 suite
// rows from the profile handshake's negotiated suite instead and never
// fakes offer-one there.
//
// Rejections are results (the observation carries the server's alert);
// the returned error is reserved for caller-level misuse (never for a
// server answer).
func SuiteOfferProbe(addr, host, suiteName string, version uint16, timeout time.Duration) (*SuiteObservation, error) {
	obs := &SuiteObservation{Offered: suiteName, WantVersion: version, Error: errSuiteOfferStub.Error()}
	return obs, nil
}

// errSuiteOfferStub is the PQ-20 watched-RED stub marker (implementation
// lands in the GREEN commit).
var errSuiteOfferStub = errors.New("tlsx: SuiteOfferProbe not implemented (PQ-20 RED stub)")

// offerClassify maps one failed offer handshake onto the findings
// vocabulary (the stdlib's error taxonomy: remote alert → rejected; dial
// class → refused; anything else → error). Client-side alert errors are
// bare AlertErrors; server-sent alerts ride `remote error: tls: …`
// wrapped in an OpError (any of which is a net.Error — the prefix check
// comes first, exactly because of that).
func offerClassify(err error) (state string) {
	text := ""
	if err != nil {
		text = err.Error()
	}
	var ae Alert
	if errors.As(err, &ae) || strings.HasPrefix(text, "remote error: tls: ") {
		return SuiteRejected
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return SuiteRefused
	}
	return SuiteError
}

// Alert aliases the stdlib's alert error type by name (errors.As target;
// a named uint8, not a struct literal).
type Alert = tls.AlertError
