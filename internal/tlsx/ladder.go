package tlsx

import (
	"crypto/tls"
	"net"
	"time"
)

// ProbeResult is one row of the capability matrix: what was offered, what
// the server answered, and the observed negotiation (spec §5.4; JSONL
// mapping mirrors the schema in spec §5.7).
type ProbeResult struct {
	Offered        uint32 `json:"offered_group"`
	Shared         bool   `json:"shared"`
	Path           string `json:"path"`             // "stdlib" | "raw"
	State          string `json:"state"`            // negotiated | hrr | alert | read-error | error
	Negotiated     uint32 `json:"negotiated_group"` // stdlib path: 0 = unknown
	RequestedGroup uint32 `json:"requested_group"`  // raw path: HRR target
	Suite          string `json:"suite"`
	Version        uint16 `json:"version"`
	AlertDesc      uint8  `json:"alert"`
	Error          string `json:"error"`
}

// stdlibGroups are the codepoints the Go stack can construct a real share
// for (1.26+/toolchain floor; anything else is offered share-less via the
// raw path — the oracle probes).
func stdlibGroups(groups []uint32) bool {
	for _, g := range groups {
		switch g {
		case 4585, 4586, 4590, 25497, 25498:
			return false
		}
		if g > 65535 {
			return false
		}
	}
	return true
}

// ProbeNegotiated forces `groups` via crypto/tls and reports the observed
// negotiation end to end (real key shares, real HRR handling). addr is
// host:port; host carries the SNI.
func ProbeNegotiated(addr, host string, groups []uint32, timeout time.Duration) (*ProbeResult, error) {
	res := &ProbeResult{Offered: groups[0], Shared: true, Path: "stdlib"}
	curvePrefs := make([]tls.CurveID, 0, len(groups))
	for _, g := range groups {
		curvePrefs = append(curvePrefs, tls.CurveID(g))
	}
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // negotiation is the assertion; cert analytics is a separate probe
		CurvePreferences:   curvePrefs,
		MinVersion:         tls.VersionTLS12,
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err != nil {
		res.State = "error"
		res.Error = err.Error()
		return res, nil // rejection is a result, not a failure of the ladder
	}
	defer conn.Close() //nolint:errcheck

	cs := conn.ConnectionState()
	res.State = "negotiated"
	res.Negotiated = uint32(cs.CurveID)
	res.Version = cs.Version
	if id := cs.CipherSuite; id != 0 {
		res.Suite = tls.CipherSuiteName(cs.CipherSuite)
	}
	return res, nil
}

// GroupLadder runs the forced-group ladder against one host (spec §5.2 `pq`
// mode core, §7.4): standards-track groups through the stdlib path (real
// shares), everything else — the obsolete-Kyber oracle and exotic hybrids —
// share-less through the raw first-flight path, observing HRR/alerts and
// recording the server's demanded group where it asks for one.
func GroupLadder(addr, host string, groups []uint32, timeout time.Duration) []ProbeResult {
	out := make([]ProbeResult, 0, len(groups))
	for _, g := range groups {
		if stdlibGroups([]uint32{g}) {
			r, err := ProbeNegotiated(addr, host, []uint32{g}, timeout)
			if err != nil {
				out = append(out, ProbeResult{Offered: g, Path: "stdlib", State: "error", Error: err.Error()})
				continue
			}
			out = append(out, *r)
			continue
		}
		obs, err := SendHelloProbe(addr, host, []uint32{g}, 0)
		if err != nil {
			out = append(out, ProbeResult{Offered: g, Shared: false, Path: "raw", State: "error", Error: err.Error()})
			continue
		}
		out = append(out, ProbeResult{
			Offered:        g,
			Shared:         false,
			Path:           "raw",
			State:          obs.State,
			RequestedGroup: obs.RequestedGroup,
			Version:        obs.Version,
			AlertDesc:      obs.AlertDesc,
		})
	}
	return out
}
