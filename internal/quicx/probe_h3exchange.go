package quicx

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/shsingh/pqscan/internal/diag"
)

// probe_h3exchange.go — the functional HTTP/3 verification surface
// (PQ-69, issue #181): VerifyH3Exchange dials QUIC v1 (ALPN h3), waits
// for the server's SETTINGS frame on the control stream, then completes
// ONE HTTP/3 GET / through the pinned quic-go v0.63 http3 stack. The
// finding separates "ALPN h3 negotiated" from "an HTTP/3 exchange
// completed": a server that answers the handshake but carries no
// functional h3 layer records its own finding class at the executor.

// H3ExchangeResult carries one functional HTTP/3 exchange observation
// (PQ-69). The state vocabulary matches QuicResult's (the one dial-class
// word list): negotiated | refused | blocked | error for the QUIC
// dial/handshake phase.
type H3ExchangeResult struct {
	State      string // negotiated | refused | blocked | error
	ALPN       string // the negotiated ALPN ("h3" expected)
	UDPBlocked bool   // server silent / policy-filtered (recorded as a result)

	// Settings reports the server's HTTP/3 SETTINGS frame (the control
	// stream's mandatory first frame, RFC 9114 §4.2). Status carries
	// the ONE HTTP/3 GET /'s response status (0 = no completed
	// exchange). ExchangeErr is the h3 layer's failure text: the
	// server's own answers verbatim, the probe's class words for a
	// silent layer.
	Settings    bool
	Status      int
	ExchangeErr string

	DialMs     float64
	ExchangeMs float64

	// Err is the raw dial/handshake failure text for the classified
	// (non-negotiated) states — the wiring's honest-refusal classifier
	// re-reads it (the same contract as QuicResult.Err).
	Err string
}

// The h3 layer's probe-shaped class words (the probe states them; the
// remote's answers ride ExchangeErr verbatim).
const (
	h3NoSettings  = "the server sent no HTTP/3 SETTINGS frame"
	h3ALPNNeverH3 = "the negotiated ALPN is not h3"
)

// VerifyH3Exchange runs the functional HTTP/3 probe (PQ-69, issue #181,
// spec §5.3/§7.5): one QUIC v1 dial (ALPN h3, no forced group — the
// exchange verification tests the h3 layer, not group acceptance), then
// the server's SETTINGS frame, then ONE HTTP/3 GET / through the pinned
// quic-go http3 stack. Rejections and a broken h3 layer are classified
// as results, never errors; the exchange stops at the first missing
// plane (one fact per rung: no SETTINGS frame = no request attempt).
func VerifyH3Exchange(addr, host string, timeout time.Duration) (*H3ExchangeResult, error) {
	res := &H3ExchangeResult{}

	tlsCfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{H3ALPN},
		InsecureSkipVerify: true, // functional exchange is the assertion; cert analytics is a separate probe
		MinVersion:         tls.VersionTLS13,
	}
	qcfg := &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
		Versions:             []quic.Version{quic.Version1},
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
	defer cancel()
	sess, err := quic.DialAddr(ctx, addr, tlsCfg, qcfg)
	res.DialMs = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		res.State, res.UDPBlocked = classifyUDP(err.Error())
		res.Err = err.Error()
		level := diag.Warn
		if res.State == "error" {
			level = diag.Error
		}
		diag.Emit(level, diag.DomQuic, "h3-exchange", addr, "h3 exchange dial answered", nil,
			map[string]string{"state": res.State,
				"udp_blocked": strconv.FormatBool(res.UDPBlocked), "dial_ms": msF(res.DialMs)})
		return res, nil // rejections are results
	}
	defer sess.CloseWithError(0, "") //nolint:errcheck

	res.State = "negotiated"
	res.ALPN = sess.ConnectionState().TLS.NegotiatedProtocol
	if res.ALPN != H3ALPN {
		res.ExchangeErr = h3ALPNNeverH3 + " (alpn " + res.ALPN + ")"
		emitH3Exchange(res)
		return res, nil
	}

	tr := &http3.Transport{}
	cc := tr.NewClientConn(sess)
	select {
	case <-cc.ReceivedSettings():
		res.Settings = true
	case <-ctx.Done():
	}
	if !res.Settings {
		res.ExchangeErr = h3NoSettings
		emitH3Exchange(res)
		return res, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		res.ExchangeErr = err.Error()
		emitH3Exchange(res)
		return res, nil
	}
	exStart := time.Now()
	resp, err := cc.RoundTrip(req)
	res.ExchangeMs = float64(time.Since(exStart).Microseconds()) / 1000
	if err != nil {
		res.ExchangeErr = err.Error() // the server's h3-level answer, verbatim
		emitH3Exchange(res)
		return res, nil
	}
	res.Status = resp.StatusCode
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	emitH3Exchange(res)
	return res, nil
}

// emitH3Exchange lands the exchange's diagnostic event (the DomQuic
// decision record; the accepted rows carry the status).
func emitH3Exchange(res *H3ExchangeResult) {
	fields := map[string]string{
		"state":    res.State,
		"alpn":     res.ALPN,
		"settings": strconv.FormatBool(res.Settings),
		"status":   strconv.Itoa(res.Status),
		"dial_ms":  msF(res.DialMs),
	}
	level := diag.Info
	if res.State != "negotiated" || res.Status == 0 {
		level = diag.Warn
		fields["exerr"] = res.ExchangeErr
	}
	diag.Emit(level, diag.DomQuic, "h3-exchange", "", "h3 exchange", nil, fields)
}
