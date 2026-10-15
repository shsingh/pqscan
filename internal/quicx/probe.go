package quicx

import (
	"context"
	"crypto/tls"
	"runtime"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shsingh/pqscan/internal/classify"
)

// convert maps the ladder's codepoints to CurveIDs.
func conv(in []uint32) []tls.CurveID {
	out := make([]tls.CurveID, len(in))
	for i, v := range in {
		out[i] = tls.CurveID(v)
	}
	return out
}

// ProbeQUIC runs one QUIC v1 handshake (TLS 1.3 inside QUIC, ALPN h3)
// with forced group preferences; reports the negotiated group via the
// session's TLS ConnectionState (spec §5.7, §7.5). Server silence and
// refusals are classified as results, never errors.
func ProbeQUIC(addr, host string, groups []uint32, timeout time.Duration) (*QuicResult, error) {
	res := &QuicResult{Version: 1}

	tlsCfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true, // negotiation is the assertion; cert analytics is a separate probe
		CurvePreferences:   conv(groups),
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
		return res, nil // rejections are results
	}
	defer sess.CloseWithError(0, "") //nolint:errcheck

	cs := sess.ConnectionState()
	res.State = "negotiated"
	res.Group = uint32(cs.TLS.CurveID)
	res.ALPN = cs.TLS.NegotiatedProtocol
	res.HandshakeMs = float64(time.Since(start).Microseconds()) / 1000
	if cls, ok := classify.GroupClass(res.Group); ok {
		res.GroupClass = string(cls)
	}
	return res, nil
}

// classifyUDP maps a dial/handshake failure to its result class.
func classifyUDP(errText string) (state string, blocked bool) {
	switch {
	case strings.Contains(errText, "connection refused"):
		return "refused", false
	case strings.Contains(errText, "Timeout") || strings.Contains(errText, "timeout") ||
		strings.Contains(errText, "handshake did not complete") ||
		strings.Contains(errText, "no recent network activity"):
		return "blocked", true // server silent: policy-filtered or unreachable
	default:
		return "error", false
	}
}

// MeasureCost runs `sessions` sequential QUIC dials (GC between each),
// reporting per-session timing and the process goroutine footprint — the
// 10k in-flight budget inputs (spec §7.5).
func MeasureCost(addr, host string, sessions int, timeout time.Duration) (*CostStats, error) {
	if sessions < 1 {
		return nil, errNotImplementedShortRun
	}
	stats := &CostStats{Sessions: sessions}
	goroutineBase := runtime.NumGoroutine()
	totalMs := 0.0
	negotiated := 0
	for i := 0; i < sessions; i++ {
		runtime.GC()
		r, err := ProbeQUIC(addr, host, []uint32{4588}, timeout)
		if err != nil {
			return nil, err
		}
		if r.State != "negotiated" {
			continue
		}
		negotiated++
		totalMs += r.HandshakeMs
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	stats.AvgTotalMs = totalMs / float64(negotiated)
	stats.Goroutines = runtime.NumGoroutine() - goroutineBase
	stats.HeapDeltaKB = float64(mem.HeapAlloc) / 1024
	if negotiated == 0 {
		stats.AvgTotalMs = 0
	}
	return stats, nil
}
