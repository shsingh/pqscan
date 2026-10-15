package quicx

import (
	"context"
	"crypto/tls"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shsingh/pqscan/internal/classify"
	"github.com/shsingh/pqscan/internal/diag"
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
		level := diag.Warn
		if res.State == "error" {
			level = diag.Error
		}
		diag.Emit(level, diag.DomQuic, "quic-handshake", addr, "QUIC handshake answered", nil,
			map[string]string{"offered": groupsJoined(groups), "state": res.State,
				"udp_blocked": strconv.FormatBool(res.UDPBlocked), "dial_ms": msF(res.DialMs)})
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
	diag.Emit(diag.Info, diag.DomQuic, "quic-handshake", addr, "QUIC v1 handshake", nil,
		map[string]string{"offered": groupsJoined(groups), "negotiated": strconvI(uint64(res.Group)),
			"group_class": res.GroupClass, "alpn": res.ALPN,
			"dial_ms": msF(res.DialMs), "handshake_ms": msF(res.HandshakeMs)})
	return res, nil
}

// groupsJoined packs the offered codepoints for the event fields.
func groupsJoined(groups []uint32) string {
	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		parts = append(parts, strconvI(uint64(g)))
	}
	return strings.Join(parts, ",")
}

func strconvI(u uint64) string { return strconv.FormatUint(u, 10) }

func msF(v float64) string { return strconv.FormatFloat(v, 'f', 3, 64) }

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
