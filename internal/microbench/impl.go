package microbench

import (
	"crypto/tls"
	"net"
	"time"
)

// MeasureHost performs n fast-mode handshakes sequentially against addr
// (forced hybrid-capable groups; SNI = host) with timed decomposition:
// each attempt splits connect RTT from the TLS handshake (spec §7.1).
func MeasureHost(addr, host string, n int, timeout time.Duration) (*Results, error) {
	res := &Results{Targets: addr, Attempted: n}
	start := time.Now()
	for i := 0; i < n; i++ {
		d := measureOnce(addr, host, timeout)
		res.Decompositions = append(res.Decompositions, *d)
		if d.HandshakeMs > 0 {
			res.Negotiated++
		}
	}
	res.ElapsedTotalS = time.Since(start).Seconds()
	return res, nil
}

func measureOnce(addr, host string, timeout time.Duration) *Decomposition {
	d := &Decomposition{}
	start := time.Now()
	nc, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	d.ConnectMs = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		return d
	}
	defer nc.Close() //nolint:errcheck

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // negotiation timing is the measurement
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		MinVersion:         tls.VersionTLS13,
	}
	tc := tls.Client(nc, cfg)
	hsStart := time.Now()
	err = tc.Handshake()
	d.HandshakeMs = float64(time.Since(hsStart).Microseconds()) / 1000
	d.TotalMs = d.ConnectMs + d.HandshakeMs
	if err != nil {
		d.HandshakeMs = -d.HandshakeMs // negative marks a failed flight
	}
	return d
}

// MeasureConcurrent runs workers × perWorker handshakes concurrently and
// aggregates — the W in T ≈ W/L (spec §7.1): the per-core SLO evidence.
func MeasureConcurrent(addr, host string, workers, perWorker int, timeout time.Duration) (*Results, error) {
	res := &Results{Targets: addr, Attempted: workers * perWorker}
	type agg struct {
		negotiated int
		decomps    []Decomposition
		elapsed    float64
	}
	out := make(chan agg, workers)
	for w := 0; w < workers; w++ {
		go func() {
			start := time.Now()
			d := agg{}
			for i := 0; i < perWorker; i++ {
				r, _ := MeasureHost(addr, host, 1, timeout)
				d.negotiated += r.Negotiated
				d.decomps = append(d.decomps, r.Decompositions...)
			}
			d.elapsed = time.Since(start).Seconds()
			out <- d
		}()
	}
	startWall := time.Now()
	for w := 0; w < workers; w++ {
		a := <-out
		res.Negotiated += a.negotiated
		res.Decompositions = append(res.Decompositions, a.decomps...)
	}
	res.ElapsedTotalS = time.Since(startWall).Seconds()
	return res, nil
}
