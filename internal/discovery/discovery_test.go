package discovery

// The h3-discovery contract (PQ-25): the hint half against an in-process
// TLS fixture that answers GET / with crafted HTTP/1.1 response bytes (a
// header is text — no real h3 listener is needed for the hint), the
// direct half against the shared quicx h3 fixture (UDP and TCP ports are
// independent namespaces, so both halves can share one port). The live
// cloudflare proof is env-gated per ADR-0002: it never runs offline, and
// the offline suite proves the gate by skipping it.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/quicx"
)

// Crafted HTTP/1.1 response bytes for the hint-half fixture.
const (
	respH3Hint     = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nAlt-Svc: h3=\":8443\"; ma=86400\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	respNoAltSvc   = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	respH2OnlyHint = "HTTP/1.1 200 OK\r\nServer: pqscan-fixture\r\nAlt-Svc: h2=\":443\"; ma=86400\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)

// TestParseAltSvc: the loose directive grammar (RFC 7838) — any h3=
// assignment token marks the hint and the raw value is kept; other
// protocol ids (h2, h3-29-era drafts), clear, and malformed rows do not.
func TestParseAltSvc(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantH3  bool
		wantRaw string
	}{
		{"quoted authority", `h3=":8443"`, true, `h3=":8443"`},
		{"with parameters", `h3=":8443"; ma=86400`, true, `h3=":8443"; ma=86400`},
		{"named authority", `h3="alt.example:443"`, true, `h3="alt.example:443"`},
		{"case-insensitive token", `H3=":443"`, true, `H3=":443"`},
		{"h2 then h3", `h2=":443", h3=":8443"`, true, `h2=":443", h3=":8443"`},
		{"h2 only", `h2=":443"`, false, ""},
		{"draft token is not h3", `h3-29=":8443"`, false, ""},
		{"clear rescinds", `clear`, false, ""},
		{"clear padded", `clear `, false, ""},
		{"empty", "", false, ""},
		{"no assignment is malformed", `h3; ma=86400`, false, ""},
		{"whitespace tolerated", `  h3=":443"  `, true, `  h3=":443"  `},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h3, kept := parseAltSvc(tc.raw)
			if h3 != tc.wantH3 {
				t.Fatalf("parseAltSvc(%q) h3 = %v, want %v", tc.raw, h3, tc.wantH3)
			}
			if kept != tc.wantRaw {
				t.Fatalf("parseAltSvc(%q) raw = %q, want %q", tc.raw, kept, tc.wantRaw)
			}
		})
	}
}

// TestDiscoverFixtures: the full Discover contract against the offline
// fixtures (one port, two transports). Refusals and silence are results,
// not errors; caller aborts and contract misuse are the only errors.
func TestDiscoverFixtures(t *testing.T) {
	type buildResult struct {
		host string
		port uint16
	}
	cases := []struct {
		name      string
		timeout   time.Duration // 0 exercises the Options default fallback
		build     func(t *testing.T) buildResult
		want      Hints
		wantAbort error // sentinel via errors.Is; nil = result path (no error)
	}{
		{
			name:    "alt-svc hint and direct h3 agree",
			timeout: 5 * time.Second,
			build: func(t *testing.T) buildResult {
				addr := FixtureH3AndHint(t, []byte(respH3Hint)) // the coupled pair on both transports
				port := PortOf(t, addr)
				return buildResult{"127.0.0.1", uint16(port)}
			},
			want: Hints{AltSvcH3: true, H3Direct: true, AltSvcValue: `h3=":8443"; ma=86400`},
		},
		{
			name: "no alt-svc header = no hint",
			build: func(t *testing.T) buildResult {
				port := FixtureHintHTTP(t, 0, []byte(respNoAltSvc)) // TCP only: the direct half is answered by nothing
				return buildResult{"127.0.0.1", uint16(port)}
			},
			want: Hints{},
		},
		{
			name: "alt-svc without h3 token = no hint",
			build: func(t *testing.T) buildResult {
				port := FixtureHintHTTP(t, 0, []byte(respH2OnlyHint))
				return buildResult{"127.0.0.1", uint16(port)}
			},
			want: Hints{},
		},
		{
			name: "direct h3 without TLS (quic-only target)",
			build: func(t *testing.T) buildResult {
				addr := quicx.FixtureH3(t, nil)
				return buildResult{"127.0.0.1", uint16(PortOf(t, addr))}
			},
			want: Hints{H3Direct: true},
		},
		{
			name:    "transport refused is a result, not an error",
			timeout: 700 * time.Millisecond,
			build: func(t *testing.T) buildResult {
				return buildResult{"127.0.0.1", uint16(FreeTCPPort(t))}
			},
			want: Hints{},
		},
		{
			name: "cancelled context aborts",
			build: func(t *testing.T) buildResult {
				return buildResult{"127.0.0.1", uint16(FreeTCPPort(t))}
			},
			wantAbort: context.Canceled,
		},
		{
			name:      "empty host is contract misuse",
			build:     func(t *testing.T) buildResult { return buildResult{} },
			wantAbort: errHostRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := tc.build(t)
			ctx := context.Background()
			var cancel context.CancelFunc
			if tc.wantAbort != nil {
				ctx, cancel = context.WithCancel(ctx)
				cancel() // pre-cancelled: Discover must still return promptly
			}
			hints, err := Discover(ctx, tr.host, tr.port, Options{Timeout: tc.timeout})
			if !errors.Is(err, tc.wantAbort) {
				t.Fatalf("Discover err = %v, want %v", err, tc.wantAbort)
			}
			if tc.wantAbort != nil {
				if hints != nil {
					t.Fatalf("hints = %+v, want nil on abort", hints)
				}
				return
			}
			if hints == nil {
				t.Fatal("hints = nil on a result path, want zero-valued or populated Hints")
			}
			if *hints != tc.want {
				t.Fatalf("hints = %+v, want %+v", *hints, tc.want)
			}
		})
	}
}

// TestDiscoverEmitsDiagnostics: discovery emits the same decision events
// the planes do (the diag record covers the discovery surface too).
func TestDiscoverEmitsDiagnostics(t *testing.T) {
	sink, err := diag.NewSink(nil, 0)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	diag.SetDefault(sink)
	defer diag.SetDefault(nil)

	addr := FixtureH3AndHint(t, []byte(respH3Hint))
	port := PortOf(t, addr)
	if _, err := Discover(context.Background(), "127.0.0.1", uint16(port), Options{Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("discover: %v", err)
	}
	rep, err := sink.Report()
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	found := false
	for _, e := range rep.Events {
		if e.Domain == diag.DomQuic && e.Op == "h3-discovery" &&
			e.Fields["alt_svc_h3"] == "true" && e.Fields["h3_direct"] == "true" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no h3-discovery diagnostics with alt_svc_h3/h3_direct=true; events=%d", rep.Summary.Events)
	}
}

// TestMismatchStateClassification (the PQ-25 RED core): the hint/truth
// pairing table — both mismatch directions name their direction, the
// agreements leave the empty token so the probe's own state stands, and
// the flag rides the token exactly.
func TestMismatchStateClassification(t *testing.T) {
	cases := []struct {
		name        string
		hint, truth bool
		wantState   string
		wantFlag    bool
	}{
		{"agreement: hint=yes truth=yes", true, true, "", false},
		{"agreement: hint=no truth=no", false, false, "", false},
		{"the hint lied: hint=yes truth=no", true, false, "mismatch: hint=yes truth=no", true},
		{"h3 speaks unhinted: hint=no truth=yes", false, true, "mismatch: hint=no truth=yes", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, flag := MismatchState(tc.hint, tc.truth)
			if state != tc.wantState {
				t.Fatalf("MismatchState(hint=%v truth=%v) state = %q, want %q", tc.hint, tc.truth, state, tc.wantState)
			}
			if flag != tc.wantFlag {
				t.Fatalf("MismatchState(hint=%v truth=%v) flag = %v, want %v", tc.hint, tc.truth, flag, tc.wantFlag)
			}
		})
	}
}

// TestProbeHintFixtures: the hint half alone (the wiring seam the fast
// lane composes the QUIC gate from). Hits and misses are results; the
// raw alt-svc value is kept with the hint; caller aborts are the only
// errors.
func TestProbeHintFixtures(t *testing.T) {
	cases := []struct {
		name     string
		build    func(t *testing.T) (host string, port uint16)
		wantHint bool
		wantRaw  string
		wantErr  error
	}{
		{
			name: "alt-svc h3 hint found, raw value kept",
			build: func(t *testing.T) (string, uint16) {
				port := FixtureHintHTTP(t, 0, []byte(respH3Hint)) // the hint half binds and holds its own number
				return "127.0.0.1", uint16(port)
			},
			wantHint: true,
			wantRaw:  `h3=":8443"; ma=86400`,
		},
		{
			name: "no alt-svc header = no hint",
			build: func(t *testing.T) (string, uint16) {
				return "127.0.0.1", uint16(FixtureHintHTTP(t, 0, []byte(respNoAltSvc)))
			},
		},
		{
			name: "h2-only alt-svc = no h3 hint",
			build: func(t *testing.T) (string, uint16) {
				return "127.0.0.1", uint16(FixtureHintHTTP(t, 0, []byte(respH2OnlyHint)))
			},
		},
		{
			name: "transport refused is a result, not an error",
			build: func(t *testing.T) (string, uint16) {
				return "127.0.0.1", uint16(FreeTCPPort(t))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port := tc.build(t)
			ctx := context.Background()
			var cancel context.CancelFunc
			if tc.wantErr != nil {
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			hint, raw, err := ProbeHint(ctx, host, port, Options{Timeout: 3 * time.Second})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ProbeHint err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if hint != tc.wantHint {
				t.Fatalf("hint = %v, want %v (raw %q)", hint, tc.wantHint, raw)
			}
			if raw != tc.wantRaw {
				t.Fatalf("raw = %q, want %q", raw, tc.wantRaw)
			}
		})
	}
}

const integrationEnv = "PQSCAN_INTEGRATION"

// integrationOnly gates live-network truth (never in CI): the gate reads
// the ENVIRONMENT, not the const name (the const merely names the var).
// The offline suite proves the gate by showing the SKIP lines.
func integrationOnly(t *testing.T) {
	t.Helper()
	if os.Getenv(integrationEnv) == "" {
		t.Skip("PQSCAN_INTEGRATION not set; live-network probe skipped")
	}
}

// TestIntegrationDiscoverCloudflare: the real-world proof — hint and
// truth agree on a hybrid edge: cloudflare.com serves alt-svc h3 on the
// HTTP/1.1 response and negotiates h3 over the direct QUIC handshake
// (spec §5.1, §5.3). Env-gated per ADR-0002; no invented transcripts.
func TestIntegrationDiscoverCloudflare(t *testing.T) {
	integrationOnly(t)

	hints, err := Discover(context.Background(), "cloudflare.com", 443, Options{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	t.Logf("cloudflare discovery: %+v", hints)
	if !hints.AltSvcH3 {
		t.Fatalf("alt-svc hint = %v (value %q); cloudflare serves the h3 hint", hints.AltSvcH3, hints.AltSvcValue)
	}
	if !hints.H3Direct {
		t.Fatal("direct h3 = false; want a negotiated QUIC h3 session")
	}
	if hints.AltSvcValue == "" {
		t.Fatal("raw alt-svc value not kept with the hint")
	}
}
