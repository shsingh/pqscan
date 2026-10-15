package tlsx

// suite_offer_test.go — PQ-20's offer-one test battery (spec §7.4): the
// fixture matrix drives the probe offline (accept, reject, refuse and
// construction-refusal rows, plus the plain version probe via the same
// call). Fixture servers are negotiation oracles (spec §10.1); a server
// answer is a result, never a run failure.
import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	fixtures "github.com/shsingh/pqscan/tests/fixtures/servers"
)

// offerRow is one offer-one matrix row: a fixture posture, the offered
// suite ("" = the default suite set: the version probe) and the forced
// version, and the finding vocabulary the observation must carry. caveat
// (when set) is a verbatim substring the observation's reason must carry.
type offerRow struct {
	name    string
	cfg     fixtures.ServerConfig
	addr    string // preset for the refusal rows (closed port): no server
	suite   string
	version uint16
	want    string // accepted | rejected | refused | error
	caveat  string // detail substring asserted on non-accepted rows
}

func offerFixtureRows() []offerRow {
	rows := []offerRow{
		{
			name: "1.3 suite offer-one is the fixed-set caveat (crypto/tls cannot restrict the 1.3 suite list)",
			cfg: fixtures.ServerConfig{
				Name: "t13", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			},
			suite: "TLS_AES_256_GCM_SHA384", version: tls.VersionTLS13,
			want:   "refused",
			caveat: "fixed 1.3 suite set",
		},
		{
			name: "1.2 suite offer-one accepted on a matching fixture",
			cfg: fixtures.ServerConfig{
				Name: "t12", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			},
			suite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", version: tls.VersionTLS12,
			want: "accepted",
		},
		{
			name: "1.2 suite offer-one rejected on a TLS-1.3-only fixture",
			cfg: fixtures.ServerConfig{
				Name: "t13", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			},
			suite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", version: tls.VersionTLS12,
			want: "rejected",
		},
		{
			name: "version probe (default suites) forced onto the negotiated version",
			cfg: fixtures.ServerConfig{
				Name: "t12", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			},
			version: tls.VersionTLS12,
			want:    "accepted",
		},
		{
			name: "version probe forced below the server's floor is rejected",
			cfg: fixtures.ServerConfig{
				Name: "t13", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			},
			version: tls.VersionTLS12,
			want:    "rejected",
		},
		{
			name:    "closed endpoint: dial-class failure is a refusal",
			addr:    "127.0.0.1:1",
			version: tls.VersionTLS12,
			want:    "refused",
		},
	}
	return rows
}

func TestSuiteOfferProbeMatrix(t *testing.T) {
	for _, row := range offerFixtureRows() {
		row := row
		t.Run(row.name, func(t *testing.T) {
			addr := row.addr
			if addr == "" {
				addr = fixtures.StartFixtureServer(t, row.cfg)
			}
			obs, err := SuiteOfferProbe(addr, "example.org", row.suite, row.version, 3*time.Second)
			if err != nil {
				t.Fatalf("SuiteOfferProbe: %v", err)
			}
			if obs.State != row.want {
				t.Fatalf("state = %q, want %q (obs=%+v)", obs.State, row.want, obs)
			}
			if row.want == "accepted" && obs.NegotiatedSuite == "" {
				t.Fatalf("accepted row must carry the negotiated answer (obs=%+v)", obs)
			}
			if row.caveat != "" && !strings.Contains(obs.Error, row.caveat) {
				t.Fatalf("reason %q missing the caveat %q", obs.Error, row.caveat)
			}
		})
	}
}

// TestSuiteOfferVersionOnlyNegotiated pins the version probe's payload:
// the same call with suiteName "" negotiates the forced version with the
// default suite set, and the observation reports both.
func TestSuiteOfferVersionOnlyNegotiated(t *testing.T) {
	addr := fixtures.StartFixtureServer(t, fixtures.ServerConfig{
		Name: "t12", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
	})
	obs, err := SuiteOfferProbe(addr, "example.org", "", tls.VersionTLS12, 3*time.Second)
	if err != nil {
		t.Fatalf("SuiteOfferProbe: %v", err)
	}
	if obs.State != "accepted" {
		t.Fatalf("state = %q, want accepted (obs=%+v)", obs.State, obs)
	}
	if obs.NegotiatedVersion != tls.VersionTLS12 {
		t.Fatalf("negotiated version = %#x, want 1.2", obs.NegotiatedVersion)
	}
	if obs.NegotiatedSuite == "" {
		t.Fatalf("negotiated suite empty (obs=%+v)", obs)
	}
}

// TestSuiteOfferUnknownSuitePinsConstructionRefusal: a suite name outside
// both stdlib lists is a caller-visible refusal row (SuiteError), verbatim
// — no silent substitution of a near name.
func TestSuiteOfferUnknownSuitePinsConstructionRefusal(t *testing.T) {
	obs, err := SuiteOfferProbe("127.0.0.1:1", "example.org", "TLS_NOPE_NOPE", tls.VersionTLS13, time.Second)
	if err != nil {
		t.Fatalf("SuiteOfferProbe: %v", err)
	}
	if obs.State != "error" {
		t.Fatalf("state = %q, want error", obs.State)
	}
	if obs.Error == "" {
		t.Fatalf("unknown-suite observation must carry the reason")
	}
	if !strings.Contains(obs.Error, "TLS_NOPE_NOPE") {
		t.Fatalf("error text should name the unknown suite: %q", obs.Error)
	}
}
