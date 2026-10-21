package grammar

import (
	"reflect"
	"strings"
	"testing"
)

// parseCase is one row of the target-grammar acceptance table. wantErr is a
// substring the returned error must contain; empty means Parse must succeed
// with exactly the want targets.
type parseCase struct {
	name    string
	spec    string
	want    []Target
	wantErr string
}

// TestParse pins the target grammar (issue #38 / PQ-15, spec §5.1): bare
// hosts and IP literals default to port 443, host:port, bracketed IPv6
// "[addr]:port" (the only form that attaches a port to IPv6), CIDR v4/v6
// (one Target per network with its prefix length) and the "--" stdin marker.
// Everything else — empty/whitespace specs, bare ports, out-of-range ports,
// malformed CIDRs, bracket mistakes and URL-scheme prefixes — is rejected
// with a directional error.
func TestParse(t *testing.T) {
	for _, tc := range []parseCase{
		// ---- accepted forms ----
		{
			name: "bare domain defaults to port 443",
			spec: "example.com",
			want: []Target{{Input: "example.com", Host: "example.com", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "single-label host",
			spec: "localhost",
			want: []Target{{Input: "localhost", Host: "localhost", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "host with explicit port",
			spec: "scanner.example.com:8443",
			want: []Target{{Input: "scanner.example.com:8443", Host: "scanner.example.com", Port: 8443, Class: "host", Prefix: 0}},
		},
		{
			name: "host at the maximal port",
			spec: "example.com:65535",
			want: []Target{{Input: "example.com:65535", Host: "example.com", Port: 65535, Class: "host", Prefix: 0}},
		},
		{
			name: "host at the minimal port",
			spec: "example.com:1",
			want: []Target{{Input: "example.com:1", Host: "example.com", Port: 1, Class: "host", Prefix: 0}},
		},
		{
			name: "surrounding whitespace is trimmed",
			spec: "  example.com  ",
			want: []Target{{Input: "example.com", Host: "example.com", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "ipv4 literal defaults to port 443",
			spec: "10.1.2.3",
			want: []Target{{Input: "10.1.2.3", Host: "10.1.2.3", Port: 443, Class: "ip", Prefix: 0}},
		},
		{
			name: "ipv4 literal with port",
			spec: "10.1.2.3:9443",
			want: []Target{{Input: "10.1.2.3:9443", Host: "10.1.2.3", Port: 9443, Class: "ip", Prefix: 0}},
		},
		{
			name: "ipv6 literal defaults to port 443",
			spec: "::1",
			want: []Target{{Input: "::1", Host: "::1", Port: 443, Class: "ip", Prefix: 0}},
		},
		{
			name: "expanded ipv6 literal is canonicalised",
			spec: "0:0:0:0:0:0:0:1",
			want: []Target{{Input: "0:0:0:0:0:0:0:1", Host: "::1", Port: 443, Class: "ip", Prefix: 0}},
		},
		{
			// Anything that parses as an address IS an address: an
			// unbracketed "::1:8443" is the unicast address ...:1:8443,
			// never a port on ::1 — brackets are the way to attach ports
			// to IPv6 literals.
			name: "unbracketed ipv6 with a colon group is an address, not a port",
			spec: "::1:8443",
			want: []Target{{Input: "::1:8443", Host: "::1:8443", Port: 443, Class: "ip", Prefix: 0}},
		},
		{
			name: "bracketed ipv6 with port",
			spec: "[::1]:443",
			want: []Target{{Input: "[::1]:443", Host: "::1", Port: 443, Class: "ip", Prefix: 0}},
		},
		{
			name: "bracketed ipv6 full form with port",
			spec: "[2001:db8::1]:8443",
			want: []Target{{Input: "[2001:db8::1]:8443", Host: "2001:db8::1", Port: 8443, Class: "ip", Prefix: 0}},
		},
		{
			name: "bracketed ipv6 without port",
			spec: "[2001:db8::1]",
			want: []Target{{Input: "[2001:db8::1]", Host: "2001:db8::1", Port: 443, Class: "ip", Prefix: 0}},
		},
		{
			name: "cidr v4 yields one network target",
			spec: "192.168.1.0/24",
			want: []Target{{Input: "192.168.1.0/24", Host: "192.168.1.0", Port: 443, Class: "cidr", Prefix: 24}},
		},
		{
			name: "cidr v4 masks host bits to the network",
			spec: "192.168.1.7/24",
			want: []Target{{Input: "192.168.1.7/24", Host: "192.168.1.0", Port: 443, Class: "cidr", Prefix: 24}},
		},
		{
			name: "cidr v4 single-address prefix",
			spec: "10.0.0.1/32",
			want: []Target{{Input: "10.0.0.1/32", Host: "10.0.0.1", Port: 443, Class: "cidr", Prefix: 32}},
		},
		{
			name: "cidr v6 yields one network target",
			spec: "2001:db8::/32",
			want: []Target{{Input: "2001:db8::/32", Host: "2001:db8::", Port: 443, Class: "cidr", Prefix: 32}},
		},
		{
			name: "cidr v6 single-address prefix",
			spec: "2001:db8::1/128",
			want: []Target{{Input: "2001:db8::1/128", Host: "2001:db8::1", Port: 443, Class: "cidr", Prefix: 128}},
		},
		{
			name: "stdin marker carries no host or port",
			spec: "--",
			want: []Target{{Input: "--", Host: "", Port: 0, Class: "stdin", Prefix: 0}},
		},

		// ---- rejected forms ----
		{
			name:    "empty spec",
			spec:    "",
			wantErr: "empty",
		},
		{
			name:    "whitespace-only spec",
			spec:    "   ",
			wantErr: "empty",
		},
		{
			name:    "tab-only spec",
			spec:    "\t\t",
			wantErr: "empty",
		},
		{
			name:    "internal whitespace",
			spec:    "example com",
			wantErr: "whitespace",
		},
		{
			name:    "internal tab",
			spec:    "exa\tmple",
			wantErr: "whitespace",
		},
		{
			name:    "bare port by missing host before the colon",
			spec:    ":443",
			wantErr: "bare port",
		},
		{
			name:    "bare port with no host at all",
			spec:    "443",
			wantErr: "bare port",
		},
		{
			name:    "host with empty port",
			spec:    "example.com:",
			wantErr: "missing port",
		},
		{
			name:    "port zero is out of range",
			spec:    "example.com:0",
			wantErr: "out of range",
		},
		{
			name:    "negative port is not a port",
			spec:    "example.com:-1",
			wantErr: "invalid port",
		},
		{
			name:    "non-numeric port",
			spec:    "example.com:abc",
			wantErr: "invalid port",
		},
		{
			name:    "port above the range",
			spec:    "example.com:65536",
			wantErr: "out of range",
		},
		{
			name:    "port integer overflow",
			spec:    "example.com:99999999999999999999",
			wantErr: "out of range",
		},
		{
			name:    "unbracketed multi-colon spec is ambiguous",
			spec:    ":::8000",
			wantErr: "brackets",
		},
		{
			name:    "unclosed bracket",
			spec:    "[::1:443",
			wantErr: "brackets",
		},
		{
			name:    "bracketed but empty host",
			spec:    "[]:443",
			wantErr: "missing host",
		},
		{
			name:    "invalid cidr v4 prefix length",
			spec:    "10.0.0.0/33",
			wantErr: "invalid CIDR",
		},
		{
			name:    "invalid cidr v6 prefix length",
			spec:    "2001:db8::/129",
			wantErr: "invalid CIDR",
		},
		{
			name:    "cidr on a hostname is not a network",
			spec:    "example.com/24",
			wantErr: "invalid CIDR",
		},
		{
			name:    "cidr missing the prefix length",
			spec:    "10.0.0.0/",
			wantErr: "invalid CIDR",
		},
		{
			name:    "http scheme prefix is rejected",
			spec:    "http://example.com",
			wantErr: "reads host/port",
		},
		{
			name:    "https scheme prefix with a port is rejected",
			spec:    "https://example.com:8443",
			wantErr: "reads host/port",
		},
		{
			name:    "ftp scheme prefix on an ipv4 literal is rejected",
			spec:    "ftp://10.1.2.3",
			wantErr: "reads host/port",
		},
		{
			name:    "empty scheme prefix is rejected",
			spec:    "://example.com",
			wantErr: "scheme",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.spec)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error containing %q", tc.spec, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Parse(%q) error = %q, want containing %q", tc.spec, err, tc.wantErr)
				}
				if got != nil {
					t.Errorf("Parse(%q) = %+v alongside an error; want nil targets", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) error = %v, want %+v", tc.spec, err, tc.want)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("Parse(%q) returned %d targets, want %d: got %#v", tc.spec, len(got), len(tc.want), got)
			}
			for i, want := range tc.want {
				if !reflect.DeepEqual(got[i], want) {
					t.Fatalf("Parse(%q)[%d]:\n got:  %#v\n want: %#v", tc.spec, i, got[i], want)
				}
			}
		})
	}
}
