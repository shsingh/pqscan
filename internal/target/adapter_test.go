package target

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/shsingh/pqscan/internal/grammar"
)

// adapterCase is one row of the input-adapter acceptance table. want is
// asserted exactly (every field, in order — the adapters return whatever
// grammar.Parse yields per line; the composition's dedupe by host:port
// applies on top, first occurrence wins). wantErr is a substring the
// returned error must contain; empty means the adapter must succeed with
// exactly the want targets.
type adapterCase struct {
	name    string
	in      string
	want    []grammar.Target
	wantErr string
}

// runAdapterCases runs one adapter against its table: on error the adapter
// must return NO targets (a bad line aborts the whole stream — the
// composition refuses the run on a bad spec, so partial lists are never
// silently scanned), and the error must name the 1-based line number.
func runAdapterCases(t *testing.T, from func(io.Reader) ([]grammar.Target, error), cases []adapterCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := from(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("error %q: got none (targets %s)", tc.wantErr, describeTargets(got))
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q: missing %q", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("error %q: got %d targets — a bad line must abort the stream, not return a partial list", tc.wantErr, len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("targets mismatch\n got: %s\nwant: %s", describeTargets(got), describeTargets(tc.want))
			}
		})
	}
}

// describeTargets renders a target list for failure output (field values
// and order visible).
func describeTargets(ts []grammar.Target) string {
	if ts == nil {
		return "<nil>"
	}
	out := "["
	for i, t := range ts {
		if i > 0 {
			out += "\n       "
		}
		out += fmt.Sprintf("{Input:%q Host:%q Port:%d Class:%q Prefix:%d}", t.Input, t.Host, t.Port, t.Class, t.Prefix)
	}
	return out + "]"
}

// TestFromHTTPX pins the -from-httpx adapter (issue #80 / PQ-35, spec
// §5.7 grammar-in dialect parsers): httpx text-mode lines are
// host-URI-ish — scheme://host:port with an optional URL path suffix —
// plus the plain host:port and bare-host list lines (an httpx list file
// carries hosts, which keep the grammar's https default). The scheme and
// any path suffix are decoration; the stripped spec is handed to
// grammar.Parse exactly as the -u composition would, so the identical
// parsing (and, downstream at the composition, dedupe) semantics apply.
// Duplicates are NOT deduped at the adapter: -u/-l/--/from-* all compose
// through the pipeline's dedupe, first occurrence wins.
//
// Line numbers are 1-based over every physical line (comments and blanks
// skipped but numbered); the first rejected spec aborts the stream.
func TestFromHTTPX(t *testing.T) {
	for _, tc := range []adapterCase{
		{
			name: "scheme://host:port parses as host:port",
			in:   "https://example.com:8443\n",
			want: []grammar.Target{{Input: "example.com:8443", Host: "example.com", Port: 8443, Class: "host", Prefix: 0}},
		},
		{
			name: "path suffix is stripped with the scheme",
			in:   "http://example.com:9443/a/b/c?d=e\n",
			want: []grammar.Target{{Input: "example.com:9443", Host: "example.com", Port: 9443, Class: "host", Prefix: 0}},
		},
		{
			name: "bare host line keeps the https default (443)",
			in:   "example.com\n",
			want: []grammar.Target{{Input: "example.com", Host: "example.com", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "host:port line passes through unchanged",
			in:   "example.com:8443\n",
			want: []grammar.Target{{Input: "example.com:8443", Host: "example.com", Port: 8443, Class: "host", Prefix: 0}},
		},
		{
			name: "bracketed IPv6 with port and path suffix",
			in:   "https://[2001:db8::1]:8443/path\n",
			want: []grammar.Target{{Input: "[2001:db8::1]:8443", Host: "2001:db8::1", Port: 8443, Class: "ip", Prefix: 0}},
		},
		{
			name: "blank and comment lines are skipped, lines still numbered",
			in:   "\n\n# probe comment\nhttps://example.com\n\n",
			want: []grammar.Target{{Input: "example.com", Host: "example.com", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "multiple lines compose in order",
			in:   "a.example.com\nhttps://b.example.com:8443/api\n# trailing comment\n",
			want: []grammar.Target{
				{Input: "a.example.com", Host: "a.example.com", Port: 443, Class: "host", Prefix: 0},
				{Input: "b.example.com:8443", Host: "b.example.com", Port: 8443, Class: "host", Prefix: 0},
			},
		},
		{
			name: "duplicates are returned per line; the composition dedupes upstream",
			in:   "https://a.example.com\nhttps://a.example.com\n",
			want: []grammar.Target{
				{Input: "a.example.com", Host: "a.example.com", Port: 443, Class: "host", Prefix: 0},
				{Input: "a.example.com", Host: "a.example.com", Port: 443, Class: "host", Prefix: 0},
			},
		},
		{
			name:    "out-of-range port errors with its line number",
			in:      "https://good.example.com\n\nhttps://bad.example.com:99999\n",
			wantErr: `line 3: port "99999" out of range`,
		},
		{
			name:    "scheme with no host errors at its line number",
			in:      "# nothing above\nhttps://\n",
			wantErr: "line 2: target spec is empty",
		},
	} {
		runAdapterCases(t, FromHTTPX, []adapterCase{tc})
	}
}

// TestFromNaabu pins the -from-naabu adapter (issue #80 / PQ-35, spec
// §5.7 grammar-in dialect parsers): naabu text lines are host:port per
// line (hackerone.com:443; bare IPs as-is), or the bare-host block shape —
// a host line followed by a ports list (bare decimal ports, indented or
// not). A bare host with no ports block following (naabu's host-discovery
// list) keeps the grammar's https default (443). Comments (#) and blanks
// are skipped but numbered; the first rejected spec aborts the stream.
//
// The adapter parses each port pair through grammar.Parse("host:port") —
// no adapter-level dedupe, so the composition's dedupe semantics are the
// same ones the -u/-l/-- specs get.
func TestFromNaabu(t *testing.T) {
	for _, tc := range []adapterCase{
		{
			name: "host:port line",
			in:   "example.com:443\n",
			want: []grammar.Target{{Input: "example.com:443", Host: "example.com", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "ip:port line",
			in:   "104.16.99.52:80\n",
			want: []grammar.Target{{Input: "104.16.99.52:80", Host: "104.16.99.52", Port: 80, Class: "ip", Prefix: 0}},
		},
		{
			name: "bare host opens a ports block: host + ports list",
			in:   "example.com\n  80\n  443\n",
			want: []grammar.Target{
				{Input: "example.com:80", Host: "example.com", Port: 80, Class: "host", Prefix: 0},
				{Input: "example.com:443", Host: "example.com", Port: 443, Class: "host", Prefix: 0},
			},
		},
		{
			name: "bare hosts with no ports block keep the https default",
			in:   "a.example.com\nb.example.com\n",
			want: []grammar.Target{
				{Input: "a.example.com", Host: "a.example.com", Port: 443, Class: "host", Prefix: 0},
				{Input: "b.example.com", Host: "b.example.com", Port: 443, Class: "host", Prefix: 0},
			},
		},
		{
			name: "a ports block closes when the next host line opens",
			in:   "one.example.com\n80\n22\nsecond.example.com\n443\n",
			want: []grammar.Target{
				{Input: "one.example.com:80", Host: "one.example.com", Port: 80, Class: "host", Prefix: 0},
				{Input: "one.example.com:22", Host: "one.example.com", Port: 22, Class: "host", Prefix: 0},
				{Input: "second.example.com:443", Host: "second.example.com", Port: 443, Class: "host", Prefix: 0},
			},
		},
		{
			name: "comment and blank lines are skipped, lines still numbered",
			in:   "# naabu output\n\nexample.com\n\n80\n",
			want: []grammar.Target{{Input: "example.com:80", Host: "example.com", Port: 80, Class: "host", Prefix: 0}},
		},
		{
			name:    "port line with no preceding host errors at its line number",
			in:      "\n80\n",
			wantErr: `line 2: port "80" outside a ports block`,
		},
		{
			name:    "malformed host:port errors with its line number",
			in:      "example.com:443\nbad.example.com:99999\n",
			wantErr: `line 2: port "99999" out of range`,
		},
		{
			name:    "a trailing bare host whose grammar rejects keeps the host line number",
			in:      "example.com\n!! bad!!\n",
			wantErr: `line 2: target spec "!! bad!!" contains whitespace`,
		},
	} {
		runAdapterCases(t, FromNaabu, []adapterCase{tc})
	}
}

// TestFromLines pins the raw -l/-- adapter (issue #80 / PQ-35; the
// composition's list-file and positional-spec path): newline-separated
// grammar specs, blank/whitespace-only lines skipped, every surviving line
// handed to grammar.Parse unchanged. The raw path has no comment
// convention (only the -from-* dialects skip # lines) and passes classes
// through untouched: a CIDR line parses as a cidr-class target (the
// composition refuses the class) and the -- marker stays a stdin-class
// target exactly as grammar.Parse yields it.
func TestFromLines(t *testing.T) {
	for _, tc := range []adapterCase{
		{
			name: "specs parse like the -l/-- composition",
			in:   "example.com\nexample.com:9443\n10.0.0.1\n",
			want: []grammar.Target{
				{Input: "example.com", Host: "example.com", Port: 443, Class: "host", Prefix: 0},
				{Input: "example.com:9443", Host: "example.com", Port: 9443, Class: "host", Prefix: 0},
				{Input: "10.0.0.1", Host: "10.0.0.1", Port: 443, Class: "ip", Prefix: 0},
			},
		},
		{
			name: "blank and whitespace-only lines are skipped",
			in:   "example.com\n\n   \n10.0.0.1\n",
			want: []grammar.Target{
				{Input: "example.com", Host: "example.com", Port: 443, Class: "host", Prefix: 0},
				{Input: "10.0.0.1", Host: "10.0.0.1", Port: 443, Class: "ip", Prefix: 0},
			},
		},
		{
			name:    "malformed line errors with its line number",
			in:      "example.com\n443\n",
			wantErr: `line 2: bare port "443"`,
		},
		{
			name:    "the raw path has no comment convention (only -from-* dialects skip them)",
			in:      "10.0.0.1\n# comment line\n",
			wantErr: `line 2: target spec "# comment line" contains whitespace`,
		},
		{
			name: "CIDR lines parse like the grammar; the class stays untouched",
			in:   "10.0.0.0/24\n",
			want: []grammar.Target{{Input: "10.0.0.0/24", Host: "10.0.0.0", Port: 443, Class: "cidr", Prefix: 24}},
		},
		{
			name: "the -- marker passes through as the stdin-class target",
			in:   "--\n",
			want: []grammar.Target{{Input: "--", Host: "", Port: 0, Class: "stdin", Prefix: 0}},
		},
	} {
		runAdapterCases(t, FromLines, []adapterCase{tc})
	}
}
