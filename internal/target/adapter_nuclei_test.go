package target

// adapter_nuclei_test.go pins the -from-nuclei adapter (PQ-55, issue #149;
// the watched-RED pair per ADR-0002): the pinned capture
// `nuclei -l hosts.txt -silent -j` (nuclei v3.11.1, captured 2026-10-20,
// 28 findings over scanme.sh) emits ONE JSON finding per line; every
// finding contributes the host:port of its matched-at field (the url field
// is the fallback where matched-at is empty — both ride every captured
// line), scheme/path decoration stripped by the SAME dialect rule the
// httpx lines walk (stripDialectDecor), so ONE grammar and ONE composition
// dedupe (host:port, first occurrence wins) serve the nuclei import exactly
// like every other input source. The ADAPTER never dedupes: the capture
// holds one host:port across many findings (28 lines → two distinct
// host:ports) and the composition's dedupe owns the collapse — the same
// contract the other adapters document.
//
// The observed matched-at classes in the pinned capture:
//
//	https://scanme.sh   (http-type findings: scheme, no explicit port —
//	                     the grammar's https default 443 applies)
//	scanme.sh:443       (ssl-type findings: bare host:port)
//	scanme.sh:22        (javascript/ssh findings: bare host:port, the
//	                     port-preservation class)
//	scanme.sh           (dns-type findings: bare host)
//
// Comment (#) and blank lines skip but still number (the -from-* dialect
// convention: every pinned fixture file carries header comments). A line
// that is not a findings object (no matched-at and no url) is a recorded
// observation at its line number: the stream aborts, the run refuses exit
// 64 named by its flag — the adapters' one convention (no partial list ever
// scans). The lines below carry the capture's shape: the ssl-issuer finding
// is the pinned capture's line 26 verbatim; its siblings are the same shape
// over the capture's own observed fields.
import (
	"testing"

	"github.com/shsingh/pqscan/internal/grammar"
)

// nucleiRealSSLLine is the pinned capture's ssl-issuer finding, verbatim
// (nuclei v3.11.1 -j; every field shape below came off the real capture —
// matched-at is the parse contract's source field).
const nucleiRealSSLLine = `{"template":"ssl/detect-ssl-issuer.yaml","template-url":"https://cloud.projectdiscovery.io/public/ssl-issuer","template-id":"ssl-issuer","template-path":"/Users/shsingh/.config/nuclei/nuclei-templates/ssl/detect-ssl-issuer.yaml","info":{"name":"Detect SSL Certificate Issuer","author":["lingtren"],"tags":["ssl","tls","discovery"],"description":"Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.\n","severity":"info","metadata":{"max-request":1}},"type":"ssl","host":"scanme.sh","port":"443","matched-at":"scanme.sh:443","extracted-results":["pd"],"ip":"128.199.158.128","timestamp":"2026-10-20T19:28:38.133523+11:00","matcher-status":true}`

func TestFromNuclei(t *testing.T) {
	for _, tc := range []adapterCase{
		{
			name: "the real ssl-issuer finding contributes its matched-at host:port",
			in:   nucleiRealSSLLine + "\n",
			want: []grammar.Target{{Input: "scanme.sh:443", Host: "scanme.sh", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "scheme://host matched-at strips: the http class keeps the https default (443)",
			in:   `{"template-id":"http-missing-cms","matched-at":"https://scanme.sh","url":"https://scanme.sh","matcher-status":true}` + "\n",
			want: []grammar.Target{{Input: "scanme.sh", Host: "scanme.sh", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "matched-at host:port preserves the port (the ssh class)",
			in:   `{"template-id":"ssh-server-enumeration","type":"javascript","matched-at":"scanme.sh:22","url":"scanme.sh:22","matcher-status":true}` + "\n",
			want: []grammar.Target{{Input: "scanme.sh:22", Host: "scanme.sh", Port: 22, Class: "host", Prefix: 0}},
		},
		{
			name: "bare host matched-at keeps the https default (the dns class)",
			in:   `{"template-id":"dns-aaaa-fingerprint","type":"dns","matched-at":"scanme.sh","host":"scanme.sh","matcher-status":true}` + "\n",
			want: []grammar.Target{{Input: "scanme.sh", Host: "scanme.sh", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "the url field is the fallback when matched-at is empty",
			in:   `{"template-id":"dns-aaaa-fingerprint","type":"dns","matched-at":"","url":"scanme.sh:22","matcher-status":true}` + "\n",
			want: []grammar.Target{{Input: "scanme.sh:22", Host: "scanme.sh", Port: 22, Class: "host", Prefix: 0}},
		},
		{
			name: "comment and blank lines skip but still number (the fixture headers)",
			in:   "# pinned-capture: nuclei -l hosts.txt -silent -j\n\n" + `{"matched-at":"scanme.sh:443"}` + "\n",
			want: []grammar.Target{{Input: "scanme.sh:443", Host: "scanme.sh", Port: 443, Class: "host", Prefix: 0}},
		},
		{
			name: "findings repeat one host:port; the composition dedupes upstream",
			in:   `{"matched-at":"https://scanme.sh"}` + "\n" + `{"matched-at":"scanme.sh:443"}` + "\n" + nucleiRealSSLLine + "\n",
			want: []grammar.Target{
				{Input: "scanme.sh", Host: "scanme.sh", Port: 443, Class: "host", Prefix: 0},
				{Input: "scanme.sh:443", Host: "scanme.sh", Port: 443, Class: "host", Prefix: 0},
				{Input: "scanme.sh:443", Host: "scanme.sh", Port: 443, Class: "host", Prefix: 0},
			},
		},
		{
			name:    "a non-JSON line (naabu-shape text) is a recorded line-numbered observation",
			in:      "scanme.sh:443\n",
			wantErr: `line 1: not a nuclei findings JSONL object`,
		},
		{
			name:    "a JSON line with neither matched-at nor url is a recorded observation",
			in:      `{"template-id":"template-only","matcher-status":false}` + "\n",
			wantErr: "line 1: nuclei finding with neither matched-at nor url",
		},
		{
			name:    "comments and blanks count toward the failing line's number",
			in:      "# header\n\nnot json either\n",
			wantErr: "line 3: not a nuclei findings JSONL object",
		},
	} {
		runAdapterCases(t, FromNuclei, []adapterCase{tc})
	}
}
