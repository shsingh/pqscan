package tlsx

import "testing"

// TestClientHelloRoundtrip pins the wire format end to end: the built
// hello must parse back with byte-exact semantics. This is the permanent
// regression test for the u16-vs-u8 list-length class of defect
// (PQ-10; the SNI defect in #16 lives here).
func TestClientHelloRoundtrip(t *testing.T) {
	msg := buildClientHello("example.com", []uint32{4588, 29}, 29)
	ch, err := parseClientHello(msg)
	if err != nil {
		t.Fatalf("roundtrip parse: %v", err)
	}
	if ch.Host != "example.com" {
		t.Fatalf("roundtrip host = %q, want example.com", ch.Host)
	}
	if ch.LegacyVersion != 0x0301 {
		t.Fatalf("legacy version = %#x, want 0x0301", ch.LegacyVersion)
	}
	if want := []uint16{0x1301, 0x1302, 0x1303}; len(ch.Suites) != 3 || ch.Suites[0] != want[0] || ch.Suites[1] != want[1] || ch.Suites[2] != want[2] {
		t.Fatalf("suites = %#x, want %#x", ch.Suites, want)
	}
	if ch.Groups[0] != 4588 || ch.Groups[1] != 29 || len(ch.Groups) != 2 {
		t.Fatalf("groups = %#x, want [4588 29]", ch.Groups)
	}
	if !ch.SharePresent || ch.ShareGroup != 29 {
		t.Fatalf("share = %v/%d, want present/29", ch.SharePresent, ch.ShareGroup)
	}
	if ch.SupportedVersion != 0x0304 {
		t.Fatalf("supported version = %#x, want 0x0304", ch.SupportedVersion)
	}
}

// TestClientHelloRoundtripShareless pins the share-less oracle offer
// roundtrip: empty key_share vector parsed as absent.
func TestClientHelloRoundtripShareless(t *testing.T) {
	msg := buildClientHello("pqscan.fixture", []uint32{25497}, 0)
	ch, err := parseClientHello(msg)
	if err != nil {
		t.Fatalf("roundtrip parse: %v", err)
	}
	if ch.SharePresent || ch.ShareGroup != 0 {
		t.Fatalf("share should be absent; got %v/%d", ch.SharePresent, ch.ShareGroup)
	}
	if ch.Groups[0] != 25497 {
		t.Fatalf("groups = %#x, want [25497]", ch.Groups)
	}
}
