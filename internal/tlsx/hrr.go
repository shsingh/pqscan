package tlsx

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Observation states for the raw first-flight probe (spec §5.4: HRR is an
// observable, not an error).
const (
	StateHRR   = "hrr"
	StateSH    = "sh"
	StateAlert = "alert"
	StateRead  = "read-error"
)

// helloRetryRandom is the mandated HelloRetryRequest pseudo-random from
// RFC 8446 §4.1.3 — its presence in a ServerHello's random field is the
// on-the-wire HRR test.
var helloRetryRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02,
	0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// HelloObservation classifies one raw first-flight response. The oracle
// probes (obsolete-Kyber drafts, SM2 hybrids) land here too: they read the
// server's reaction without needing shares the local stack cannot
// generate (spec Appendix A; PQ-05 deliverable).
type HelloObservation struct {
	State          string // StateHRR | StateSH | StateAlert | StateRead
	Version        uint16 // record-layer version of the first flight
	RequestedGroup uint32 // HRR only: group the server demands (0 = none)
	AlertDesc      uint8  // alert only
	FarVersion     uint16 // payload's legacy version field, as seen
}

// SendHelloProbe dials addr (host:port), sends a hand-built TLS 1.3
// ClientHello offering `groups` with one key_share for `shareGroup`
// (0 = share-less offer: supported-groups advertisement only), and
// classifies the server's first flight. The connection closes after the
// observation; this probe never completes a handshake it did not set out
// to complete.
func SendHelloProbe(addr, host string, groups []uint32, shareGroup uint32) (*HelloObservation, error) {
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	ch := buildClientHello(host, groups, shareGroup)
	if _, err := conn.Write(wrapRecord(0x16, 0x0301, ch)); err != nil {
		return nil, err
	}
	return readFirstFlight(bufio.NewReader(conn))
}

// SendHelloProbeRaw is the test seam: drives an existing connection so the
// fixture matrix can exercise the probe offline (spec §10.1).
func SendHelloProbeRaw(conn net.Conn, host string, groups []uint32, shareGroup uint32) (*HelloObservation, error) {
	ch := buildClientHello(host, groups, shareGroup)
	if _, err := conn.Write(wrapRecord(0x16, 0x0301, ch)); err != nil {
		return nil, err
	}
	return readFirstFlight(bufio.NewReader(conn))
}

func wrapRecord(recType uint8, ver uint16, handshake []byte) []byte {
	rec := make([]byte, 5+len(handshake))
	rec[0] = recType
	binary.BigEndian.PutUint16(rec[1:3], ver)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(handshake)))
	copy(rec[5:], handshake)
	return rec
}

var sigAlgs = []uint16{0x0403, 0x0804, 0x0805, 0x0806} // ecdsa-p256, rsa-pss 2048/3072/4096
var t13Suites = []uint16{0x1301, 0x1302, 0x1303}

// buildClientHello assembles one TLS 1.3 ClientHello handshake body:
// handshake header, legacy fields, and the four extensions the ladder
// needs (server_name, supported_groups, signature_algorithms, key_share,
// supported_versions).
func buildClientHello(host string, groups []uint32, shareGroup uint32) []byte {
	var random, sessionID [32]byte
	_, _ = rand.Read(random[:])
	_, _ = rand.Read(sessionID[:])

	// --- extensions ---
	sni := []byte(host)
	// server_name ext data: u16 list_len (= 1 + 2 + name_len) + u8 host_name(0)
	// + u16 name_len + name
	nameEntry := append(packUint16(uint16(len(sni)+3)), packBytes([]byte{0x00}, packUint16(uint16(len(sni))), sni)...)
	extServerName := pack(tlsex(0x0000, nameEntry))
	groupsData := packUint16(uint16(len(groups) * 2))
	for _, g := range groups {
		groupsData = append(groupsData, packUint16(uint16(g))...)
	}
	extGroups := pack(tlsex(0x000a, groupsData))
	segsData := packUint16(uint16(len(sigAlgs) * 2))
	for _, s := range sigAlgs {
		segsData = append(segsData, packUint16(s)...)
	}
	extSigAlgs := pack(tlsex(0x000d, segsData))

	extKeyShare := pack(tlsex(0x0033, buildKeyShare(shareGroup)))
	extVersions := pack(tlsex(0x002b, []byte{0x02, 0x03, 0x04}))

	suiteList := packUint16(uint16(len(t13Suites) * 2))
	for _, s := range t13Suites {
		suiteList = append(suiteList, packUint16(s)...)
	}

	inner := make([]byte, 0, 256)
	inner = append(inner, 0x03, 0x01)      // legacy_version
	inner = append(inner, random[:]...)    // random
	inner = append(inner, 0x20)            // legacy_session_id len
	inner = append(inner, sessionID[:]...) // legacy_session_id
	inner = append(inner, suiteList...)    // cipher_suites
	inner = append(inner, 0x01, 0x00)      // compression: null
	all := bytes.Join([][]byte{extServerName, extGroups, extSigAlgs, extKeyShare, extVersions}, nil)
	inner = append(inner, packUint16(uint16(len(all)))...) // extensions total
	inner = append(inner, all...)                          // extensions

	hs := make([]byte, 0, len(inner)+4)
	hs = append(hs, 0x01)                                                        // handshake: client_hello
	hs = append(hs, byte(len(inner)>>16), byte(len(inner)>>8), byte(len(inner))) // u24 length
	hs = append(hs, inner...)
	return hs
}

// buildKeyShare encodes the key_share extension: one entry with a valid
// zero-share body for x25519-shaped probes (32 bytes of entropy the
// fixture side can decode), or an empty entry list for share-less oracle
// offers. Non-x25519 share groups are emitted as share-less; generating
// real shares for KEM groups is the native engine's job (PQ-05's stdlib
// path), not the raw probe's.
func buildKeyShare(shareGroup uint32) []byte {
	if shareGroup == 0 || shareGroup != 29 {
		return []byte{0x00, 0x00} // empty client_shares vector
	}
	var share [32]byte
	_, _ = rand.Read(share[:])
	body := packUint16(29)
	body = append(body, packUint16(uint16(len(share)))...)
	body = append(body, share[:]...)
	return append(packUint16(uint16(len(body))), body...)
}

// readFirstFlight classifies the server's response: an alert, a
// HelloRetryRequest (magic random -> requested-group extraction), or an
// ordinary ServerHello. Records accumulate until the handshake message
// completes (fragmentation across TCP records is legal and handled).
func readFirstFlight(r *bufio.Reader) (*HelloObservation, error) {
	body := &bytes.Buffer{}
	for {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) || len(hdr) == 0 {
				return &HelloObservation{State: StateRead}, nil
			}
			return nil, fmt.Errorf("record header: %w", err)
		}
		recType := hdr[0]
		bodyLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		payload := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("record body: %w", err)
		}
		ver := binary.BigEndian.Uint16(hdr[1:3])
		obs := &HelloObservation{Version: ver, FarVersion: ver}

		if recType == 0x15 { // alert
			if len(payload) >= 2 {
				obs.State = StateAlert
				obs.AlertDesc = payload[1]
				return obs, nil
			}
			obs.State = StateRead
			return obs, nil
		}
		if recType != 0x16 {
			obs.State = StateRead
			return obs, nil
		}
		body.Write(payload)
		if hs, err := parseHandshake(body.Bytes()); err == nil {
			return hs, nil
		}
		if body.Len() > 4096 {
			return &HelloObservation{State: StateRead}, nil
		}
	}
}

// parseHandshake reads one complete handshake message (type, u24 length,
// payload) and classifies it.
func parseHandshake(b []byte) (*HelloObservation, error) {
	if len(b) < 4 {
		return nil, errors.New("handshake incomplete")
	}
	hsType := b[0]
	ln := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+ln {
		return nil, errors.New("handshake incomplete")
	}
	payload := b[4 : 4+ln]
	obs := &HelloObservation{FarVersion: binary.BigEndian.Uint16(payload[0:2])}

	if hsType == 2 { // server_hello
		if len(payload) < 2+32+1 {
			return nil, errors.New("server_hello short")
		}
		rand := payload[2:34]
		if bytes.Equal(rand, helloRetryRandom[:]) {
			group, err := hrrRequestedGroup(payload[34:])
			if err != nil {
				return nil, err
			}
			obs.State = StateHRR
			obs.RequestedGroup = group
			return obs, nil
		}
		obs.State = StateSH
		return obs, nil
	}
	return nil, errors.New("handshake incomplete")
}

// hrrRequestedGroup walks the post-server_hello-random remainder (session
// id, legacy cipher/compression, extension vector) for the key_share
// extension and extracts the requested (server-selected) group.
func hrrRequestedGroup(rest []byte) (uint32, error) {
	if len(rest) < 5 {
		return 0, errors.New("hrr remainder short")
	}
	sidLen := int(rest[0])
	off := 1 + sidLen + 3 // session_id + cipher_suite + compression
	if off+2 > len(rest) {
		return 0, errors.New("hrr remainder short")
	}
	extTotal := int(binary.BigEndian.Uint16(rest[off : off+2]))
	off += 2
	end := off + extTotal
	if end > len(rest) {
		end = len(rest)
	}
	for off+4 <= end {
		extType := binary.BigEndian.Uint16(rest[off : off+2])
		extLen := int(binary.BigEndian.Uint16(rest[off+2 : off+4]))
		data := rest[off+4 : min(off+4+extLen, len(rest))]
		if extType == 0x33 && len(data) >= 2 { // key_share: selected_group
			return uint32(binary.BigEndian.Uint16(data[0:2])), nil
		}
		off += 4 + extLen
	}
	return 0, errors.New("hrr carries no key_share extension")
}

func packUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func tlsex(extType uint16, data []byte) []byte {
	out := packUint16(extType)
	out = append(out, packUint16(uint16(len(data)))...)
	return append(out, data...)
}

// packBytes joins byte slices (helper to keep extension assembly readable).
func packBytes(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func pack(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
