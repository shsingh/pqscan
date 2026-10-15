package tlsx

import (
	"encoding/binary"
	"errors"
)

// parseClientHello parses one client-hello handshake MESSAGE (type,
// u24 length, payload) as the roundtrip test seam: the fixture-side and
// test-side verifier for the raw probe's byte assembly (PQ-10; guards
// the u16-vs-u8 list-length defect class permanently).
func parseClientHello(msg []byte) (*ClientHello, error) {
	if len(msg) < 6 || msg[0] != 0x01 {
		return nil, errors.New("not a client_hello message")
	}
	ln := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if len(msg) < 4+ln {
		return nil, errors.New("client_hello truncated")
	}
	p := msg[4 : 4+ln]
	ch := &ClientHello{LegacyVersion: binary.BigEndian.Uint16(p[0:2])}
	p = p[2:]
	p = p[32:] // random
	sidLen := int(p[0])
	p = p[1+sidLen:]

	suiteBytes := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	for i := 0; i < suiteBytes; i += 2 {
		ch.Suites = append(ch.Suites, binary.BigEndian.Uint16(p[i:i+2]))
	}
	p = p[suiteBytes:]

	compLen := int(p[0])
	p = p[1+compLen:]

	extTotal := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < extTotal {
		return nil, errors.New("extension vector truncated")
	}
	p = p[:extTotal]
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[0:2])
		extLen := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+extLen > len(p) {
			return nil, errors.New("extension truncated")
		}
		data := p[4 : 4+extLen]
		switch extType {
		case 0x0000: // server_name list
			if len(data) < 5 {
				return nil, errors.New("sni short")
			}
			hostLen := int(binary.BigEndian.Uint16(data[3:5]))
			ch.Host = string(data[5 : 5+hostLen])
		case 0x000a: // supported_groups
			n := int(binary.BigEndian.Uint16(data[0:2]))
			for i := 2; i < 2+n; i += 2 {
				ch.Groups = append(ch.Groups, uint32(binary.BigEndian.Uint16(data[i:i+2])))
			}
		case 0x0033: // key_share: u16 vector_len + entries (u16 group + u16 share_len + share)
			if len(data) >= 4 {
				vectorLen := int(binary.BigEndian.Uint16(data[0:2]))
				if vectorLen >= 4 && len(data) >= 2+4 {
					ch.SharePresent = true
					ch.ShareGroup = uint32(binary.BigEndian.Uint16(data[2:4]))
					shareLen := int(binary.BigEndian.Uint16(data[4:6]))
					if len(data) < 6+shareLen {
						return nil, errors.New("key_share entry truncated")
					}
					_ = shareLen
				}
			}
		case 0x002b: // supported_versions
			if len(data) >= 3 {
				ch.SupportedVersion = binary.BigEndian.Uint16(data[1:3])
			}
		}
		p = p[4+extLen:]
	}
	return ch, nil
}

// ClientHello is the parsed-back view of the raw probe's constructed
// hello (PQ-10 wire-format roundtrip: pins the extension-encoding defect
// class permanently).
type ClientHello struct {
	LegacyVersion    uint16
	Suites           []uint16
	Host             string
	Groups           []uint32
	ShareGroup       uint32
	SharePresent     bool
	SupportedVersion uint16
}
