package out

import (
	"io"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Format selects the record encoder for a run (spec §5.7 dialect rules:
// one JSON object per line in -jsonl, csv for spreadsheets, urls for the
// chainable endpoint list, and single-line text as the default).
type Format int

const (
	// FormatText is the default: one human line per target.
	FormatText Format = iota
	// FormatJSONL writes one schema-1 JSON record per line (-json/-jsonl).
	FormatJSONL
	// FormatCSV writes the header line once, then one row per record.
	FormatCSV
	// FormatURLs writes one scheme://host:port line per record.
	FormatURLs
)

// String returns the flag-level format name (diagnostics, progress).
func (f Format) String() string {
	switch f {
	case FormatJSONL:
		return "jsonl"
	case FormatCSV:
		return "csv"
	case FormatURLs:
		return "urls"
	default:
		return "text"
	}
}

// csvHeader is the fixed CSV column list: the header row precedes the
// first record's row and is emitted once per stream.
const csvHeader = "target,host,port,ptr,sni,negotiated,group_name,group_class,suite,version,alpn,quic_state,quic_group,udp_blocked,error,ts"

// Encoder writes records in one format to an injected stream. Not safe
// for concurrent use: the streaming stage feeds it from its own goroutine.
type Encoder struct {
	w      io.Writer
	format Format
	header bool // csv header emitted

	buf []byte
}

// NewEncoder wires a format into a destination stream (stdout or the -o
// file — the caller owns the stream, the encoder only writes lines).
func NewEncoder(w io.Writer, f Format) *Encoder {
	return &Encoder{w: w, format: f}
}

// Encode writes one record line to the stream (CSV: the header line goes
// out ahead of the first row). One line per call; newline included.
//
// Hand-rolled end to end (spec §7.7): no reflection, no encoding/json on
// the encode path, no Sprintf — one reused buffer per encoder.
func (e *Encoder) Encode(r *Record) error {
	e.buf = e.buf[:0]
	switch e.format {
	case FormatJSONL:
		e.buf = AppendRecordJSON(e.buf, r)
		e.buf = append(e.buf, '\n')
	case FormatCSV:
		if !e.header {
			e.buf = append(e.buf, csvHeader...)
			e.buf = append(e.buf, '\n')
			e.header = true
		}
		e.buf = appendCSVRecord(e.buf, r)
		e.buf = append(e.buf, '\n')
	case FormatURLs:
		e.buf = appendURLLine(e.buf, r)
		e.buf = append(e.buf, '\n')
	default:
		e.buf = appendTextLine(e.buf, r)
		e.buf = append(e.buf, '\n')
	}
	_, err := e.w.Write(e.buf)
	return err
}

// hexDigits is the lowercase alphabet encoding/json escapes with.
const hexDigits = "0123456789abcdef"

// AppendJSONString appends s as a JSON string literal, byte-compatible
// with encoding/json's default (HTML-safe) escaping: quotes, backslashes,
// control bytes (named \b\f\n\r\t escapes, then \u00xx), the HTML bytes
// < > &, U+2028/2029, and invalid UTF-8 (one \ufffd per bad byte) — the
// one escaping implementation shared by the record line and the journal.
func AppendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if jsonSafeByte[b] {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch b {
			case '\\', '"':
				dst = append(dst, '\\', b)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				// control bytes plus the HTML-escaped <, >, & (byte-
				// compatible with encoding/json's default escaping)
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, "\ufffd"...)
			i += size
			start = i
			continue
		}
		if r == '\u2028' || r == '\u2029' {
			dst = append(dst, s[start:i]...)
			if r == '\u2028' {
				dst = append(dst, `\u2028`...)
			} else {
				dst = append(dst, `\u2029`...)
			}
			i += size
			start = i
			continue
		}
		i += size
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

// jsonSafeByte mirrors encoding/json's htmlSafeSet: printable ASCII that
// survives JSON escaping untouched, minus quote, backslash, <, >, &.
var jsonSafeByte = func() [utf8.RuneSelf]bool {
	var safe [utf8.RuneSelf]bool
	for c := ' '; c <= '~'; c++ {
		safe[c] = true
	}
	safe['"'] = false
	safe['\\'] = false
	safe['<'] = false
	safe['>'] = false
	safe['&'] = false
	return safe
}()

// AppendRecordJSON appends the schema-1 record object: the JSONL line
// body (byte-pinned by the tests/goldens files — -json and -jsonl emit
// these same bytes) and the exact field set the rc-1 encode surface
// shipped: schema, mode, target, handshake (every omitempty corner), the
// quic block, error. The WAL composes this same body into its entries.
func AppendRecordJSON(dst []byte, r *Record) []byte {
	dst = append(dst, `{"schema":`...)
	dst = strconv.AppendInt(dst, int64(r.Schema), 10)
	dst = append(dst, `,"mode":`...)
	dst = AppendJSONString(dst, r.Mode)
	dst = append(dst, `,"target":{"input":`...)
	dst = AppendJSONString(dst, r.Target.Input)
	dst = append(dst, `,"host":`...)
	dst = AppendJSONString(dst, r.Target.Host)
	dst = append(dst, `,"ip":`...)
	dst = AppendJSONString(dst, r.Target.IP)
	dst = append(dst, `,"port":`...)
	dst = strconv.AppendUint(dst, uint64(r.Target.Port), 10)
	dst = append(dst, `,"ptr":`...)
	dst = AppendJSONString(dst, r.Target.Ptr)
	dst = append(dst, `,"sni_used":`...)
	dst = AppendJSONString(dst, r.Target.SNIUsed)
	dst = append(dst, `},"handshake":{"negotiated":`...)
	dst = strconv.AppendUint(dst, uint64(r.Handshake.Negotiated), 10)
	if r.Handshake.GroupName != "" {
		dst = append(dst, `,"group_name":`...)
		dst = AppendJSONString(dst, r.Handshake.GroupName)
	}
	if r.Handshake.GroupClass != "" {
		dst = append(dst, `,"group_class":`...)
		dst = AppendJSONString(dst, r.Handshake.GroupClass)
	}
	if r.Handshake.Suite != "" {
		dst = append(dst, `,"suite":`...)
		dst = AppendJSONString(dst, r.Handshake.Suite)
	}
	if r.Handshake.Version != "" {
		dst = append(dst, `,"version":`...)
		dst = AppendJSONString(dst, r.Handshake.Version)
	}
	if r.Handshake.ALPNNeg != "" {
		dst = append(dst, `,"alpn_neg":`...)
		dst = AppendJSONString(dst, r.Handshake.ALPNNeg)
	}
	dst = append(dst, '}')
	if q := r.Quic; q != nil {
		dst = append(dst, `,"quic":{"attempted":`...)
		dst = strconv.AppendBool(dst, q.Attempted)
		if q.State != "" {
			dst = append(dst, `,"state":`...)
			dst = AppendJSONString(dst, q.State)
		}
		if q.Negotiated != 0 {
			dst = append(dst, `,"negotiated":`...)
			dst = strconv.AppendUint(dst, uint64(q.Negotiated), 10)
		}
		if q.GroupName != "" {
			dst = append(dst, `,"group_name":`...)
			dst = AppendJSONString(dst, q.GroupName)
		}
		if q.GroupClass != "" {
			dst = append(dst, `,"group_class":`...)
			dst = AppendJSONString(dst, q.GroupClass)
		}
		if q.UDPBlocked {
			dst = append(dst, `,"udp_blocked":true`...)
		}
		dst = append(dst, '}')
	}
	dst = append(dst, `,"error":`...)
	dst = AppendJSONString(dst, r.Error)
	return append(dst, '}')
}

// appendTextLine is the default one-liner (the shipped rc-1 format,
// byte-identical): host:port group= class= suite= version= with the dash
// fallbacks, then the optional alpn, quic pair, udp_blocked and error
// tails as their observations exist.
func appendTextLine(dst []byte, r *Record) []byte {
	dst = append(dst, orNoHost(r.Target.Host)...)
	dst = append(dst, ':')
	dst = strconv.AppendUint(dst, uint64(r.Target.Port), 10)
	dst = append(dst, " group="...)
	dst = append(dst, orDash(r.Handshake.GroupName)...)
	dst = append(dst, " class="...)
	dst = append(dst, orDash(r.Handshake.GroupClass)...)
	dst = append(dst, " suite="...)
	dst = append(dst, orDash(r.Handshake.Suite)...)
	dst = append(dst, " version="...)
	dst = append(dst, orDash(r.Handshake.Version)...)
	if r.Handshake.ALPNNeg != "" {
		dst = append(dst, " alpn="...)
		dst = append(dst, r.Handshake.ALPNNeg...)
	}
	if q := r.Quic; q != nil && q.Negotiated > 0 {
		dst = append(dst, " quic_neg="...)
		dst = append(dst, orDash(q.GroupName)...)
		dst = append(dst, " quic_class="...)
		dst = append(dst, orDash(q.GroupClass)...)
	}
	if q := r.Quic; q != nil && q.UDPBlocked {
		dst = append(dst, " udp_blocked=true"...)
	}
	if r.Error != "" {
		dst = append(dst, " error="...)
		dst = append(dst, r.Error...)
	}
	return dst
}

// appendCSVRecord appends one row of the fixed column list: target, host,
// port, ptr, sni, negotiated (codepoint; empty when nothing negotiated),
// group_name, group_class, suite, version, alpn, the quic block (state +
// group + udp_blocked; the three cells empty when the plane never
// probed), error, ts — RFC 4180 quoting for any cell that needs it.
func appendCSVRecord(dst []byte, r *Record) []byte {
	dst = appendCSVField(dst, r.Target.Input)
	dst = append(dst, ',')
	dst = appendCSVField(dst, r.Target.Host)
	dst = append(dst, ',')
	dst = strconv.AppendUint(dst, uint64(r.Target.Port), 10)
	dst = append(dst, ',')
	dst = appendCSVField(dst, r.Target.Ptr)
	dst = append(dst, ',')
	dst = appendCSVField(dst, r.Target.SNIUsed)
	dst = append(dst, ',')
	if r.Handshake.Negotiated != 0 {
		dst = strconv.AppendUint(dst, uint64(r.Handshake.Negotiated), 10)
	}
	for _, cell := range []string{r.Handshake.GroupName, r.Handshake.GroupClass, r.Handshake.Suite, r.Handshake.Version, r.Handshake.ALPNNeg} {
		dst = append(dst, ',')
		dst = appendCSVField(dst, cell)
	}
	dst = append(dst, ',')
	if q := r.Quic; q != nil && q.Attempted {
		dst = appendCSVField(dst, q.State)
		dst = append(dst, ',')
		dst = appendCSVField(dst, q.GroupName)
		dst = append(dst, ',')
		dst = strconv.AppendBool(dst, q.UDPBlocked)
	} else {
		dst = append(dst, ",,"...)
	}
	dst = append(dst, ',')
	dst = appendCSVField(dst, r.Error)
	dst = append(dst, ',')
	dst = appendCSVField(dst, r.Ts)
	return dst
}

// appendCSVField appends one cell, RFC 4180-quoted (quotes doubled) when
// it carries a comma, quote, newline or carriage return.
func appendCSVField(dst []byte, s string) []byte {
	if !strings.ContainsAny(s, ",\"\n\r") {
		return append(dst, s...)
	}
	dst = append(dst, '"')
	dst = append(dst, strings.ReplaceAll(s, `"`, `""`)...)
	return append(dst, '"')
}

// appendURLLine is the chainable endpoint list (spec §5.7: scheme://
// host:port per target, one line each, IPv6 literals bracketed) — https,
// the scanned plane's scheme; the host falls back to the raw spec when a
// record carries none.
func appendURLLine(dst []byte, r *Record) []byte {
	dst = append(dst, "https://"...)
	host := r.Target.Host
	if host == "" {
		host = r.Target.Input
	}
	return append(dst, net.JoinHostPort(host, strconv.Itoa(int(r.Target.Port)))...)
}

func orNoHost(s string) string {
	if s == "" {
		return "(no host)"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
