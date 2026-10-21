package main

// help.go is the CLI's self-description (PQ-38): the -h/-help path whose
// rendering is what an operator sees at the terminal — the intro in
// practitioner terms, the whole implemented surface grouped from the
// one registration surface (flags.go: descriptions read straight off
// the flag set, never duplicated), the stdin grammar, runnable
// examples, the real exit codes, and the reading-the-output glossary.
// No developer-document references: the help is what the terminal
// shows.
//
// The -h pre-scan mirrors chooseFormat's semantics: the scan stops at
// the bare `--` marker (past it, tokens are target data, never
// options) and runs BEFORE the flag set parses, so -h never becomes
// an unknown-flag error.

import (
	"flag"
	"io"
	"strings"
	"unicode/utf8"
)

// helpRequested reports whether the raw argv asks for help: the bare
// -h/-help spellings (any dash count), only before the -- marker; a
// "=false" form does not ask.
func helpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			if name[i+1:] != "true" {
				continue
			}
			name = name[:i]
		}
		if name == "h" || name == "help" {
			return true
		}
	}
	return false
}

// printHelp renders the full help (PQ-38). The intro is written for
// the practitioner: what the tool observes, on both planes, and what a
// rating means — no developer-document references. Flag descriptions
// read straight off the registration surface (flags.go): one source.
// The prose follows ASD-STE100 (one thought per sentence, the fixed
// technical names kept verbatim), so the render reads in the standard
// the census audits.
func printHelp(w io.Writer) {
	fs, _ := newFlagSet()
	var b strings.Builder
	b.WriteString(`pqscan — the TLS/QUIC cipher-configuration and post-quantum readiness scanner.

The tool reads the negotiated cipher configuration of remote endpoints.
The fields: key-exchange group, cipher suite, protocol version, ALPN,
the certificate's signature, the certificate's key algorithm.
The reads run on both planes: TCP/TLS and QUIC/UDP.
A fixed rubric rates every observation on the post-quantum readiness scale.
The record carries the rating as pq=<label>(<score>).
The rating names the layers that hold against a quantum attacker.
The rating names the harvest-now-decrypt-later exposure that remains.
Rejections are results, too: a server that refuses a probe is an
observation, never an error.

THE DOUBLED DASH
  Every flag also takes the doubled dash.
  --word and -word name the same flag.
  The parser reads both spellings alike.
  The rows below show the single-dash form.
  --mode, --jsonl, --u, --l, --o work wherever the rows show
  -mode, -jsonl, -u, -l, -o.
  The shell completions offer both spellings.

TARGETS
  Targets arrive four ways: by flag, by file, by stdin, by the pipe:

  -u example.com                    one target (host, host:port, ip,
                                    ip:port, scheme://host[:port]; the
                                    scheme strips)
  -l targets.txt                    one target spec per line
  -l -                              stdin as the list (the "-" alias; one
                                    line per spec)
  cat targets.txt | pqscan          a piped stdin is the default input
  cat targets.txt | pqscan --       explicit stdin marker (composes with
                                    -u/-l)

  Specs compose: -u, -l, the pipe, the -- marker.
  The compose dedupes by host:port, first occurrence first.
  Default port 443.
  Spec lines accept scheme://host[:port].
  A URL path suffix is the adapters' decoration.
  -from-httpx and -from-naabu strip the scheme and the path.

FLAGS, BY ROLE
`)
	for _, grp := range helpGroups {
		b.WriteString("\n  " + grp.name + "\n")
		for _, name := range grp.flags {
			token, desc := helpRow(fs, name)
			b.WriteString("    " + token + "\n")
			for _, line := range wrap(desc, 76) {
				b.WriteString("      " + line + "\n")
			}
		}
	}
	b.WriteString("\n" + `EXAMPLES
  pqscan -u google.com                          the fast handshake + the readiness rating (default)
  pqscan -u google.com -explain                 the same scan, read back in plain language
  pqscan -u google.com -mode pq                 the forced PQ offer set (every PQ group offered)
  pqscan -u google.com -mode deep               the offer-one probe matrix (the 24-probe default cap)
  cat targets.txt | pqscan -jsonl --            stdin targets in, one schema-1 JSON record per line out
  subfinder -d shain.io -silent | pqscan        the subfinder handoff: the piped stdin IS the input
  subfinder -d shain.io -silent | pqscan -l -   the same handoff by the explicit stdin-file alias
  subfinder -d shain.io -silent | httpx -silent -p 443 | pqscan -jsonl
                                                the live PD chain (httpx's scheme:// lines strip to the host)
  echo https://shain.io | pqscan --             scheme://host[:port] strips on the pipe; same on -u and -l lines
  pqscan -completion zsh > _pqscan              keep the completions (zsh; see GENERAL above)
  httpx -silent -p 443 > hx.txt                 the httpx handoff feeds through the adapter:
  pqscan -from-httpx hx.txt                     paths strip there too (https://host/api is accepted)
  pqscan -l all.txt -shard 1/4 -o s1.jsonl      box 1 of a 4-box pass
  pqscan -l all.txt -resume -o results.out      finish an interrupted run from the WAL
  pqscan -u 10.1.2.3 -ptr -certs-dir certs/     IP target: reverse DNS + PEM cert export
  pqscan -u google.com -rate 5 -threads 50      the pace cap and the window cap
  pqscan -u google.com -debug -debug-out d.json the full diagnostics (attach the file to a bug report)

READING THE OUTPUT
  The default text line: one target per line, key=value fields.
  The readiness rating rides at the end as pq=<label>(<score>).
  -explain expands each line into a plain-language block.
  The block reads the rating in words.
  The block reads the negotiated group: PQ hybrid, classical, obsolete draft.
  The block reads the certificate layer and the QUIC plane.
  The block adds an error hint when nothing negotiated.

  Rating bands (the readiness scale, 0-100):
    pq-ready          >= 80: the key exchange and the certificate layer
                             are both post-quantum
    pq-ready-hybrid   >= 60: the PQ hybrid negotiated, plus one PQ
                             certificate signal
    pq-partial        >= 40: the PQ hybrid negotiated; the certificate
                             layer is classical
    pq-missing        1-39:  a PQ signal is on the record; no PQ
                             negotiation feeds the rating
    scan-error        0:     zero usable PQ signal (an error state, not
                             a rating)

  Group classes:
    pq_hybrid = the post-quantum hybrid (ML-KEM plus a classical curve)
    classic   = classical
    draft     = an obsolete pre-final PQ group (it carries HNDL)
    pq        = pure PQ
    unknown   = unrecognised
  HNDL — harvest-now-decrypt-later: traffic captured today stays
  decryptable to a future quantum computer. Classical key exchanges
  carry the exposure. Obsolete draft groups carry it, too.
  -explain names the layer.

EXIT STATUS
  0    scan complete (results on the output stream; the stream may be empty)
  1    runtime error (a probe failure, an engine failure, a system
       failure during the scan)
  64   usage refusal, nothing scanned: an unknown flag; a bad
       -mode/-deep/-sni value; a bad -shard value; no targets;
       -explain under a machine output format
`)
	_, _ = w.Write([]byte(b.String()))
}

// helpRow resolves one flag's rendered token + description: the token
// from flagTokens (booleans render bare), the description straight off
// the registration surface; the synthetic -- row carries the stdin
// grammar.
func helpRow(fs *flag.FlagSet, name string) (string, string) {
	if name == "--" {
		return "--", `read target specs from stdin — the bare marker. Options live before it. The pipe composes as the default input when no other target source arrives. Piped lines accept scheme://host[:port]. Composes with -u and -l; deduped by host:port.`
	}
	if tok, ok := flagTokens[name]; ok {
		return tok, fs.Lookup(name).Usage
	}
	return "-" + name, fs.Lookup(name).Usage
}

// wrap greedy-wraps a description to the help column, returning the
// content lines (the caller owns the indent); a single overlong word
// rides alone, unsplit.
func wrap(text string, width int) []string {
	var lines []string
	cur := ""
	for _, word := range strings.Fields(text) {
		cand := word
		if cur != "" {
			cand = cur + " " + word
		}
		if utf8.RuneCountInString(cand) <= width {
			cur = cand
			continue
		}
		if cur != "" {
			lines = append(lines, cur)
		}
		cur = word
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// flagGroup is a rendered help section: the group header plus the
// flags in reading order — the help presents the surface in curator's
// order, not registration order.
type flagGroup struct {
	name  string
	flags []string
}

// helpGroups is the rendered order of the implemented surface. The
// PQ-38 rule the table enforces: the help lists what the binary does,
// nothing else — planned flags stay man-page rows. The synthetic "--"
// row carries the stdin grammar. flagTokens holds the value-taking
// flags' display tokens (booleans render as -name directly); it is
// shared with the completion generator. flagFiles are the flags that
// complete to filesystem paths.
var helpGroups = []flagGroup{
	{"GENERAL", []string{"version", "completion"}},
	{"TARGETS AND INPUT", []string{"u", "l", "--", "from-httpx", "from-naabu", "from-nuclei"}},
	{"SCAN MODE", []string{"mode", "deep", "quic-off", "quic-always"}},
	{"PACING", []string{"rate", "threads"}},
	{"MULTI-BOX AND RECOVERY", []string{"shard", "resume"}},
	{"ENRICHMENT", []string{"ptr", "sni", "certs-dir"}},
	{"OUTPUT", []string{"text", "explain", "json", "jsonl", "csv", "urls", "o"}},
	{"DIAGNOSTICS", []string{"debug", "debug-out"}},
}

// flagTokens: the typed-argument flags' display forms (the token a
// reader types), shared with the completion generator.
var flagTokens = map[string]string{
	"u":           "-u target",
	"l":           "-l file",
	"from-httpx":  "-from-httpx file",
	"from-naabu":  "-from-naabu file",
	"from-nuclei": "-from-nuclei file",
	"shard":       "-shard i/n",
	"o":           "-o file",
	"rate":        "-rate rps",
	"threads":     "-threads n",
	"mode":        "-mode fast|deep|pq",
	"deep":        "-deep standard|full",
	"sni":         "-sni auto|ptr-then-ip|ip-only",
	"certs-dir":   "-certs-dir dir",
	"completion":  "-completion shell",
	"debug-out":   "-debug-out file",
}

// flagFiles: the flags whose argument is a filesystem path.
var flagFiles = []string{"l", "o", "certs-dir", "from-httpx", "from-naabu", "from-nuclei", "debug-out"}
