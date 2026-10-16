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
	"fmt"
	"io"
	"strings"
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

// printHelp renders the help. Stub for PQ-38's watched RED: the full
// rendering lands after the pins read it.
func printHelp(w io.Writer) {
	fmt.Fprintln(w, "pqscan")
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
	{"GENERAL", []string{"version"}},
	{"TARGETS AND INPUT", []string{"u", "l", "--", "from-httpx", "from-naabu"}},
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
	"u":          "-u target",
	"l":          "-l file",
	"from-httpx": "-from-httpx file",
	"from-naabu": "-from-naabu file",
	"shard":      "-shard i/n",
	"o":          "-o file",
	"rate":       "-rate rps",
	"threads":    "-threads n",
	"mode":       "-mode fast|deep|pq",
	"deep":       "-deep standard|full",
	"sni":        "-sni auto|ptr-then-ip|ip-only",
	"certs-dir":  "-certs-dir dir",
	"debug-out":  "-debug-out file",
}

// flagFiles: the flags whose argument is a filesystem path.
var flagFiles = []string{"l", "o", "certs-dir", "from-httpx", "from-naabu", "debug-out"}
