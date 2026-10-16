package diag

// buildVersion is the diagnostics-reported build identity. The CLI wires
// it once, BEFORE the sink arms (main.go, from the stamped `version` var
// the release fills via -ldflags "-X main.version=<tag>"); a source
// build prints the default revision. One version symbol: hard-coded
// second copies rot (the rc1 footer printed 0.0.1 while -version
// printed the tag; PQ-38).
var buildVersion = "0.0.1"

// binaryVersion resolves the version stamp for the footer and the
// machine Report (swappable in tests).
var binaryVersion = func() string { return buildVersion }

// SetBinaryVersion records the CLI build's stamped identity — called by
// the command layer before any report is built.
func SetBinaryVersion(v string) { buildVersion = v }
