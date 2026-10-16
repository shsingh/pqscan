package main

import "fmt"

// completionScript renders the shell-completion script for the named
// shell (PQ-40): generated from the same surface table the help
// renders (flags.go — flag names, the choice values, the file-argument
// flags), stdout is the emission, determinism is a contract (the
// tables' fixed order + sorted flag lines).
//
// Stub for PQ-40's watched RED: returns nothing yet.
func completionScript(shell string) (string, error) {
	return "", fmt.Errorf("unknown shell %q (want bash or zsh)", shell)
}

// flagChoices are the enumerated value flags (shared by the help's
// token forms and both completion generators).
var flagChoices = map[string][]string{
	"completion": {"bash", "zsh"},
	"deep":       {"standard", "full"},
	"mode":       {"fast", "deep", "pq"},
	"sni":        {"auto", "ptr-then-ip", "ip-only"},
}
