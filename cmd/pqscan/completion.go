package main

// completion.go renders the shell-completion scripts (PQ-40): bash
// (complete -F) and zsh (#compdef), generated from the same surface
// table the help renders (flags.go — flag names, the choice values,
// the file-argument flags). stdout is the emission; determinism is a
// contract (sorted flag names + the fixed tables), so two runs byte a
// single stream.

import (
	"flag"
	"fmt"
	"sort"
	"strings"
)

// flagChoices are the enumerated value flags (shared by the help's
// token forms and both completion generators).
var flagChoices = map[string][]string{
	"completion": {"bash", "zsh"},
	"deep":       {"standard", "full"},
	"mode":       {"fast", "deep", "pq"},
	"sni":        {"auto", "ptr-then-ip", "ip-only"},
}

// completionScript resolves the shell and renders its script.
func completionScript(shell string) (string, error) {
	switch shell {
	case "bash":
		return bashScript(), nil
	case "zsh":
		return zshScript(), nil
	default:
		return "", fmt.Errorf("unknown shell %q (want bash or zsh)", shell)
	}
}

// sortedFlagNames is every implemented flag's dash form, lexically
// sorted (deterministic output across builds).
func sortedFlagNames() []string {
	fs, _ := newFlagSet()
	names := []string{}
	fs.VisitAll(func(f *flag.Flag) { names = append(names, "-"+f.Name) })
	sort.Strings(names)
	return names
}

// allDashForms is every implemented flag's BOTH dash spellings (PQ-48:
// the doubled spelling completes beside the single one, since the flag
// parser reads one and two dashes alike), lexically sorted.
func allDashForms() []string {
	fs, _ := newFlagSet()
	names := []string{}
	fs.VisitAll(func(f *flag.Flag) { names = append(names, "-"+f.Name, "--"+f.Name) })
	sort.Strings(names)
	return names
}

// sortedKeys keeps the generated sections' order deterministic.
func sortedKeys(m map[string][]string) []string {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// fileFlagTokens renders the file-argument flags' dash forms (both
// spellings, PQ-48).
func fileFlagTokens() []string {
	toks := []string{}
	for _, name := range flagFiles {
		toks = append(toks, "-"+name, "--"+name)
	}
	sort.Strings(toks)
	return toks
}

// bashScript renders the bash completion (complete -F): flag names,
// the enumerated values per choice flag, file completion for the
// file flags, and the bare -- token (the stdin marker) for non-flag
// words.
func bashScript() string {
	var b strings.Builder
	b.WriteString("# bash completion for pqscan (generated: pqscan -completion bash)\n")
	b.WriteString("# Session: source <(pqscan -completion bash)\n")
	b.WriteString("# Persist: pqscan -completion bash > \"$(bash-completion-writable-dir)/pqscan\"\n\n")
	fmt.Fprintf(&b, "_pqscan_flags=\"%s\"\n", strings.Join(allDashForms(), " "))
	for _, name := range sortedKeys(flagChoices) {
		fmt.Fprintf(&b, "_pqscan_%s_values=\"%s\"\n", name, strings.Join(flagChoices[name], " "))
	}
	fmt.Fprintf(&b, "_pqscan_file_flags=\"%s\"\n", strings.Join(fileFlagTokens(), " "))
	fmt.Fprintf(&b, `
_pqscan_completions() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
`)
	for _, name := range sortedKeys(flagChoices) {
		fmt.Fprintf(&b, "    -%s|--%s) COMPREPLY=($(compgen -W \"$_pqscan_%s_values\" -- \"$cur\")); return;;\n", name, name, name)
	}
	fmt.Fprintf(&b, `    %s) COMPREPLY=($(compgen -f -- "$cur")); return;;
  esac
  if [[ "$cur" == -* ]]; then
    COMPREPLY=($(compgen -W "$_pqscan_flags" -- "$cur"))
  else
    COMPREPLY=($(compgen -W "--" -- "$cur"))
  fi
}
complete -F _pqscan_completions pqscan
`, strings.Join(fileFlagTokens(), "|"))
	return b.String()
}

// zshDesc trims a flag description to its leading phrase and strips
// the characters _arguments would parse (brackets, the description
// colon, apostrophes in single-quoted specs).
func zshDesc(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, "[", "(")
	s = strings.ReplaceAll(s, "]", ")")
	s = strings.ReplaceAll(s, "'", "")
	return strings.TrimSpace(s)
}

// zshScript renders the zsh completion (#compdef): every flag as an
// _arguments spec — booleans bare, value flags with their choice
// lists, the file flags completing to filesystem paths.
func zshScript() string {
	fs, _ := newFlagSet()
	names := sortedFlagNames()
	fileSet := map[string]bool{}
	for _, tok := range fileFlagTokens() {
		fileSet[strings.TrimLeft(tok, "-")] = true // both spellings map same name
	}
	var b strings.Builder
	b.WriteString("#compdef pqscan\n")
	b.WriteString("# Completion for pqscan (generated: pqscan -completion zsh).\n")
	b.WriteString("# Install: pqscan -completion zsh > /usr/local/share/zsh/site-functions/_pqscan\n")
	b.WriteString("# (compinit picks it up); for the session: eval \"$(pqscan -completion zsh)\".\n\n")
	b.WriteString("_pqscan() {\n  local -a opts\n  opts=(\n")
	for _, tok := range names {
		name := strings.TrimLeft(tok, "-")
		desc := zshDesc(fs.Lookup(name).Usage)
		// both dash spellings complete for every flag (PQ-48): the
		// parser reads one and two dashes alike.
		for _, dash := range []string{"-", "--"} {
			var spec string
			switch {
			case flagChoices[name] != nil:
				spec = fmt.Sprintf("    '%s%s[%s]:%s:(%s)'\n", dash, name, desc, name, strings.Join(flagChoices[name], " "))
			case fileSet[name]:
				spec = fmt.Sprintf("    '%s%s[%s]:file:_files'\n", dash, name, desc)
			case name == "u":
				spec = fmt.Sprintf("    '%s%s[%s]:target:'\n", dash, name, desc)
			default:
				spec = fmt.Sprintf("    '%s%s[%s]'\n", dash, name, desc)
			}
			b.WriteString(spec)
		}
	}
	b.WriteString("  )\n  _arguments -S -s $opts\n}\n\n_pqscan \"$@\"\n")
	return b.String()
}
