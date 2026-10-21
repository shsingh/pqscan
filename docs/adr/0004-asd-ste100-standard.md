# 0004 — All written text follows ASD-STE100

Status: accepted

## Context

The project's text surface grew past the docs. The CLI help, the refusal
messages, the `-explain` prose, the README, the man page, the spec prose
and the site pages all speak to the same reader: a NETSEC/NETOPS operator.
Two language defects showed the cost. The help descriptions carried project
tracking references; the operators read noise. The refusal prose carried
metaphor nouns and future tense; the operators missed the boundary. The
operator set the writing standard on 2026-10-20: every project text follows
ASD-STE100 Simplified Technical English — including the records the tool
shows and the replies the project's automation writes.

Decision context cites the standing style rules (the zero-reference policy,
the format-parity rule) and the conversion lanes PQ-66, PQ-67, PQ-68.

## Decision

Every written text in the repository follows ASD-STE100:

1. The CLI surface: the help descriptions, the refusal and error messages,
   the `-explain` prose, the completion text.
2. The repository documents: README, USAGE, INSTALL and the spec prose.
3. The site pages: index, usage, recipes, design.
4. The project's issue and PR bodies: forward-written only. The historical
   bodies stay as filed.

The standing rules ride on top: one thought per sentence, twenty words cap,
active voice, present tense, one word per meaning, digits for numbers,
imperative for instructions, the fixed technical names stay exact, and no
tracking references in the rendered text (the zero-reference policy).

## Enforcement

The surface audit carries the banned-word census. It greps the rendered
faces for the banned verbs, the future tense and the tracked-referenced
tokens. A re-introduction goes red in CI. The doc conversion lanes
(PQ-66, PQ-67, PQ-68) re-pin every goldens and want-string in the same
change; the greps carry the four reference families.

## Consequences

- The prose gets shorter. The boundary statements get plainer.
- The record keeps its contract names; only the prose converts.
- New text (issues, answers, docs, CLI strings) starts in the standard.
  The conversion runs one lane per surface, and the merge order is CLI
  surface, then the documents and the site pages.
