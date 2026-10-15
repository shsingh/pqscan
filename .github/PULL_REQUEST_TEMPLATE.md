<!--
PR title: Conventional Commits form; roadmap slices carry the task id, e.g.
feat(classify): PQ-04 — hybrid-group ladder and readiness verdicts
(A CI gate checks the title form on every PR.) One logical change per PR.
-->
## What

<!-- what changed, one paragraph -->

## Why

<!-- the PQ-XX issue this implements; the linked docs/spec.md sections
(GitHub heading anchors) are the design source -->

Closes PQ-__

## Verification

<!-- how the change is proven: test output, fixture runs, differential evidence -->

- [ ] `gofmt -l .` clean
- [ ] `go vet ./...` green
- [ ] `go test ./...` green
- [ ] relevant fixture/differential evidence linked
