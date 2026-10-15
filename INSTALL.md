# Installing pqscan

Install one static binary; verify it before the first scan. The
[release page](https://github.com/shsingh/pqscan/releases) carries three
platforms (linux/amd64, linux/arm64, darwin/arm64) plus
`CHECKSUMS-sha256.txt`; every binary carries SLSA build provenance
([ADR-0003](docs/adr/0003-slsa-provenance-attestations.md)).

The tagged version used in the examples below is always the current
release: substitute `v0.0.2-alpha` with the latest tag from the release
page.

## Verify before you run

Every published binary is attested. After downloading:

```bash
sha256sum -c <(grep pqscan-darwin-arm64 CHECKSUMS-sha256.txt)   # checksum
gh attestation verify pqscan-darwin-arm64 -R shsingh/pqscan     # SLSA provenance
```

## macOS (Homebrew)

The maintained tap builds from the signed release tags; the formula
verifier pins the release artifact's sha256.

```bash
brew tap shsingh/tap
brew install pqscan
```

Manual install without Homebrew (Apple Silicon):

```bash
curl -fsSL -o pqscan \
  https://github.com/shsingh/pqscan/releases/download/v0.0.2-alpha/pqscan-darwin-arm64
chmod +x pqscan && sudo mv pqscan /usr/local/bin/
```

## Linux

```bash
ARCH=$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/)
curl -fsSL -o pqscan \
  "https://github.com/shsingh/pqscan/releases/download/v0.0.2-alpha/pqscan-linux-${ARCH}"
sha256sum -c <(grep "pqscan-linux-${ARCH}" CHECKSUMS-sha256.txt)   # after fetching CHECKSUMS-sha256.txt
gh attestation verify "pqscan-linux-${ARCH}" -R shsingh/pqscan
chmod +x pqscan && sudo mv pqscan /usr/local/bin/
```

## Windows

Pre-built windows/amd64 artifacts land with the next versioned cut
([PQ-29](https://github.com/shsingh/pqscan/issues/52); the release
matrix currently covers linux and darwin). Until then, build from
source in a Go environment:

```powershell
go install github.com/shsingh/pqscan/cmd/pqscan@v0.0.2-alpha
```

## From source (all platforms)

The module path is `github.com/shsingh/pqscan`; installing by tag pins
the version (recommended over `@latest` until v1):

```bash
go install github.com/shsingh/pqscan/cmd/pqscan@v0.0.2-alpha
```

Requirements: Go 1.25+ (the toolchain floor in `go.mod`). The binary is
CGO-free; cross-compiling is `CGO_ENABLED=0 GOOS=<goos> GOARCH=<goarch>
go build -trimpath -ldflags "-s -w" ./cmd/pqscan`.

## Sanity check

```bash
pqscan -version
pqscan -u example.com
```

## Chain it with the PD tools

```bash
subfinder -d example.com -silent | httpx -silent | pqscan -mode fast -jsonl | nuclei -jsonl -
```

The record shape is specified in
[`docs/spec.md#7-data-contract-record-and-pipelines`](docs/spec.md#7-data-contract-record-and-pipelines);
each line is schema-1 JSON.
