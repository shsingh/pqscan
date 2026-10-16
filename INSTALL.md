# Installing pqscan

Install one static binary; verify it before the first scan. The
[release page](https://github.com/shsingh/pqscan/releases) carries three
platforms (linux/amd64+arm64, darwin/amd64+arm64, windows/amd64) plus
`CHECKSUMS-sha256.txt`; every binary carries SLSA build provenance
([ADR-0003](docs/adr/0003-slsa-provenance-attestations.md)).

The tagged version used in the examples below is always the current
release: substitute `2026.01-rc2` with the latest tag from the release
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
  https://github.com/shsingh/pqscan/releases/download/2026.01-rc2/pqscan-darwin-arm64
chmod +x pqscan && sudo mv pqscan /usr/local/bin/
```

## Linux

```bash
ARCH=$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/)
curl -fsSL -o pqscan \
  "https://github.com/shsingh/pqscan/releases/download/2026.01-rc2/pqscan-linux-${ARCH}"
sha256sum -c <(grep "pqscan-linux-${ARCH}" CHECKSUMS-sha256.txt)   # after fetching CHECKSUMS-sha256.txt
gh attestation verify "pqscan-linux-${ARCH}" -R shsingh/pqscan
chmod +x pqscan && sudo mv pqscan /usr/local/bin/
```

## Windows

```powershell
curl.exe -L -o pqscan.exe `
  "https://github.com/shsingh/pqscan/releases/download/2026.01-rc2/pqscan-windows-amd64.exe"
# verify: sha256 against CHECKSUMS-sha256.txt, then
#   gh attestation verify pqscan-windows-amd64.exe -R shsingh/pqscan

go install github.com/shsingh/pqscan/cmd/pqscan@2026.01-rc2   # from source instead
```

## From source (all platforms)

The module path is `github.com/shsingh/pqscan`; installing by tag pins
the version (recommended over `@latest` until v1):

```bash
go install github.com/shsingh/pqscan/cmd/pqscan@2026.01-rc2
```

Requirements: Go 1.25+ (the toolchain floor in `go.mod`). The binary is
CGO-free; cross-compiling is `CGO_ENABLED=0 GOOS=<goos> GOARCH=<goarch>
go build -trimpath -ldflags "-s -w" ./cmd/pqscan`.

## Sanity check

```bash
pqscan -version
pqscan -u example.com
```

## Shell completions

```bash
# zsh (persisted; compinit picks it up on the next shell)
pqscan -completion zsh > /usr/local/share/zsh/site-functions/_pqscan
# or, for the session only
eval "$(pqscan -completion zsh)"
# bash — session, or persist the script into a bash-completion.d drop
source <(pqscan -completion bash)
```

The script is generated from the same surface the `-h` help renders
(every implemented flag, the `-mode`/`-deep`/`-sni`/`-completion` value
lists, and file completion where the flag takes a path); re-run it after
upgrading so the completion matches the binary.

## Chain it with the PD tools

The PD chain reads targets off the pipe (the implicit piped stdin — no
`--` marker needed) and the httpx `scheme://` lines strip to the host on
the way in. Verified live, end to end:

```bash
subfinder -d shain.io -silent | httpx -silent -p 443 | pqscan -jsonl
```

The record shape is specified in
[`docs/spec.md#7-data-contract-record-and-pipelines`](docs/spec.md#7-data-contract-record-and-pipelines);
each line is schema-1 JSON. For lists held in files, the adapters
`-from-httpx` / `-from-naabu` parse the same dialects (scheme and path
stripping built in); `-l -` reads the pipe explicitly.
