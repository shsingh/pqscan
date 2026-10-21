# Installing pqscan

Install one static binary. Verify the binary before the first scan.
The [release page](https://github.com/shsingh/pqscan/releases) carries
three platforms (linux/amd64+arm64, darwin/amd64+arm64, windows/amd64)
plus `CHECKSUMS-sha256.txt`. Every binary carries SLSA build provenance
([ADR-0003](docs/adr/0003-slsa-provenance-attestations.md)).

The examples pin the tag `2026.01-rc3`. The release page carries the newest
tag; use it in the commands.

## Verify before the first run

Every published binary carries the build attestation. Download the binary;
then verify:

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
  https://github.com/shsingh/pqscan/releases/download/2026.01-rc3/pqscan-darwin-arm64
chmod +x pqscan && sudo mv pqscan /usr/local/bin/
```

## Linux

```bash
ARCH=$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/)
curl -fsSL -o pqscan \
  "https://github.com/shsingh/pqscan/releases/download/2026.01-rc3/pqscan-linux-${ARCH}"
sha256sum -c <(grep "pqscan-linux-${ARCH}" CHECKSUMS-sha256.txt)   # after fetching CHECKSUMS-sha256.txt
gh attestation verify "pqscan-linux-${ARCH}" -R shsingh/pqscan
chmod +x pqscan && sudo mv pqscan /usr/local/bin/
```

## Windows

```powershell
curl.exe -L -o pqscan.exe `
  "https://github.com/shsingh/pqscan/releases/download/2026.01-rc3/pqscan-windows-amd64.exe"
# verify: sha256 against CHECKSUMS-sha256.txt, then
#   gh attestation verify pqscan-windows-amd64.exe -R shsingh/pqscan

go install github.com/shsingh/pqscan/cmd/pqscan@2026.01-rc3   # from source instead
```

## From source (all platforms)

The module path is `github.com/shsingh/pqscan`; an install by tag pins the
version (recommended over `@latest` until v1):

```bash
go install github.com/shsingh/pqscan/cmd/pqscan@2026.01-rc3
```

Requirements: Go 1.25+ (the toolchain floor in `go.mod`). The binary is
CGO-free. The cross-compile command:
`CGO_ENABLED=0 GOOS=<goos> GOARCH=<goarch> go build -trimpath -ldflags "-s -w" ./cmd/pqscan`.

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

The script comes from the same surface the `-h` help renders. That
surface: every implemented flag, the `-mode`/`-deep`/`-sni`/`-completion`
value lists, and the file completion where a flag takes a path. Re-run
the command after every upgrade; the completion then renders the
binary's current surface.

## Chain the import toolset

The import chain reads the targets off the pipe (the implicit piped stdin;
no `--` marker needed). The httpx `scheme://` lines strip to the host on
the way in. Verified live, end to end:

```bash
subfinder -d shain.io -silent | httpx -silent -p 443 | pqscan -jsonl
```

Each line is schema-1 JSON; the record shape is specified in
[`docs/spec.md#7-data-contract-record-and-pipelines`](docs/spec.md#7-data-contract-record-and-pipelines).
For lists held in files, the adapters `-from-httpx` and `-from-naabu`
parse the same dialects (the scheme and the path strip inside). `-l -`
reads the pipe explicitly.
