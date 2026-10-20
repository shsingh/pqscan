// Package differential is the PQ-22 parity engine: the gate that keeps
// pqscan's answers honest against the reference tools gnutls-cli-debug and
// sslyze (docs/spec.md#9-milestones, §10.1 Differential).
//
// Reference-tool transcripts come in through pure parsers
// (ParseGnutlsCLI, ParseSSLyze) fed by an INJECTED Runner seam — the
// real-tool exec harness is the PQ-22 second pair and never runs inside
// offline CI; tests inject canned tool outputs instead (ADR-0002).
// Parity(pqscan, refs) reduces both observation sets into per-check rows:
// protocol agreement (top TLS version), group-class agreement (the pqscan
// side classified via classify.GroupClass, the reference side via its
// textual detail), negotiated-suite agreement (pqscan's suite named by
// every observing reference tool) and — for anything not mappable — a
// NonAgreement row with a Note. Unknown shapes never crash the gate.
//
// The pqscan side is fed by the deep executor (second pair) using these
// check keys: "protocol" (detail = top observed version, e.g. "TLS1.3"),
// "suite" (detail = negotiated suite in RFC/IANA spelling), group rows
// ("group <IANA name>", see GroupCheck) and any other engine surface it
// wants surfaced (surfaced as rule-less rows).
package differential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/shsingh/pqscan/internal/classify"
)

// Obs is one observation handed to Parity: either built from pqscan's own
// engine output (Tool "pqscan") or parsed from a reference tool transcript.
// Observed detail only; classes are DERIVED here from the shared taxonomy
// (classify.GroupClass), never accepted as a tool's self-report — an
// asserted PQ flag on an obs would smuggle in the defect the gate exists
// to catch.
type Obs struct {
	Tool   string
	Check  string
	Detail string
}

// Comparison is one parity row for a check key present on either side.
// PQObs = the pqscan-side rendering of the row (the observed detail, plus
// the derived class in parentheses for group rows); Diff = the concrete
// divergence text ("" when Agree); Note = mapping note (unknown shapes,
// pqscan-only exceptions, rule-less checks).
type Comparison struct {
	Check string
	Agree bool
	PQObs string
	Diff  string
	Note  string
}

// Canonical check keys (spec: protocol / suite / group; anything else is
// rule-less and surfaced with a Note, never dropped silently).
const (
	CheckProtocol    = "protocol"
	CheckSuite       = "suite"
	CheckCertificate = "certificate"
)

// groupCheckPrefix is the row-key prefix for group observations (see
// GroupCheck).
const groupCheckPrefix = "group "

// GroupCheck returns the parity row key for a group observation: the
// canonical IANA name for a group in the comparison name index (alias
// spellings collapse, e.g. OpenSSL's "prime256v1" → secp256r1), else the
// lower-cased raw token. The deep executor keys its group obs through this
// helper so both sides join on identical rows.
func GroupCheck(groupName string) string {
	name := strings.TrimSpace(groupName)
	if cp, ok := groupIndex[strings.ToLower(name)]; ok {
		return groupCheckPrefix + groupCanonical[cp]
	}
	return groupCheckPrefix + strings.ToLower(name)
}

func isGroupCheck(check string) bool {
	return strings.HasPrefix(check, groupCheckPrefix)
}

// Runner is the injected execution seam for the reference tools: the
// real-tool harness (second pair) supplies stdout-capturing runners; tests
// inject canned-output runners so nothing shells out in offline CI.
type Runner interface {
	Run(ctx context.Context, tool string, args ...string) (string, error)
}

// Tool/tool-name vocabulary for Scan.
const (
	ToolGnutlsCLIDebug = "gnutls-cli-debug"
	ToolSSLyze         = "sslyze"
)

// groupIndex maps every accepted surface spelling of a supported group —
// IANA Description tokens, gnutls priority-spelling variants and OpenSSL
// names sslyze reports — to its IANA codepoint. Classes are never stored
// here: resolution routes through classify.GroupClass, so the taxonomy is
// single-sourced. Cross-checked against the committed IANA snapshot by
// TestNameIndexCrossChecksRegistrySnapshot.
var groupIndex = map[string]uint32{
	"x25519":                   29,
	"secp256r1":                23,
	"prime256v1":               23,
	"p-256":                    23,
	"secp384r1":                24,
	"p-384":                    24,
	"secp521r1":                25,
	"p-521":                    25,
	"mlkem512":                 512,
	"mlkem768":                 513,
	"mlkem1024":                514,
	"secp256r1mlkem512":        4585,
	"mlkem512x25519":           4586,
	"secp256r1mlkem768":        4587,
	"x25519mlkem768":           4588,
	"secp384r1mlkem1024":       4589,
	"curvesm2mlkem768":         4590,
	"x25519kyber768draft00":    25497,
	"secp256r1kyber768draft00": 25498,
}

// groupCanonical carries the IANA Description name (registry snapshot
// spelling) for every indexed codepoint — the canonical row-key name and
// the detail used for accepted-group observations.
var groupCanonical = map[uint32]string{
	29:    "x25519",
	23:    "secp256r1",
	24:    "secp384r1",
	25:    "secp521r1",
	512:   "MLKEM512",
	513:   "MLKEM768",
	514:   "MLKEM1024",
	4585:  "SecP256r1MLKEM512",
	4586:  "MLKEM512X25519",
	4587:  "SecP256r1MLKEM768",
	4588:  "X25519MLKEM768",
	4589:  "SecP384r1MLKEM1024",
	4590:  "curveSM2MLKEM768",
	25497: "X25519Kyber768Draft00",
	25498: "SecP256r1Kyber768Draft00",
}

// versionNorm normalizes protocol-version tokens to the canonical forms
// the parity rows use (gnutls "TLS1.3", sslyze's schema field evidence,
// prose "TLS 1.3").
var versionNorm = map[string]string{
	"ssl3.0":  "SSL3.0",
	"sslv3":   "SSL3.0",
	"tls1.0":  "TLS1.0",
	"tlsv1.0": "TLS1.0",
	"tls1.1":  "TLS1.1",
	"tlsv1.1": "TLS1.1",
	"tls1.2":  "TLS1.2",
	"tlsv1.2": "TLS1.2",
	"tls1.3":  "TLS1.3",
	"tlsv1.3": "TLS1.3",
}

// versionRank orders supported-version evidence; the top version is the
// parity row's semantic.
var versionRank = map[string]int{
	"SSL3.0": 1,
	"TLS1.0": 2,
	"TLS1.1": 3,
	"TLS1.2": 4,
	"TLS1.3": 5,
}

func normVersion(token string) string {
	v := strings.ToLower(strings.TrimSpace(token))
	v = strings.ReplaceAll(v, " ", "")
	if out, ok := versionNorm[v]; ok {
		return out
	}
	return ""
}

func topVersion(versions []string) string {
	top := ""
	rank := 0
	for _, v := range versions {
		if r, ok := versionRank[v]; ok && r > rank {
			top, rank = v, r
		}
	}
	return top
}

// suiteNorm maps gnutls/OpenSSL surface spellings to the canonical IANA
// (RFC) name. Spelling divergence is real (gnutls prints TLS1.3-…-style
// names); unknown spellings must stay unknown — never normalized by
// guessing. Keep this table only for verified tool spellings.
var suiteNorm = map[string]string{
	"tls1.3-aes128-gcm-sha256":           "TLS_AES_128_GCM_SHA256",
	"tls1.3-aes256-gcm-sha384":           "TLS_AES_256_GCM_SHA384",
	"tls1.3-chacha20-poly1305-sha256":    "TLS_CHACHA20_POLY1305_SHA256",
	"tls1.3-aes128-ccm-sha256":           "TLS_AES_128_CCM_SHA256",
	"tls1.3-aes128-ccm-8-sha256":         "TLS_AES_128_CCM_8_SHA256",
	"tls1.2-ecdhe-rsa-aes128-gcm-sha256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"ecdhe-rsa-aes128-gcm-sha256":        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
}

func normSuite(token string) string {
	s := strings.ToLower(strings.TrimSpace(token))
	s = strings.ReplaceAll(s, " ", "")
	if out, ok := suiteNorm[s]; ok {
		return out
	}
	// RFC/IANA spellings pass through verbatim (upper-cased).
	if strings.HasPrefix(s, "tls_") && !strings.Contains(s, "-") {
		return strings.ToUpper(s)
	}
	return ""
}

// Scan runs the named reference tool through the INJECTED runner, parses
// the captured output into observations and returns them. Unknown tool
// names error out (never a crash); empty output errors out (never compare
// against nothing).
func Scan(ctx context.Context, tool string, r Runner, args ...string) ([]Obs, error) {
	if r == nil {
		return nil, errors.New("differential: nil injected runner")
	}
	out, err := r.Run(ctx, tool, args...)
	if err != nil {
		return nil, fmt.Errorf("differential: %s runner: %w", tool, err)
	}
	if strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("differential: %s produced empty output", tool)
	}
	switch tool {
	case ToolGnutlsCLIDebug:
		return ParseGnutlsCLI(out)
	case ToolSSLyze:
		return ParseSSLyze(out)
	default:
		return nil, fmt.Errorf("differential: unknown reference tool %q", tool)
	}
}

// gnutlsObs accumulates one transcript's evidence in emission order.
type gnutlsObs struct {
	versions    []string
	suites      []string
	suiteSeen   map[string]bool
	groupKeys   []string
	groupDetail map[string]string
	recognized  int
}

// ParseGnutlsCLI parses gnutls-cli-debug's transcript into observations:
// the per-check verdict lines ("for TLS 1.3 (RFC8446) support... yes",
// "for curve X25519 (RFC8422)... yes") plus the summary shapes
// ("Protocols: TLS1.3, TLS1.2", "Ciphersuites: TLS1.3-AES128-GCM-SHA256",
// "- Version: ...", "- Ciphersuite: ..."). Protocol verdicts collapse to
// the top supported version; group verdicts become per-group rows
// ("yes" = the canonical group name, "no" = "not accepted"); suites list
// as accepted-suite rows under canonical IANA names. Non-parity checks
// (renegotiation, MACs, ciphers-family, ...) are ignored. A transcript
// with no recognizable reference-tool shape errors out.
func ParseGnutlsCLI(output string) ([]Obs, error) {
	acc := &gnutlsObs{suiteSeen: map[string]bool{}, groupDetail: map[string]string{}}
	for _, ln := range strings.Split(output, "\n") {
		line := strings.TrimSpace(ln)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Protocols:"):
			acc.recognized++
			for _, tok := range strings.Split(strings.TrimPrefix(line, "Protocols:"), ",") {
				if v := normVersion(tok); v != "" {
					acc.versions = append(acc.versions, v)
				}
			}
		case strings.HasPrefix(line, "Ciphersuites:"):
			acc.recognized++
			acc.addSuites(strings.TrimPrefix(line, "Ciphersuites:"))
		case strings.HasPrefix(line, "- Ciphersuite:"):
			acc.recognized++
			acc.addSuites(strings.TrimPrefix(line, "- Ciphersuite:"))
		case strings.HasPrefix(line, "- Version:"):
			acc.recognized++
			rest := strings.TrimPrefix(line, "- Version:")
			if idx := strings.IndexByte(rest, '.'); idx >= 0 {
				rest = rest[:idx]
			}
			if v := normVersion(rest); v != "" {
				acc.versions = append(acc.versions, v)
			}
		default:
			acc.checkLine(line)
		}
	}
	if acc.recognized == 0 {
		return nil, errors.New("differential: no recognizable gnutls-cli-debug output")
	}
	obs := make([]Obs, 0, 1+len(acc.groupKeys)+len(acc.suites))
	if v := topVersion(acc.versions); v != "" {
		obs = append(obs, Obs{Tool: ToolGnutlsCLIDebug, Check: CheckProtocol, Detail: v})
	}
	for _, key := range acc.groupKeys {
		obs = append(obs, Obs{Tool: ToolGnutlsCLIDebug, Check: key, Detail: acc.groupDetail[key]})
	}
	for _, suite := range acc.suites {
		obs = append(obs, Obs{Tool: ToolGnutlsCLIDebug, Check: CheckSuite, Detail: suite})
	}
	return obs, nil
}

// addSuites splits a comma-separated gnutls suite list into canonical
// accepted-suite evidence (deduplicated, first-appearance order).
func (a *gnutlsObs) addSuites(list string) {
	for _, tok := range strings.Split(list, ",") {
		if s := normSuite(tok); s != "" && !a.suiteSeen[s] {
			a.suiteSeen[s] = true
			a.suites = append(a.suites, s)
		}
	}
}

// checkLine parses one gnutls check-verdict line: "<check-name>...
// <verdict>" with verdicts yes / no / dunno. Only version and curve checks
// carry parity evidence (family checks — AES-GCM, MACs, renegotiation, ... —
// are ignored); "dunno" verdicts are never asserted as observations.
func (a *gnutlsObs) checkLine(line string) {
	idx := strings.Index(line, "...")
	if idx <= 0 {
		return
	}
	name := strings.TrimSpace(line[:idx])
	verdict := strings.TrimSpace(line[idx+3:])
	switch verdict {
	case "yes", "no":
	default:
		return
	}

	if name == "" || !strings.HasPrefix(name, "for ") {
		return
	}
	if rest, ok := cutCurveName(name); ok {
		a.recognized++
		key := GroupCheck(rest)
		if _, seen := a.groupDetail[key]; seen {
			return
		}
		detail := strings.ToLower(rest)
		if cp, resolved := groupIndex[strings.ToLower(rest)]; resolved {
			detail = groupCanonical[cp]
		}
		if verdict == "no" {
			detail = "not accepted"
		}
		a.groupDetail[key] = detail
		a.groupKeys = append(a.groupKeys, key)
		return
	}

	// "for <v> (RFC…) support" version checks: the RFC-annotated support
	// probes. The record-version variants ("... support with TLS 1.0
	// record version") deliberately match the same rule — the
	// record-version probe is the same version evidence. Inverted checks
	// ("whether we need to disable TLS 1.2") carry neither an
	// "(RFC" marker nor this wording, and are skipped.
	if !strings.Contains(name, "(RFC") || !strings.Contains(name, " support") {
		return
	}
	if v := extractVersionToken(name); v != "" {
		a.recognized++
		if verdict == "yes" {
			a.versions = append(a.versions, v)
		}
	}
}

// cutCurveName extracts the curve token from "for curve <NAME> (RFC…)".
func cutCurveName(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, "for curve ")
	if !ok {
		return "", false
	}
	if idx := strings.LastIndex(rest, "("); idx > 0 {
		rest = rest[:idx]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	return rest, true
}

// extractVersionToken finds "TLS 1.x" / "SSL 3.0" prose inside a check
// name and normalizes it; family checks never match.
func extractVersionToken(name string) string {
	for _, prefix := range []string{"TLS ", "SSL "} {
		idx := strings.Index(name, prefix)
		if idx < 0 {
			continue
		}
		rest := name[idx+len(prefix):]
		if dot := strings.IndexByte(rest, ' '); dot >= 0 {
			rest = rest[:dot]
		}
		if v := normVersion(prefix + rest); v != "" {
			return v
		}
	}
	return ""
}

// sslyzeRoot is the recognizable slice of sslyze's released JSON root
// (nabla-c0d3/sslyze json_output_schema.json): the scan results live under
// server_scan_results[].scan_result.
type sslyzeRoot struct {
	ServerScanResults []sslyzeScanResult `json:"server_scan_results"`
}

type sslyzeScanResult struct {
	ServerLocation sslyzeLocation     `json:"server_location"`
	ScanResult     *sslyzeScanResults `json:"scan_result"`
}

type sslyzeLocation struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

// sslyzeScanResults carries the schema's per-command attempt fields; the
// per-version suite attempts exist as distinct schema keys, so they are
// named fields (the iteration in ParseSSLyze fixes their emission order).
type sslyzeScanResults struct {
	CertificateInfo *sslyzeAttempt `json:"certificate_info"`
	SSL2_0          *sslyzeAttempt `json:"ssl_2_0_cipher_suites"`
	SSL3_0          *sslyzeAttempt `json:"ssl_3_0_cipher_suites"`
	TLS1_0          *sslyzeAttempt `json:"tls_1_0_cipher_suites"`
	TLS1_1          *sslyzeAttempt `json:"tls_1_1_cipher_suites"`
	TLS1_2          *sslyzeAttempt `json:"tls_1_2_cipher_suites"`
	TLS1_3          *sslyzeAttempt `json:"tls_1_3_cipher_suites"`
	EllipticCurves  *sslyzeAttempt `json:"elliptic_curves"`
}

type sslyzeAttempt struct {
	Status string          `json:"status"`
	Result json.RawMessage `json:"result"`
}

type sslyzeSuiteResult struct {
	TLSVersionUsed string                `json:"tls_version_used"`
	IsSupported    bool                  `json:"is_tls_version_supported"`
	Accepted       []sslyzeSuiteAccepted `json:"accepted_cipher_suites"`
	Rejected       []sslyzeSuiteAccepted `json:"rejected_cipher_suites"`
}

type sslyzeSuiteAccepted struct {
	CipherSuite sslyzeSuiteName `json:"cipher_suite"`
}

type sslyzeSuiteName struct {
	Name        string `json:"name"`
	OpensslName string `json:"openssl_name"`
}

type sslyzeCurvesResult struct {
	SupportsECDH    bool          `json:"supports_ecdh_key_exchange"`
	SupportedCurves []sslyzeCurve `json:"supported_curves"`
	RejectedCurves  []sslyzeCurve `json:"rejected_curves"`
}

type sslyzeCurve struct {
	Name string `json:"name"`
}

type sslyzeCertResult struct {
	CertificateDeployments []struct {
		CertificateChain []struct {
			ChainPosition int             `json:"chain_position"`
			Certificate   sslyzeCertEntry `json:"certificate"`
		} `json:"certificate_chain"`
	} `json:"certificate_deployments"`
}

type sslyzeCertEntry struct {
	SignatureHashAlgorithm string `json:"signature_hash_algorithm"`
	SignatureAlgorithmOID  *struct {
		Name string `json:"name"`
	} `json:"signature_algorithm_oid"`
	PublicKey *sslyzePublicKey `json:"public_key"`
}

type sslyzePublicKey struct {
	Algorithm string `json:"algorithm"`
	KeySize   *int   `json:"key_size"`
}

// ParseSSLyze parses sslyze's JSON output into observations from its
// scan_result fields: per-version cipher-suite results (protocol evidence
// + accepted suites), the elliptic_curves result (supported/rejected
// groups) and the leaf certificate info (signature + key). Unknown JSON
// shapes error out with a recognizable message; malformed JSON errors out.
func ParseSSLyze(output string) ([]Obs, error) {
	var root sslyzeRoot
	if err := json.Unmarshal([]byte(output), &root); err != nil {
		return nil, fmt.Errorf("differential: unparseable sslyze JSON: %w", err)
	}
	if root.ServerScanResults == nil {
		return nil, errors.New("differential: unrecognized sslyze JSON shape (missing server_scan_results)")
	}

	var versions []string
	var groups []Obs
	var suites []Obs
	suiteSeen := map[string]bool{}
	var certObs []Obs

	for _, result := range root.ServerScanResults {
		if result.ScanResult == nil {
			continue
		}
		sr := result.ScanResult

		// Version evidence + accepted suites: suite attempts in the
		// documented schema order (oldest → newest) so emissions
		// stabilize across runs.
		for _, va := range []struct {
			version string
			attempt *sslyzeAttempt
		}{
			{"SSL2.0", sr.SSL2_0},
			{"SSL3.0", sr.SSL3_0},
			{"TLS1.0", sr.TLS1_0},
			{"TLS1.1", sr.TLS1_1},
			{"TLS1.2", sr.TLS1_2},
			{"TLS1.3", sr.TLS1_3},
		} {
			if va.attempt == nil || va.attempt.Result == nil {
				continue
			}
			var suiteResult sslyzeSuiteResult
			if err := json.Unmarshal(va.attempt.Result, &suiteResult); err != nil {
				return nil, fmt.Errorf("differential: unrecognized sslyze JSON shape (%s: %w)", va.version, err)
			}
			if va.attempt.Status == "COMPLETED" && suiteResult.IsSupported {
				versions = append(versions, va.version)
			}
			for _, accepted := range suiteResult.Accepted {
				name := accepted.CipherSuite.Name
				if name == "" {
					name = accepted.CipherSuite.OpensslName
				}
				canonical := normSuite(name)
				if canonical == "" || suiteSeen[canonical] {
					continue
				}
				suiteSeen[canonical] = true
				suites = append(suites, Obs{Tool: ToolSSLyze, Check: CheckSuite, Detail: canonical})
			}
		}

		// Supported/rejected groups.
		if sr.EllipticCurves != nil && sr.EllipticCurves.Result != nil {
			var curves sslyzeCurvesResult
			if err := json.Unmarshal(sr.EllipticCurves.Result, &curves); err != nil {
				return nil, fmt.Errorf("differential: unrecognized sslyze JSON shape (elliptic_curves: %w)", err)
			}
			for _, curve := range curves.SupportedCurves {
				groups = append(groups, groupObservation(ToolSSLyze, curve.Name, ""))
			}
			for _, curve := range curves.RejectedCurves {
				groups = append(groups, groupObservation(ToolSSLyze, curve.Name, "not accepted"))
			}
		}

		// Leaf certificate info (signature + key surface; rule-less in
		// parity — surfaced with a Note, parsed for the report).
		if sr.CertificateInfo != nil && sr.CertificateInfo.Result != nil {
			var cert sslyzeCertResult
			if err := json.Unmarshal(sr.CertificateInfo.Result, &cert); err != nil {
				return nil, fmt.Errorf("differential: unrecognized sslyze JSON shape (certificate_info: %w)", err)
			}
			if leaf := leafCert(cert); leaf != nil {
				if detail := certDetail(*leaf); detail != "" {
					certObs = append(certObs, Obs{Tool: ToolSSLyze, Check: CheckCertificate, Detail: detail})
				}
			}
		}
	}

	if len(versions) == 0 && len(groups) == 0 && len(suites) == 0 && len(certObs) == 0 {
		return nil, errors.New("differential: unrecognized sslyze JSON shape (no scan evidence)")
	}

	obs := make([]Obs, 0, 1+len(groups)+len(suites)+len(certObs))
	if v := topVersion(versions); v != "" {
		obs = append(obs, Obs{Tool: ToolSSLyze, Check: CheckProtocol, Detail: v})
	}
	obs = append(obs, groups...)
	obs = append(obs, suites...)
	obs = append(obs, certObs...)
	return obs, nil
}

// groupObservation builds one group-row observation from a tool's
// textual group name (canonical key; unresolvable names keep their raw
// token and surface as unknown semantics in parity).
func groupObservation(tool, groupName, forced string) Obs {
	detail := forced
	if forced == "" {
		if cp, resolved := groupIndex[strings.ToLower(strings.TrimSpace(groupName))]; resolved {
			detail = groupCanonical[cp]
		} else {
			detail = strings.TrimSpace(groupName)
		}
	}
	return Obs{Tool: tool, Check: GroupCheck(groupName), Detail: detail}
}

// leafCert picks the leaf (chain_position 0, falling back to the first
// chain entry).
func leafCert(cert sslyzeCertResult) *sslyzeCertEntry {
	for _, dep := range cert.CertificateDeployments {
		for i, link := range dep.CertificateChain {
			if link.ChainPosition == 0 || i == 0 {
				return &link.Certificate
			}
		}
	}
	return nil
}

// certDetail renders the leaf's signature + key surface.
func certDetail(entry sslyzeCertEntry) string {
	var parts []string
	sig := entry.SignatureHashAlgorithm
	if entry.SignatureAlgorithmOID != nil && entry.SignatureAlgorithmOID.Name != "" {
		sig = entry.SignatureAlgorithmOID.Name
	}
	if sig != "" {
		parts = append(parts, "sig="+sig)
	}
	if entry.PublicKey != nil && entry.PublicKey.Algorithm != "" {
		key := entry.PublicKey.Algorithm
		if entry.PublicKey.KeySize != nil {
			key = fmt.Sprintf("%s(%d)", key, *entry.PublicKey.KeySize)
		}
		parts = append(parts, "key="+key)
	}
	return strings.Join(parts, "; ")
}

// groupSemantic resolves a textual group detail to the taxonomy class via
// the name index and classify.GroupClass. ok=false means the detail
// resolves to nothing (unknown semantics — surfaced, never invented).
func groupSemantic(detail string) (class classify.Class, cp uint32, ok bool) {
	id, resolvable := groupIndex[strings.ToLower(strings.TrimSpace(detail))]
	if !resolvable {
		return "", 0, false
	}
	class, ok = classify.GroupClass(id)
	return class, id, ok
}

// groupBucket collapses a full taxonomy class into the three-bucket
// semantics the reference sides are compared in (hybrid / pq / classical).
func groupBucket(class classify.Class) string {
	switch class {
	case classify.ClassPQ:
		return "pq"
	case classify.ClassPQHybrid, classify.ClassPQHybridD, classify.ClassHybridSM:
		return "hybrid"
	case classify.ClassClassic, classify.ClassObsolete:
		return "classical"
	}
	return ""
}

// groupRender renders a group detail with its derived class for the
// parity rows ("X25519MLKEM768 (pq_hybrid)"); unresolvable details render
// without a class and carry bucket=false (unknown semantics).
func groupRender(detail string) (rendered string, bucket string, ok bool) {
	class, _, resolved := groupSemantic(detail)
	if !resolved || !taxonomized(class) {
		return detail + " (unresolvable)", "", false
	}
	rendered = fmt.Sprintf("%s (%s)", detail, class)
	bucket = groupBucket(class)
	ok = bucket != ""
	return rendered, bucket, ok
}

// taxonomized reports whether classify pins the codepoint's class (ok=true
// from GroupClass). Unknown codepoints stay unknown — parity must never
// invent a classical verdict for an unrecognised group.
func taxonomized(class classify.Class) bool {
	return class != ""
}

// Parity compares the pqscan-side observations with the reference-tool
// observations check by check and returns one row per joined key
// (deterministic, sorted by Check):
//
//   - protocol: agreement on the top observed TLS version
//     (both = TLS1.3 = agree).
//   - suite: agreement when pqscan's negotiated suite is named by every
//     observing reference tool (suite spellings normalized through the
//     gnutls/RFC equivalence table; un-normalizable names → NonAgreement
//     with a Note).
//   - group <name>: class agreement — the pqscan side's classification
//     comes from classify.GroupClass (via the name index), the reference
//     side's semantic from its textual detail. A PQ-class mismatch is
//     flagged (NonAgreement + Diff text). A group only pqscan observed is
//     the documented exception (the reference tools cannot construct PQ
//     groups): Agree=true with an explanatory Note.
//   - anything else: NonAgreement with a Note ("no parity rule"), never a
//     crash; reference details that resolve to nothing get the same
//     treatment.
func Parity(pqscan []Obs, refs []Obs) []Comparison {
	pqByCheck := obsByCheck(pqscan)
	refByCheck := obsByCheck(refs)

	keys := make([]string, 0, len(pqByCheck)+len(refByCheck))
	seenKeys := map[string]bool{}
	for k := range pqByCheck {
		if !seenKeys[k] {
			seenKeys[k] = true
			keys = append(keys, k)
		}
	}
	for k := range refByCheck {
		if !seenKeys[k] {
			seenKeys[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	rows := make([]Comparison, 0, len(keys))
	for _, key := range keys {
		switch {
		case key == CheckProtocol:
			rows = append(rows, parityProtocol(pqByCheck[key], refByCheck[key]))
		case key == CheckSuite:
			rows = append(rows, paritySuite(pqByCheck[key], refByCheck[key]))
		case isGroupCheck(key):
			rows = append(rows, parityGroup(key, pqByCheck[key], refByCheck[key]))
		default:
			rows = append(rows, parityRuleless(key))
		}
	}
	return rows
}

func obsByCheck(obs []Obs) map[string][]Obs {
	byCheck := map[string][]Obs{}
	for _, o := range obs {
		byCheck[o.Check] = append(byCheck[o.Check], o)
	}
	return byCheck
}

// parityProtocol compares the top observed protocol version per side;
// reference tools that disagree among themselves are surfaced too.
func parityProtocol(pq, refs []Obs) Comparison {
	row := Comparison{Check: CheckProtocol}
	pqTop := topVersion(obsDetails(pq))
	if len(pq) == 0 || pqTop == "" {
		if len(pq) == 0 {
			row.Note = "no pqscan observation for check 'protocol'"
		} else {
			row.Note = fmt.Sprintf("pqscan protocol detail unresolvable: %q", pq[0].Detail)
		}
		return row
	}
	row.PQObs = pqTop
	if len(refs) == 0 {
		row.Note = "no reference observation for check 'protocol'"
		return row
	}
	toolVersions := map[string][]string{}
	for _, rf := range refs {
		if v := normVersion(rf.Detail); v != "" {
			toolVersions[rf.Tool] = append(toolVersions[rf.Tool], v)
		}
	}
	if len(toolVersions) == 0 {
		row.Agree = false
		row.Note = fmt.Sprintf("reference protocol detail unresolvable: %q", refs[0].Detail)
		return row
	}
	refTops := map[string]string{}
	for tool, vs := range toolVersions {
		refTops[tool] = topVersion(vs)
	}
	top := ""
	for _, tool := range sortedKeys(refTops) {
		t := refTops[tool]
		if top == "" {
			top = t
			continue
		}
		if t != top {
			row.Agree = false
			row.Note = "reference tools disagree among themselves"
			row.Diff = fmt.Sprintf("reference tops: %s", refTopsSorted(refTops))
			return row
		}
	}
	if top == pqTop {
		row.Agree = true
		return row
	}
	row.Agree = false
	for _, tool := range sortedKeys(refTops) {
		if refTops[tool] != pqTop {
			row.Diff = fmt.Sprintf("pqscan: %s vs %s: %s", pqTop, tool, refTops[tool])
			return row
		}
	}
	return row
}

// refTopsSorted renders the per-tool top versions deterministically.
func refTopsSorted(refTops map[string]string) string {
	pairList := make([]string, 0, len(refTops))
	for _, tool := range sortedKeys(refTops) {
		pairList = append(pairList, fmt.Sprintf("%s=%s", tool, refTops[tool]))
	}
	return strings.Join(pairList, ", ")
}

// paritySuite verifies pqscan's negotiated suite is named by every
// observing reference tool (after gnutls/RFC spelling normalization).
func paritySuite(pq, refs []Obs) Comparison {
	row := Comparison{Check: CheckSuite}
	if len(pq) == 0 {
		row.Note = "no pqscan observation for check 'suite'"
		return row
	}
	details := obsDetails(pq)
	resolved := make([]string, 0, len(details))
	for _, d := range details {
		if s := normSuite(d); s != "" {
			resolved = append(resolved, s)
		}
	}
	if len(resolved) == 0 {
		row.Note = fmt.Sprintf("pqscan suite detail unresolvable: %q", pq[0].Detail)
		return row
	}
	distinct := sortedUnique(resolved)
	if len(distinct) > 1 {
		row.Note = fmt.Sprintf("pqscan reports multiple negotiated suites: %v", distinct)
		return row
	}
	row.PQObs = distinct[0]
	if len(refs) == 0 {
		row.Note = "no reference observation for check 'suite'"
		return row
	}
	toolSets := map[string][]string{}
	for _, rf := range refs {
		s := normSuite(rf.Detail)
		if s == "" {
			row.Agree = false
			row.Note = fmt.Sprintf("reference suite name %q not in the gnutls/RFC equivalence table", rf.Detail)
			return row
		}
		toolSets[rf.Tool] = append(toolSets[rf.Tool], s)
	}
	for _, tool := range sortedKeys(toolSets) {
		set := sortedUnique(toolSets[tool])
		if suiteIn(set, row.PQObs) {
			continue
		}
		row.Agree = false
		row.Diff = fmt.Sprintf("pqscan: %s not among %s: %s", row.PQObs, tool, strings.Join(set, ", "))
		return row
	}
	row.Agree = true
	return row
}

// parityGroup compares group semantics: pqscan's detail classified via
// classify.GroupClass, the reference side's via its textual detail (or its
// explicit rejection). A group only the pqscan side observed is the
// documented exception class (reference tools cannot construct PQ groups).
func parityGroup(key string, pq, refs []Obs) Comparison {
	row := Comparison{Check: key}
	name := strings.TrimSpace(strings.TrimPrefix(key, groupCheckPrefix))
	if len(pq) == 0 {
		if len(refs) == 0 {
			return row
		}
		if allRejected(refs) {
			row.Agree = true
			row.Note = fmt.Sprintf("both sides reject or omit %s", name)
			return row
		}
		for _, rf := range refs {
			if rf.Detail == "not accepted" {
				continue
			}
			if _, _, ok := groupRender(rf.Detail); !ok {
				row.Note = fmt.Sprintf("reference semantic unknown for %q", rf.Detail)
				return row
			}
		}
		row.Note = fmt.Sprintf("no pqscan observation for %s (possible coverage gap)", key)
		return row
	}

	pqRender, pqBucket, pqOK := groupRender(pq[0].Detail)
	row.PQObs = pqRender
	if !pqOK {
		row.Agree = false
		row.Note = fmt.Sprintf("pqscan semantic unknown for %q", pq[0].Detail)
		return row
	}

	if len(refs) == 0 {
		row.Agree = true
		row.Note = fmt.Sprintf("no reference observation for %s (pqscan-only probe)", name)
		return row
	}

	var refBuckets []string
	for _, rf := range refs {
		if rf.Detail == "not accepted" {
			row.Agree = false
			row.Diff = fmt.Sprintf("pqscan: %s vs %s: not accepted", pqRender, rf.Tool)
			return row
		}
		_, refBucket, refOK := groupRender(rf.Detail)
		if !refOK {
			row.Agree = false
			row.Note = fmt.Sprintf("reference semantic unknown for %q", rf.Detail)
			return row
		}
		refBuckets = append(refBuckets, refBucket)
	}
	top := refBuckets[0]
	for _, b := range refBuckets[1:] {
		if b != top {
			row.Agree = false
			row.Note = "reference tools disagree among themselves"
			return row
		}
	}
	if top != pqBucket {
		// The PQ-class mismatch: pqscan's derived class contradicts the
		// reference's semantic for the same group.
		row.Agree = false
		first := refs[0]
		refRender := first.Detail
		if class, _, ok := groupSemantic(first.Detail); ok && class != "" {
			refRender = fmt.Sprintf("%s (%s)", first.Detail, class)
		}
		row.Diff = fmt.Sprintf("pqscan: %s vs %s: %s", pqRender, first.Tool, refRender)
		return row
	}
	row.Agree = true
	return row
}

// parityRuleless surfaces checks parity has no mapping rule for — visible,
// noted, never a crash.
func parityRuleless(key string) Comparison {
	return Comparison{
		Check: key,
		Agree: false,
		Note:  fmt.Sprintf("no parity rule for check '%s' (informational)", key),
	}
}

// allRejected reports whether every reference observation is an explicit
// rejection (the both-sides-empty symmetry case).
func allRejected(refs []Obs) bool {
	for _, rf := range refs {
		if rf.Detail != "not accepted" {
			return false
		}
	}
	return true
}

// obsDetails collects the Details of the observations in order.
func obsDetails(obs []Obs) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.Detail)
	}
	return out
}

// sortedUnique returns a sorted deduplicated copy (deterministic rows).
func sortedUnique(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return dedup(out)
}

// dedup squashes adjacent duplicates of a sorted slice.
func dedup(sorted []string) []string {
	out := make([]string, 0, len(sorted))
	for i, s := range sorted {
		if i == 0 || sorted[i-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// suiteIn reports set membership.
func suiteIn(set []string, suite string) bool {
	for _, s := range set {
		if s == suite {
			return true
		}
	}
	return false
}

// sortedKeys returns the map keys sorted (deterministic iteration).
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
