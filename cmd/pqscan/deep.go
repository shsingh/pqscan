// deep.go — PQ-20's deep-mode executor wiring (issue #43; spec §7.4): the
// -mode dispatch. FAST mode is the shipped single-handshake probe
// (unchanged); PQ mode runs the forced PQ ladder (tlsx.GroupLadder over
// the standards-track PQ hybrids 4585–4590 + the obsolete-Kyber drafts)
// and lands the ladder's observations in the record's handshake + pq
// blocks; DEEP mode consumes internal/deepplan's plan: the profile
// handshake runs FIRST and feeds deepplan.Observed (spec §7.4 phase 1
// gates phase 2), the executor then dispatches every probe offer-one and
// lands the executed plan in the record's deep block.
package main

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/shsingh/pqscan/internal/classify"
	"github.com/shsingh/pqscan/internal/deepplan"
	"github.com/shsingh/pqscan/internal/diag"
	"github.com/shsingh/pqscan/internal/grammar"
	"github.com/shsingh/pqscan/internal/out"
	"github.com/shsingh/pqscan/internal/tlsx"
)

// The mode labels (-mode) and the deep plan selector (-deep) as the
// commands surface them; the record's mode field carries the same token.
const (
	modeFast = "fast"
	modeDeep = "deep"
	modePQ   = "pq"

	deepStandard = "standard"
	deepFull     = "full"
)

// pqLadderGroups is the forced PQ group ladder of -mode pq (spec §5.2's
// PQ ladder, §7.4's executor wiring): the registry's standards-track PQ
// hybrid block 4585–4590 (RFC 10024 + the SM2 hybrid) then the obsolete
// Kyber drafts (25497/25498, the HNDL oracle) — every step a forced offer.
var pqLadderGroups = []uint32{4585, 4586, 4587, 4588, 4589, 4590, 25497, 25498}

// draftGroups is the pre-standards codepoint set whose acceptance is the
// HNDL signal (the draft observation rides the raw share-less path; a
// draft group can never be a stdlib-negotiated step).
var draftGroups = map[uint32]bool{25497: true, 25498: true}

// validMode reports whether m is a defined -mode value.
func validMode(m string) bool {
	switch m {
	case modeFast, modeDeep, modePQ:
		return true
	default:
		return false
	}
}

// validDeepPlan reports whether d is a defined -deep plan value.
func validDeepPlan(d string) bool {
	switch d {
	case deepStandard, deepFull:
		return true
	default:
		return false
	}
}

// scanTargetDeep executes the target's deep plan (PQ-20): the mode's
// FAST profile shape (handshake, cert, rubric, QUIC — identical to fast
// mode) runs first and feeds the plan builder's Observed (spec §7.4:
// phase 1 prunes phase 2 — the negotiated pair, group, version and the
// cert probe the profile handshake already answered are never re-run),
// then every planned probe dispatches offer-one by kind and the executed
// plan lands in the record's deep block. A failed profile handshake
// short-circuits the plan (a target that refuses the profile dial refuses
// every probe; the record's error is that verdict — no invented
// refusals-only block).
//
// The per-target probes ride one per-probe budget (the §7.4 deadline
// ladder is a planned surface) and launch in plan order — one handshake
// at a time; in-plan concurrency rides the congestion lane's per-target
// scheduler, and the engine's rate/window surfaces govern the TARGET
// dispatch (not in-plan probes).
func scanTargetDeep(t grammar.Target, opts Options) (*scanRecord, bool, bool) {
	rec, res, failing, timedOut := scanTargetFast(t, opts)
	rec.Mode = modeDeep
	if failing || rec.Error != "" {
		// The profile handshake gated phase 2 (spec §7.4): nothing is
		// planned past a failed profile dial — the record keeps the
		// fast shape's error path, no deep block invented.
		return rec, failing, timedOut
	}
	plan, err := deepplan.Build(t.Input, planModeFor(opts), observedFromProfile(rec, res))
	if err != nil {
		// Build validates the target + plan mode; the CLI validated
		// -deep already, so an error here is a wiring bug — surfaced in
		// the record and the diagnostics, never silently dropped.
		diag.Emit(diag.Error, diag.DomEngine, "deep", t.Host, "deep plan build failed", err, nil)
		rec.Error = err.Error()
		return rec, failing, timedOut
	}
	rec.Deep = executeDeepPlan(t, opts, plan)
	diag.Emit(diag.Info, diag.DomEngine, "deep", t.Host, "deep plan executed", nil,
		map[string]string{"plan": plan.Mode, "attempted": strconv.Itoa(rec.Deep.Attempted),
			"ok": strconv.Itoa(rec.Deep.OK), "rejected": strconv.Itoa(rec.Deep.Rejected)})
	return rec, failing, timedOut
}

// observedFromProfile maps the profile handshake's facts onto the plan
// builder's Observed (spec §7.4 phase 1): the negotiated group/suite/
// version and whether the same handshake delivered an analyzable chain.
func observedFromProfile(rec *scanRecord, res *tlsx.ProbeResult) *deepplan.Observed {
	obs := &deepplan.Observed{
		NegotiatedGroup: rec.Handshake.Negotiated,
		NegotiatedSuite: rec.Handshake.Suite,
	}
	if res != nil {
		obs.Version = res.Version
		obs.HasCert = res.CertificateInfo != nil
	}
	return obs
}

// scanTargetPQ runs the forced PQ ladder (PQ-20): the mode's FAST profile
// shape first (the cert facts, the browser-grade posture, the QUIC plane
// and the engine's breaker/AIMD signal ride exactly like fast mode), then
// the ladder (4585–4590 + the obsolete drafts) whose observations land in
// the record: the handshake block is the ladder's first accepted hybrid
// (falling back to the profile handshake's facts when nothing PQ was
// accepted), and the pq verdict is SCORED from the ladder's facts —
// the profile's PQ acceptance or absence, the draft acceptance (HNDL),
// and the classical preference the profile posture showed.
//
// A failed profile handshake does NOT skip the ladder: the ladder's raw
// probes work where a modern share-match cannot (a draft-preference-only
// endpoint never completes a modern negotiation — the HNDL fact is the
// ladder's whole point; spec §5.6 hndl_risk).
func scanTargetPQ(t grammar.Target, opts Options) (*scanRecord, bool, bool) {
	rec, res, failing, timedOut := scanTargetFast(t, opts)
	rec.Mode = modePQ

	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	ladder := tlsx.GroupLadder(addr, t.Host, pqLadderGroups, timeout)

	// Acceptances: the first standards-track hybrid the server accepted
	// WITH A REAL SHARE (the stdlib path) is the ladder's handshake
	// observation; a draft group's acceptance rides the raw share-less
	// path (HRR to a draft codepoint) and surfaces as HNDL.
	var accepted *tlsx.ProbeResult
	acceptsDraft := false
	for i := range ladder {
		r := ladder[i]
		if r.Path == "stdlib" && r.State == "negotiated" && accepted == nil {
			accepted = &ladder[i]
		}
		if r.Path == "raw" && r.State == tlsx.StateHRR && draftGroups[r.Offered] {
			acceptsDraft = true
		}
	}
	if accepted != nil {
		// The ladder's observation replaces the profile's facts in the
		// handshake block (a forced PQ hybrid is the pq-mode posture).
		rec.Handshake = handshakeRecord{
			Negotiated: accepted.Negotiated,
			GroupName:  groupName(accepted.Negotiated),
			Suite:      accepted.Suite,
			Version:    versionName(accepted.Version),
			ALPNNeg:    accepted.ALPN,
		}
		cls, ok := classify.GroupClass(rec.Handshake.Negotiated)
		if ok {
			rec.Handshake.GroupClass = string(cls)
		}
		diag.Emit(diag.Info, diag.DomEngine, "pq", t.Host, "PQ ladder accepted a forced group", nil,
			map[string]string{"negotiated": u32str(rec.Handshake.Negotiated), "suite": accepted.Suite})
	}

	// The ladder-observation verdict (spec §5.6/PQ-19b): the negotiated
	// class is the handshake block's (the ladder-accepted hybrid, else
	// the profile posture); PQ was offered either way (the ladder); the
	// draft acceptance is HNDL; a classical profile posture (the
	// browser-grade offer carried PQ and the server still picked
	// classical) is the weak-preference penalty. Cert facts stay the
	// profile handshake's analysis.
	token := rubricNegotiatedClass(classify.Class(rec.Handshake.GroupClass), rec.Handshake.GroupClass != "")
	in := classify.ScoreInput{
		NegotiatedClass:    token,
		OfferedPQ:          true,
		AcceptsDraft:       acceptsDraft,
		ClassicalPreferred: profileClassical(res),
		CertPQ:             rec.Cert != nil && rec.Cert.SigPQ,
		DualCert:           rec.Cert != nil && rec.Cert.Dual,
	}
	verdict, verr := classify.DefaultRubric().Score(in)
	rec.Pq = &out.PqRecord{Score: verdict.Score, Label: verdict.Label, HNDL: verdict.HNDL, Summary: verdict.Summary}
	fields := map[string]string{"score": strconv.Itoa(verdict.Score), "label": verdict.Label}
	if verr != nil {
		rec.Error = verr.Error()
		diag.Emit(diag.Warn, diag.DomEngine, "pq", t.Host, "readiness verdict is a scan-error", verr, fields)
	} else {
		fields["hndl"] = strconv.FormatBool(verdict.HNDL)
		diag.Emit(diag.Info, diag.DomEngine, "pq", t.Host, "readiness verdict", nil, fields)
	}
	return rec, failing, timedOut
}

// planModeFor normalizes the -deep selector for zero-value Options
// callers (an unset DeepPlan = the standard default plan).
func planModeFor(opts Options) string {
	if opts.DeepPlan == "" {
		return deepplan.ModeStandard
	}
	return opts.DeepPlan
}

// profileNegotiatedPQ reports whether the profile handshake negotiated a
// PQ-class (non-classical) group — the classical-preference test needs
// the profile's real negotiation, not the ladder's forced pick.
func profileNegotiatedPQ(res *tlsx.ProbeResult) bool {
	cls, ok := classify.GroupClass(res.Negotiated)
	if !ok {
		return false
	}
	switch cls {
	case classify.ClassPQ, classify.ClassPQHybrid, classify.ClassHybridSM, classify.ClassPQHybridD:
		return true
	default:
		return false
	}
}

// profileClassical reports whether the profile handshake negotiated a
// known-classical or obsolete group: the weak_classical_preferred fact
// (PQ rode the browser-grade offer; the server still picked classical).
// A failed or unknown negotiation prefers nothing.
func profileClassical(res *tlsx.ProbeResult) bool {
	if res == nil || res.Error != "" {
		return false
	}
	cls, ok := classify.GroupClass(res.Negotiated)
	if !ok {
		return false
	}
	return cls == classify.ClassClassic || cls == classify.ClassObsolete
}

// executeDeepPlan dispatches the plan's probes and lands the executed
// surface in the record's deep block (PQ-20): one finding per probe in
// plan order; attempted = the executed count, ok/rejected the clean
// counters (refusals and errors ride the findings only).
func executeDeepPlan(t grammar.Target, opts Options, plan *deepplan.Plan) *out.DeepRecord {
	dr := &out.DeepRecord{Mode: plan.Mode, Findings: make([]out.DeepFinding, 0, len(plan.Probes))}
	for _, p := range plan.Probes {
		f := deepFindingFor(p, t, opts)
		dr.Findings = append(dr.Findings, f)
		dr.Attempted++
		switch f.Result {
		case tlsx.SuiteAccepted:
			dr.OK++
		case tlsx.SuiteRejected:
			dr.Rejected++
		}
	}
	return dr
}

// deepFindingFor maps one planned probe onto its executed finding: the
// offer-one dispatch by kind. The tlsx plane provides the probe; a probe
// the plane cannot construct is recorded as the honest not-offerable
// refusal (never a fabricated verdict).
func deepFindingFor(p deepplan.Probe, t grammar.Target, opts Options) out.DeepFinding {
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	timeout := opts.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	switch p.Kind {
	case deepplan.KindVersion:
		return deepOfferFinding(p.Name, addr, t.Host, "", p.Payload.(uint16), timeout)
	case deepplan.KindSuite:
		so := p.Payload.(deepplan.SuiteOffer)
		if so.Version == tls.VersionTLS13 {
			// Offer-one is not client-restrictable at 1.3 (spec §7.4's
			// matrix note): the honest refusal — the negotiated 1.3
			// suite is already the profile handshake's recorded fact.
			return out.DeepFinding{Probe: p.Name, Result: tlsx.SuiteRefused,
				Detail: "not-offerable on tls-1.3: crypto/tls offers the fixed 1.3 suite set (offer-one is not client-restrictable)"}
		}
		return deepOfferFinding(p.Name, addr, t.Host, so.Name, so.Version, timeout)
	case deepplan.KindGroup:
		return deepGroupFinding(p.Name, addr, t.Host, p.Payload.(uint32), timeout)
	case deepplan.KindSigalg:
		return out.DeepFinding{Probe: p.Name, Result: tlsx.SuiteRefused,
			Detail: "not-offerable: the raw ClientHello path pins its signature_algorithms list (custom-list offers are a planned surface)"}
	case deepplan.KindCert:
		// The cert probe observes the profile handshake's own surface
		// (the chain is in hand — the profile handshake IS the cert
		// fetch; it ran in phase 1 or the plan short-circuited).
		return out.DeepFinding{Probe: p.Name, Result: tlsx.SuiteAccepted,
			Detail: "the profile handshake delivered the certificate chain (analyzed in the record's cert block)"}
	case deepplan.KindResumption:
		return out.DeepFinding{Probe: p.Name, Result: tlsx.SuiteRefused,
			Detail: "not-offerable: no resumption surface is instrumented in the tlsx plane (planned)"}
	case deepplan.KindHRR:
		return deepHRRFinding(p.Name, addr, t.Host, timeout)
	default:
		return out.DeepFinding{Probe: p.Name, Result: tlsx.SuiteError, Detail: "unknown probe kind " + p.Kind}
	}
}

// deepOfferFinding is the suite/version dispatch's shared tail: the
// offer-one helper drives the handshake, the observation lands as the
// finding (an accepted offer carries the negotiated pair; a server
// refusal carries its verbatim alert).
func deepOfferFinding(name, addr, host string, suiteName string, version uint16, timeout time.Duration) out.DeepFinding {
	obs, err := tlsx.SuiteOfferProbe(addr, host, suiteName, version, timeout)
	if err != nil {
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteError, Detail: err.Error()}
	}
	if obs.State == tlsx.SuiteAccepted {
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteAccepted,
			Detail: "negotiated " + obs.NegotiatedSuite + ", " + deepVersionToken(obs.NegotiatedVersion)}
	}
	return out.DeepFinding{Probe: name, Result: obs.State, Detail: obs.Error}
}

// deepGroupFinding is the group dispatch: the ladder step's observation
// (a real share where the stack can construct one, the share-less HRR
// oracle elsewhere) as a finding.
func deepGroupFinding(name, addr, host string, group uint32, timeout time.Duration) out.DeepFinding {
	rows := tlsx.GroupLadder(addr, host, []uint32{group}, timeout)
	if len(rows) == 0 {
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteError, Detail: "the ladder returned no observation"}
	}
	r := rows[0]
	switch {
	case r.Path == "stdlib" && r.State == "negotiated":
		gname := groupName(group)
		if gname == "" {
			gname = strconv.FormatUint(uint64(group), 10)
		}
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteAccepted,
			Detail: "negotiated " + gname + ", suite " + r.Suite + ", " + deepVersionToken(r.Version)}
	case r.Path == "stdlib" && r.State == "error":
		text := r.Error
		if strings.HasPrefix(text, "remote error: tls: ") {
			return out.DeepFinding{Probe: name, Result: tlsx.SuiteRejected, Detail: text}
		}
		if isLocalStackOfferFailure(text) {
			// The client stack cannot construct this share (e.g. the
			// brainpool/CCM groups): the probe never left the scanner —
			// the honest not-offerable refusal, not a server verdict.
			return out.DeepFinding{Probe: name, Result: tlsx.SuiteRefused,
				Detail: "not-offerable locally: " + text}
		}
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteError, Detail: text}
	case r.Path == "raw":
		switch r.State {
		case tlsx.StateHRR:
			return out.DeepFinding{Probe: name, Result: tlsx.SuiteAccepted,
				Detail: "hrr: the server requested group " + groupDetailToken(r.RequestedGroup)}
		case tlsx.StateAlert:
			return out.DeepFinding{Probe: name, Result: tlsx.SuiteRejected,
				Detail: "alert " + strconv.Itoa(int(r.AlertDesc))}
		case tlsx.StateSH:
			return out.DeepFinding{Probe: name, Result: tlsx.SuiteAccepted,
				Detail: "sh: the share-less offer was answered without hrr"}
		default: // read-error: the server closed without a TLS answer
			return out.DeepFinding{Probe: name, Result: tlsx.SuiteError,
				Detail: "read-error: the server closed without a TLS answer"}
		}
	default:
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteError, Detail: r.Error}
	}
}

// deepHRRFinding is the HRR dispatch: the share-less x25519 offer read
// through the raw first-flight surface (the ServerHello-side fact: an
// HRR's demanded group, a bare SH, or the server's refusal).
func deepHRRFinding(name, addr, host string, timeout time.Duration) out.DeepFinding {
	obs, err := tlsx.SendHelloProbe(addr, host, []uint32{29}, 0)
	if err != nil {
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Op == "dial" {
			return out.DeepFinding{Probe: name, Result: tlsx.SuiteRefused, Detail: err.Error()}
		}
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteError, Detail: err.Error()}
	}
	switch obs.State {
	case tlsx.StateHRR:
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteAccepted,
			Detail: "hrr: the server requested group " + groupDetailToken(obs.RequestedGroup)}
	case tlsx.StateAlert:
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteRejected,
			Detail: "alert " + strconv.Itoa(int(obs.AlertDesc))}
	case tlsx.StateSH:
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteAccepted,
			Detail: "sh: the share-less x25519 offer was answered without hrr"}
	default:
		return out.DeepFinding{Probe: name, Result: tlsx.SuiteError,
			Detail: "read-error: the server closed without a TLS answer"}
	}
}

// isLocalStackOfferFailure reports the client-side construction
// refusals of the stdlib share path (the "no supported …" class the
// stack emits before any dial is possible; the toolchains word it
// differently — the CurveIDs enumeration and the ECDHE curve pool —
// and both are the same fact: the share cannot be constructed).
func isLocalStackOfferFailure(text string) bool {
	if i := strings.Index(text, "no supported"); i >= 0 {
		tail := text[i:]
		return strings.Contains(tail, "key exchange methods") ||
			strings.Contains(tail, "elliptic curves") ||
			strings.Contains(tail, "cipher suites") ||
			strings.Contains(tail, "ciphers")
	}
	return strings.Contains(text, "no common cipher suite")
}

// groupDetailToken renders a requested group in the findings' detail:
// the named form when the ladder's table knows it ("x25519 (29)"), the
// bare codepoint otherwise.
func groupDetailToken(group uint32) string {
	if name := groupName(group); name != "" {
		return name + " (" + strconv.FormatUint(uint64(group), 10) + ")"
	}
	return strconv.FormatUint(uint64(group), 10)
}

// deepVersionToken names a negotiated version code in the findings'
// detail (the record's token shape, the version floor included).
func deepVersionToken(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "tls-1.0"
	case tls.VersionTLS11:
		return "tls-1.1"
	case tls.VersionTLS12:
		return "tls-1.2"
	case tls.VersionTLS13:
		return "tls-1.3"
	default:
		return "0x" + strconv.FormatUint(uint64(v), 16)
	}
}
