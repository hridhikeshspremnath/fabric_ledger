package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const (
	scorerID = "spiffe://attesta.example.org/scoring-service"
	runOne   = "run-0001"
)

type env struct {
	t    *testing.T
	mem  *memState
	svc  *Service
	priv ed25519.PrivateKey
	base []byte // vector record JSON
	pub  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	c := loadCanon(t).Signing
	seed, _ := hex.DecodeString(c.SeedHex)
	e := &env{t: t, mem: newMemState(), priv: ed25519.NewKeyFromSeed(seed), base: c.Record, pub: c.PublicKeyB64}
	e.svc = NewService(e.mem, Config{AttestaMSP: "AttestaMSP", AuditorMSP: "AuditorMSP"})

	var recs recordsFile
	loadFile(t, "records.json", &recs)
	pol := Policy{PolicyVersion: "p1", AllowedScorerID: scorerID, Bands: recs.Policy.Bands}
	e.must(e.svc.SetPolicy(toJSON(t, pol)))
	e.must(e.svc.RegisterScorerKey(toJSON(t, ScorerKey{
		KeyID: "k1", PublicKey: c.PublicKeyB64, NotBefore: 1_600_000_000, NotAfter: 1_800_000_000})))
	return e
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (e *env) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

// record returns a re-signed copy of the vector record with overrides applied.
func (e *env) record(over map[string]any) string {
	e.t.Helper()
	m := parseMap(e.t, e.base)
	for k, v := range over {
		m[k] = v
	}
	payload, err := SigningPayload(m)
	e.must(err)
	m["scorer_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(e.priv, payload))
	out, err := EncodeCanonical(m)
	e.must(err)
	return string(out)
}

func (e *env) submit(over map[string]any) (string, error) {
	return e.svc.RecordDecision(e.record(over))
}

func (e *env) expectErr(over map[string]any, contains string) {
	e.t.Helper()
	_, err := e.submit(over)
	if err == nil || !strings.Contains(err.Error(), contains) {
		e.t.Fatalf("want error containing %q, got %v", contains, err)
	}
}

const recID2 = "22222222-2222-4222-8222-222222222222"

func TestRecordDecisionStoresCanonicalRecord(t *testing.T) {
	e := newEnv(t)
	if _, err := e.submit(nil); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.GetRecord("11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Record json.RawMessage `json:"record"`
		Meta   Meta            `json:"meta"`
	}
	if err := json.Unmarshal([]byte(got), &view); err != nil {
		t.Fatal(err)
	}
	if string(view.Record) != e.record(nil) {
		t.Fatalf("stored record is not the canonical bytes")
	}
	if view.Meta.EffectiveDecision != "ALLOW" || view.Meta.TxTime != 1_700_000_000 {
		t.Fatalf("unexpected meta: %+v", view.Meta)
	}
	if len(e.mem.events) != 1 || e.mem.events[0] != "RecordDecision" {
		t.Fatalf("expected a RecordDecision event")
	}
}

func TestRejections(t *testing.T) {
	e := newEnv(t)
	if _, err := e.submit(nil); err != nil {
		t.Fatal(err)
	}
	e.expectErr(map[string]any{"record_id": recID2}, "duplicate run_id")
	e.expectErr(map[string]any{"run_id": "run-0002"}, "duplicate record_id")
	e.expectErr(map[string]any{"record_id": recID2, "run_id": "run-0002", "decision": json.Number("1")}, "invalid record")
	// A weaker decision than the band's is refused (score 950 is CRITICAL => BLOCK).
	e.expectErr(map[string]any{"record_id": recID2, "run_id": "run-0002", "risk_score": json.Number("950"),
		"risk_band": "CRITICAL", "decision": "ALLOW"}, "do not match policy")
	e.expectErr(map[string]any{"record_id": recID2, "run_id": "run-0002", "risk_band": "HIGH"}, "do not match policy")
	e.expectErr(map[string]any{"record_id": recID2, "run_id": "run-0002", "policy_version": "p0"}, "active policy")
	e.expectErr(map[string]any{"record_id": recID2, "run_id": "run-0002", "scorer_key_id": "nope"}, "unknown scorer key")
	e.expectErr(map[string]any{"record_id": recID2, "run_id": "run-0002",
		"submitted_by_spiffe_id": "spiffe://attesta.example.org/ci/build-runner"}, "allowed scorer")
}

// Evidence rules may raise a decision above its band, never lower it.
func TestStricterThanBandIsAccepted(t *testing.T) {
	e := newEnv(t)
	if _, err := e.submit(map[string]any{"decision": "BLOCK"}); err != nil { // LOW band, BLOCK by evidence
		t.Fatal(err)
	}
}

func TestBadSignatureRejected(t *testing.T) {
	e := newEnv(t)
	tampered := strings.Replace(e.record(map[string]any{"record_id": recID2, "run_id": "run-0002"}),
		"example-package", "evil-package", 1)
	if _, err := e.svc.RecordDecision(tampered); err == nil || !strings.Contains(err.Error(), "invalid scorer signature") {
		t.Fatalf("want signature error, got %v", err)
	}
}

func TestUnverifiedAttestationMustBeReview(t *testing.T) {
	e := newEnv(t)
	unverified := map[string]any{"attestation_verified": false, "attestation_digest": nil,
		"record_id": recID2, "run_id": "run-0002"}
	e.expectErr(unverified, "do not match policy") // decision ALLOW is not acceptable
	unverified["decision"] = "REVIEW"
	if _, err := e.submit(unverified); err != nil {
		t.Fatal(err)
	}
}

func TestKeyValidityUsesTxTime(t *testing.T) {
	e := newEnv(t)
	e.mem.txTime = 1_900_000_000 // after not_after
	e.expectErr(nil, "outside validity window")
	e.mem.txTime = 1_500_000_000 // before not_before
	e.expectErr(nil, "outside validity window")
	e.mem.txTime = 1_700_000_000
	e.must(e.svc.RevokeScorerKey("k1"))
	e.expectErr(nil, "revoked")
}

func TestCallerAuthorization(t *testing.T) {
	e := newEnv(t)
	e.mem.caller = Caller{MSPID: "AuditorMSP", Admin: true}
	e.expectErr(nil, "not permitted")
	if err := e.svc.SetPolicy("{}"); err == nil {
		t.Fatal("auditor must not set policy")
	}
	e.mem.caller = Caller{MSPID: "AttestaMSP", Admin: false}
	if err := e.svc.RevokeScorerKey("k1"); err == nil || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("non-admin revoke should fail, got %v", err)
	}
	if _, err := e.svc.RecordOverride("11111111-1111-4111-8111-111111111111", "BLOCK", "x"); err == nil {
		t.Fatal("attesta must not override")
	}
}

func TestSetPolicyAndKeyAreImmutable(t *testing.T) {
	e := newEnv(t)
	p, err := e.svc.GetPolicy("")
	e.must(err)
	if err := e.svc.SetPolicy(p); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate policy version must fail, got %v", err)
	}
	dup := toJSON(t, ScorerKey{KeyID: "k1", PublicKey: e.pub, NotBefore: 1, NotAfter: 2})
	if err := e.svc.RegisterScorerKey(dup); err == nil {
		t.Fatal("duplicate key id must fail")
	}
}

func TestOverrideUpdatesIndexesAndHistory(t *testing.T) {
	e := newEnv(t)
	id := "11111111-1111-4111-8111-111111111111"
	if _, err := e.submit(nil); err != nil {
		t.Fatal(err)
	}
	e.mem.caller = Caller{MSPID: "AuditorMSP"}
	if _, err := e.svc.RecordOverride(id, "BLOCK", ""); err == nil {
		t.Fatal("reason is required")
	}
	e.mem.txID, e.mem.txTime = "tx-0002", 1_700_000_100
	if _, err := e.svc.RecordOverride(id, "BLOCK", "malicious post-install script found"); err != nil {
		t.Fatal(err)
	}
	allow, _ := e.svc.ListByStatus("ALLOW", 10, "")
	block, _ := e.svc.ListByStatus("BLOCK", 10, "")
	if strings.Contains(allow, id) || !strings.Contains(block, id) {
		t.Fatalf("status index not updated: allow=%s block=%s", allow, block)
	}
	hist, err := e.svc.GetHistory(id)
	e.must(err)
	var view recordView
	e.must(json.Unmarshal([]byte(hist), &view))
	if len(view.Overrides) != 1 || view.Overrides[0].PreviousDecision != "ALLOW" || view.Meta.EffectiveDecision != "BLOCK" {
		t.Fatalf("unexpected history: %s", hist)
	}
	v, err := e.svc.VerifyArtifact(str(parseMap(t, e.base), "artifact_digest"))
	e.must(err)
	if !strings.Contains(v, `"latest_effective_decision":"BLOCK"`) {
		t.Fatalf("VerifyArtifact: %s", v)
	}
}

func TestListByPackageAndPagination(t *testing.T) {
	e := newEnv(t)
	ids := []string{"11111111-1111-4111-8111-111111111111", recID2, "33333333-3333-4333-8333-333333333333"}
	for i, id := range ids {
		over := map[string]any{"record_id": id, "run_id": "run-" + string(rune('a'+i))}
		if _, err := e.submit(over); err != nil {
			t.Fatal(err)
		}
	}
	page, err := e.svc.ListByPackage("pypi", "example-package", "1.0.0", 2, "")
	e.must(err)
	var p1 listPage
	e.must(json.Unmarshal([]byte(page), &p1))
	if len(p1.Items) != 2 || p1.Bookmark == "" {
		t.Fatalf("first page: %s", page)
	}
	page, err = e.svc.ListByPackage("pypi", "example-package", "", 2, p1.Bookmark)
	e.must(err)
	var p2 listPage
	e.must(json.Unmarshal([]byte(page), &p2))
	if len(p2.Items) != 1 {
		t.Fatalf("second page: %s", page)
	}
}

func TestListRecentIsOrderedAndPaged(t *testing.T) {
	e := newEnv(t)
	ids := []string{"11111111-1111-4111-8111-111111111111", recID2, "33333333-3333-4333-8333-333333333333"}
	for i, id := range ids {
		e.mem.txID, e.mem.txTime = "tx-"+string(rune('a'+i)), 1_700_000_000+int64(i)
		if _, err := e.submit(map[string]any{"record_id": id, "run_id": "run-" + string(rune('a'+i))}); err != nil {
			t.Fatal(err)
		}
	}
	type page struct {
		Items []struct {
			Record json.RawMessage `json:"record"`
			Meta   Meta            `json:"meta"`
		} `json:"items"`
		Bookmark string `json:"bookmark"`
	}
	var p1, p2 page
	raw, err := e.svc.ListRecent(2, "")
	e.must(err)
	e.must(json.Unmarshal([]byte(raw), &p1))
	if len(p1.Items) != 2 || p1.Bookmark == "" || p1.Items[0].Meta.TxID != "tx-a" || p1.Items[1].Meta.TxID != "tx-b" {
		t.Fatalf("first page: %s", raw)
	}
	raw, err = e.svc.ListRecent(2, p1.Bookmark)
	e.must(err)
	e.must(json.Unmarshal([]byte(raw), &p2))
	if len(p2.Items) != 1 || p2.Items[0].Meta.TxID != "tx-c" || p2.Bookmark != "" {
		t.Fatalf("second page: %s", raw)
	}
}

func TestCheckpointAnchorAdminOnly(t *testing.T) {
	e := newEnv(t)
	root := strings.Repeat("ab", 32)
	if _, err := e.svc.AnchorCheckpoint("cp-1", root, 5, "sqlite-gateway"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AnchorCheckpoint("cp-1", root, 5, "sqlite-gateway"); err == nil {
		t.Fatal("duplicate checkpoint id must fail")
	}
	got, err := e.svc.GetCheckpoint("cp-1")
	e.must(err)
	if !strings.Contains(got, root) {
		t.Fatalf("checkpoint not stored: %s", got)
	}
	e.mem.caller = Caller{MSPID: "AttestaMSP", Admin: false}
	if _, err := e.svc.AnchorCheckpoint("cp-2", root, 5, "x"); err == nil {
		t.Fatal("non-admin anchor must fail")
	}
}
