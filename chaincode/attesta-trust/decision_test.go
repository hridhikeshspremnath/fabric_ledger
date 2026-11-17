package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

type decisionVector struct {
	Decision struct {
		SeedHex      string          `json:"seed_hex"`
		PublicKeyB64 string          `json:"public_key_b64"`
		Fields       json.RawMessage `json:"fields"`
		Payload      string          `json:"payload"`
		SignatureB64 string          `json:"signature_b64"`
		TamperCases  []struct {
			Name string
			Set  json.RawMessage
		} `json:"tamper_cases"`
	} `json:"decision"`
}

func loadDecision(t *testing.T) *decisionVector {
	var v decisionVector
	loadFile(t, "canonical.json", &v)
	return &v
}

// The Python policy service and the chaincode must agree on the bytes that get signed.
func TestDecisionVector(t *testing.T) {
	d := loadDecision(t).Decision
	m := parseMap(t, d.Fields)
	payload, err := DecisionPayload(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != d.Payload {
		t.Fatalf("decision payload differs from Python:\n got %s\nwant %s", payload, d.Payload)
	}
	seed, _ := hex.DecodeString(d.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) != d.PublicKeyB64 {
		t.Fatal("decision public key mismatch")
	}
	if got := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)); got != d.SignatureB64 {
		t.Fatal("Go decision signature differs from Python")
	}
	m["decision_signature"] = d.SignatureB64
	if err := VerifyDecisionSignature(m, d.PublicKeyB64); err != nil {
		t.Fatalf("valid decision signature rejected: %v", err)
	}
}

func TestTamperedDecisionsFailSignature(t *testing.T) {
	d := loadDecision(t).Decision
	for _, tc := range d.TamperCases {
		t.Run(tc.Name, func(t *testing.T) {
			m := parseMap(t, d.Fields)
			for k, v := range parseMap(t, tc.Set) {
				m[k] = v
			}
			m["decision_signature"] = d.SignatureB64
			if err := VerifyDecisionSignature(m, d.PublicKeyB64); err == nil {
				t.Fatal("tampered decision verified")
			}
		})
	}
}

const bundle = "sha256:abababababababababababababababababababababababababababababababab"

// pinned returns an env whose active policy p2 pins `bundle` and has a registered policy key.
func pinned(t *testing.T) (*env, ed25519.PrivateKey) {
	e := newEnv(t)
	seed, _ := hex.DecodeString(loadDecision(t).Decision.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	var recs recordsFile
	loadFile(t, "records.json", &recs)
	e.must(e.svc.SetPolicy(toJSON(t, Policy{PolicyVersion: "p2", AllowedScorerID: scorerID,
		Bands: recs.Policy.Bands, BundleHash: bundle})))
	e.must(e.svc.RegisterDecisionKey(toJSON(t, ScorerKey{KeyID: "d1",
		PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		NotBefore: 1_600_000_000, NotAfter: 1_800_000_000})))
	return e, priv
}

// signedSubmit builds a record under p2, signs its decision with `key` (unless nil), applies
// `after` to the record, and submits it with a fresh scorer signature.
func (e *env) signedSubmit(key ed25519.PrivateKey, over map[string]any, after func(map[string]any)) error {
	m := parseMap(e.t, e.base)
	m["policy_version"], m["policy_bundle_hash"], m["decision_key_id"] = "p2", bundle, "d1"
	for k, v := range over {
		m[k] = v
	}
	if key != nil {
		payload, err := DecisionPayload(m)
		e.must(err)
		m["decision_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	}
	if after != nil {
		after(m)
	}
	sp, err := SigningPayload(m)
	e.must(err)
	m["scorer_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(e.priv, sp))
	out, err := EncodeCanonical(m)
	e.must(err)
	_, err = e.svc.RecordDecision(string(out))
	return err
}

func (e *env) expectSignedErr(key ed25519.PrivateKey, over map[string]any, after func(map[string]any), contains string) {
	e.t.Helper()
	err := e.signedSubmit(key, over, after)
	if err == nil || !strings.Contains(err.Error(), contains) {
		e.t.Fatalf("want error containing %q, got %v", contains, err)
	}
}

func TestPinnedPolicyAcceptsASignedDecision(t *testing.T) {
	e, key := pinned(t)
	if err := e.signedSubmit(key, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedPolicyRefusesEverythingElse(t *testing.T) {
	e, key := pinned(t)
	e.expectSignedErr(nil, nil, func(m map[string]any) { m["decision_signature"] = nil }, "signed policy decision is required")
	e.expectSignedErr(key, map[string]any{"policy_bundle_hash": "sha256:" + strings.Repeat("cd", 32)},
		nil, "not the approved bundle")
	e.expectSignedErr(key, map[string]any{"decision_key_id": "nope"}, nil, "unknown policy key")
	// A decision the scorer changed after the policy service signed it, even to a stricter one.
	e.expectSignedErr(key, nil, func(m map[string]any) { m["decision"] = "BLOCK" }, "invalid decision signature")
	// The scorer key cannot stand in for the policy key.
	e.expectSignedErr(e.priv, nil, nil, "invalid decision signature")
	// A signature made for another artifact does not transfer.
	other, err := DecisionPayload(func() map[string]any {
		m := parseMap(t, e.base)
		m["policy_version"], m["policy_bundle_hash"] = "p2", bundle
		m["artifact_digest"] = "sha256:" + strings.Repeat("ef", 32)
		return m
	}())
	e.must(err)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, other))
	e.expectSignedErr(nil, nil, func(m map[string]any) { m["decision_signature"] = sig }, "invalid decision signature")
}

func TestExpiredPolicyKeyIsRefused(t *testing.T) {
	e := newEnv(t)
	seed, _ := hex.DecodeString(loadDecision(t).Decision.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	var recs recordsFile
	loadFile(t, "records.json", &recs)
	e.must(e.svc.SetPolicy(toJSON(t, Policy{PolicyVersion: "p2", AllowedScorerID: scorerID,
		Bands: recs.Policy.Bands, BundleHash: bundle})))
	e.must(e.svc.RegisterDecisionKey(toJSON(t, ScorerKey{KeyID: "d1", // valid window ends before tx time 1_700_000_000
		PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		NotBefore: 1_600_000_000, NotAfter: 1_650_000_000})))
	e.expectSignedErr(priv, nil, nil, "policy key")
}
