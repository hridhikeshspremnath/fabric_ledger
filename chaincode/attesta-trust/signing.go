package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// ScorerKey is an entry in the on-chain scorer key registry (times: unix seconds).
type ScorerKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64 raw 32-byte Ed25519 key
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	Revoked   bool   `json:"revoked"`
}

// Validate checks a key before registration.
func (k ScorerKey) Validate() error {
	if !reID.MatchString(k.KeyID) {
		return errors.New("invalid key_id")
	}
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("public_key must be base64 of a 32-byte Ed25519 key")
	}
	if k.NotBefore <= 0 || k.NotAfter <= k.NotBefore {
		return errors.New("invalid validity window")
	}
	return nil
}

// ActiveAt rejects revoked keys and keys outside their window at the given
// time. The time must be the Fabric transaction timestamp.
func (k ScorerKey) ActiveAt(txTime int64) error {
	if k.Revoked {
		return fmt.Errorf("scorer key revoked: %s", k.KeyID)
	}
	if txTime < k.NotBefore || txTime > k.NotAfter {
		return fmt.Errorf("scorer key outside validity window: %s (tx time %s)",
			k.KeyID, time.Unix(txTime, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// SigningPayload is the canonical JSON of the record without scorer_signature.
func SigningPayload(m map[string]any) ([]byte, error) {
	c := make(map[string]any, len(m))
	for k, v := range m {
		if k != "scorer_signature" {
			c[k] = v
		}
	}
	return EncodeCanonical(c)
}

// VerifyScorerSignature checks the record's Ed25519 signature against pubB64.
func VerifyScorerSignature(m map[string]any, pubB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("registered public key is malformed")
	}
	sig, err := base64.StdEncoding.DecodeString(str(m, "scorer_signature"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid scorer signature")
	}
	payload, err := SigningPayload(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("invalid scorer signature")
	}
	return nil
}

// decisionFields mirrors attesta.policy.decision.DECISION_FIELDS: what a policy decision signs.
var decisionFields = []string{
	"record_id", "artifact_digest", "policy_version", "policy_bundle_hash", "risk_score", "risk_band",
	"attestation_verified", "flag_install_exec", "flag_network", "flag_obfuscation", "flag_cred_access",
	"flag_process_spawn", "llm_verdict", "decision",
}

// DecisionPayload is the canonical JSON of the decision fields taken from the record.
func DecisionPayload(m map[string]any) ([]byte, error) {
	c := make(map[string]any, len(decisionFields))
	for _, k := range decisionFields {
		v, ok := m[k]
		if !ok {
			return nil, fmt.Errorf("record has no %s", k)
		}
		c[k] = v
	}
	return EncodeCanonical(c)
}

// VerifyDecisionSignature checks the record's decision_signature against the policy key pubB64.
func VerifyDecisionSignature(m map[string]any, pubB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("registered policy key is malformed")
	}
	sig, err := base64.StdEncoding.DecodeString(str(m, "decision_signature"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid decision signature")
	}
	payload, err := DecisionPayload(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("invalid decision signature")
	}
	return nil
}
