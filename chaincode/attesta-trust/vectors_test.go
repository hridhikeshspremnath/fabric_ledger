package main

// Runs the Python/Go shared vectors in ../../testvectors.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type canonFile struct {
	CanonicalCases []struct {
		Name, Input, Canonical, Sha256 string
	} `json:"canonical_cases"`
	CanonicalRejects []struct {
		Name, Input string
	} `json:"canonical_rejects"`
	Signing struct {
		SeedHex               string          `json:"seed_hex"`
		PublicKeyB64          string          `json:"public_key_b64"`
		KeyID                 string          `json:"key_id"`
		Record                json.RawMessage `json:"record"`
		SigningPayload        string          `json:"signing_payload"`
		CanonicalRecord       string          `json:"canonical_record"`
		CanonicalRecordSha256 string          `json:"canonical_record_sha256"`
		TamperCases           []struct {
			Name string
			Set  json.RawMessage
		} `json:"tamper_cases"`
	} `json:"signing"`
}

type recordsFile struct {
	Mutations []struct {
		Name   string
		Set    json.RawMessage
		Delete []string
		Valid  bool
	} `json:"mutations"`
	Policy struct {
		PolicyVersion string `json:"policy_version"`
		Bands         []Band `json:"bands"`
		Cases         []struct {
			Score    int64
			Verified bool
			Band     string
			Decision string
		} `json:"cases"`
	} `json:"policy"`
}

func loadFile(t *testing.T, name string, out any) {
	t.Helper()
	raw, err := os.ReadFile("../../testvectors/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func loadCanon(t *testing.T) *canonFile {
	var c canonFile
	loadFile(t, "canonical.json", &c)
	return &c
}

func parseMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	v, err := ParseJSON(raw)
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object")
	}
	return m
}

func TestCanonicalCases(t *testing.T) {
	for _, c := range loadCanon(t).CanonicalCases {
		t.Run(c.Name, func(t *testing.T) {
			out, err := Canonicalize([]byte(c.Input))
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != c.Canonical {
				t.Fatalf("canonical mismatch:\n got %s\nwant %s", out, c.Canonical)
			}
			sum := sha256.Sum256(out)
			if hex.EncodeToString(sum[:]) != c.Sha256 {
				t.Fatalf("sha256 mismatch")
			}
		})
	}
}

func TestCanonicalRejectsFloats(t *testing.T) {
	for _, c := range loadCanon(t).CanonicalRejects {
		t.Run(c.Name, func(t *testing.T) {
			if _, err := Canonicalize([]byte(c.Input)); err == nil {
				t.Fatalf("expected rejection of %s", c.Input)
			}
		})
	}
}

func TestSigningVector(t *testing.T) {
	c := loadCanon(t).Signing
	m := parseMap(t, c.Record)
	payload, err := SigningPayload(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != c.SigningPayload {
		t.Fatalf("signing payload mismatch")
	}
	full, err := EncodeCanonical(m)
	if err != nil || string(full) != c.CanonicalRecord {
		t.Fatalf("canonical record mismatch (err=%v)", err)
	}
	sum := sha256.Sum256(full)
	if hex.EncodeToString(sum[:]) != c.CanonicalRecordSha256 {
		t.Fatalf("canonical record sha256 mismatch")
	}
	seed, _ := hex.DecodeString(c.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if pub != c.PublicKeyB64 {
		t.Fatalf("public key mismatch")
	}
	if got := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)); got != str(m, "scorer_signature") {
		t.Fatalf("Go signature differs from Python signature")
	}
	if err := VerifyScorerSignature(m, c.PublicKeyB64); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestTamperedRecordsFailSignature(t *testing.T) {
	c := loadCanon(t).Signing
	for _, tc := range c.TamperCases {
		t.Run(tc.Name, func(t *testing.T) {
			m := parseMap(t, c.Record)
			for k, v := range parseMap(t, tc.Set) {
				m[k] = v
			}
			if err := VerifyScorerSignature(m, c.PublicKeyB64); err == nil {
				t.Fatalf("tampered record verified")
			}
		})
	}
}

func TestSchemaMutations(t *testing.T) {
	canon := loadCanon(t)
	var recs recordsFile
	loadFile(t, "records.json", &recs)
	for _, mu := range recs.Mutations {
		t.Run(mu.Name, func(t *testing.T) {
			m := parseMap(t, canon.Signing.Record)
			if len(mu.Set) > 0 {
				for k, v := range parseMap(t, mu.Set) {
					m[k] = v
				}
			}
			for _, k := range mu.Delete {
				delete(m, k)
			}
			err := ValidateRecord(m)
			if mu.Valid && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !mu.Valid && err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestPolicyCases(t *testing.T) {
	var recs recordsFile
	loadFile(t, "records.json", &recs)
	p := Policy{
		PolicyVersion:   recs.Policy.PolicyVersion,
		AllowedScorerID: "spiffe://attesta.example.org/scoring-service",
		Bands:           recs.Policy.Bands,
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range recs.Policy.Cases {
		band, decision, err := p.Evaluate(c.Score, c.Verified)
		if err != nil || band != c.Band || decision != c.Decision {
			t.Fatalf("score %d verified=%v: got %s/%s (%v), want %s/%s",
				c.Score, c.Verified, band, decision, err, c.Band, c.Decision)
		}
	}
}
