package main

// TrustRecord v1 schema validation, mirroring attesta.records.trust_record.
// Rules are shared with Python through testvectors/records.json.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	reSHA256      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reName        = regexp.MustCompile(`^[A-Za-z0-9._@/+:-]{1,214}$`)
	reID          = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	reSpiffe      = regexp.MustCompile(`^spiffe://[a-z0-9.-]+/[A-Za-z0-9._/-]+$`)
	reUUID        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reSignature   = regexp.MustCompile(`^[A-Za-z0-9+/]{86}==$`)
	reEcosystem   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	reFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reHex64       = reFingerprint
)

var (
	enumBand     = []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	enumVerdict  = []string{"BENIGN", "SUSPICIOUS", "MALICIOUS", "NOT_RUN"}
	enumDecision = []string{"ALLOW", "WARN", "REVIEW", "BLOCK"}
)

type kind int

const (
	kString kind = iota
	kBool
	kInt
)

type fieldSpec struct {
	name     string
	kind     kind
	re       *regexp.Regexp
	enum     []string
	nullable bool
	optional bool // may be absent; default is filled in
	def      any
}

var recordSpec = []fieldSpec{
	{name: "schema_version", kind: kInt, optional: true, def: json.Number("1")},
	{name: "record_id", kind: kString, re: reUUID},
	{name: "run_id", kind: kString, re: reID},
	{name: "submitted_by_spiffe_id", kind: kString, re: reSpiffe},
	{name: "caller_cert_sha256", kind: kString, re: reFingerprint},
	{name: "ecosystem", kind: kString, re: reEcosystem},
	{name: "package", kind: kString, re: reName},
	{name: "version", kind: kString, re: reName},
	{name: "artifact_digest", kind: kString, re: reSHA256},
	{name: "risk_score", kind: kInt},
	{name: "risk_band", kind: kString, enum: enumBand},
	{name: "flag_install_exec", kind: kBool},
	{name: "flag_network", kind: kBool},
	{name: "flag_obfuscation", kind: kBool},
	{name: "flag_cred_access", kind: kBool},
	{name: "flag_process_spawn", kind: kBool},
	{name: "llm_verdict", kind: kString, enum: enumVerdict},
	{name: "llm_evidence_hash", kind: kString, re: reSHA256, nullable: true, optional: true, def: nil},
	{name: "model_version_hash", kind: kString, re: reSHA256},
	{name: "policy_version", kind: kString, re: reID},
	{name: "runner_class", kind: kString, re: reID},
	{name: "node_attestor", kind: kString, re: reID},
	{name: "attestation_verified", kind: kBool},
	{name: "attestation_digest", kind: kString, re: reSHA256, nullable: true, optional: true, def: nil},
	{name: "decision", kind: kString, enum: enumDecision},
	{name: "policy_bundle_hash", kind: kString, re: reSHA256, nullable: true, optional: true, def: nil},
	{name: "decision_key_id", kind: kString, re: reID, nullable: true, optional: true, def: nil},
	{name: "decision_signature", kind: kString, re: reSignature, nullable: true, optional: true, def: nil},
	{name: "evidence_hash", kind: kString, re: reSHA256},
	{name: "scorer_key_id", kind: kString, re: reID},
	{name: "scorer_signature", kind: kString, re: reSignature},
}

// ParseInt parses a json.Number integer literal; floats are rejected.
func parseInt(v any) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("expected an integer")
	}
	lit := n.String()
	if strings.ContainsAny(lit, ".eE") {
		return 0, errors.New("floats are not allowed")
	}
	return strconv.ParseInt(lit, 10, 64)
}

func inEnum(value string, enum []string) bool {
	for _, e := range enum {
		if e == value {
			return true
		}
	}
	return false
}

func checkField(spec fieldSpec, v any) error {
	if v == nil {
		if spec.nullable {
			return nil
		}
		return errors.New("must not be null")
	}
	switch spec.kind {
	case kBool:
		if _, ok := v.(bool); !ok {
			return errors.New("must be a boolean")
		}
	case kInt:
		n, err := parseInt(v)
		if err != nil {
			return err
		}
		switch spec.name {
		case "schema_version":
			if n != 1 {
				return errors.New("must be 1")
			}
		case "risk_score":
			if n < 0 || n > 1000 {
				return errors.New("must be in 0..1000")
			}
		}
	case kString:
		s, ok := v.(string)
		if !ok {
			return errors.New("must be a string")
		}
		if spec.re != nil && !spec.re.MatchString(s) {
			return errors.New("has an invalid format")
		}
		if spec.enum != nil && !inEnum(s, spec.enum) {
			return errors.New("is not an allowed value")
		}
	}
	return nil
}

// ValidateRecord checks m against TrustRecord v1 and fills defaults for
// optional fields, so the canonical bytes match Python's to_dict().
func ValidateRecord(m map[string]any) error {
	known := make(map[string]bool, len(recordSpec))
	for _, spec := range recordSpec {
		known[spec.name] = true
	}
	for k := range m {
		if !known[k] {
			return fmt.Errorf("unexpected field: %s", k)
		}
	}
	for _, spec := range recordSpec {
		v, present := m[spec.name]
		if !present {
			if !spec.optional {
				return fmt.Errorf("missing field: %s", spec.name)
			}
			m[spec.name] = spec.def
			continue
		}
		if err := checkField(spec, v); err != nil {
			return fmt.Errorf("%s: %w", spec.name, err)
		}
	}
	if m["attestation_verified"] == true && m["attestation_digest"] == nil {
		return errors.New("attestation_digest is required when attestation_verified is true")
	}
	return nil
}

// Record holds the fields the contract logic needs (m has the full record).
type Record struct {
	M                   map[string]any
	RecordID, RunID     string
	SubmittedBy         string
	Ecosystem, Package  string
	Version, Digest     string
	RiskScore           int64
	RiskBand, Decision  string
	PolicyVersion       string
	AttestationVerified bool
	ScorerKeyID         string
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// ParseRecord validates raw JSON and returns the record plus its canonical bytes.
func ParseRecord(raw []byte) (*Record, []byte, error) {
	v, err := ParseJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, errors.New("record must be a JSON object")
	}
	if err := ValidateRecord(m); err != nil {
		return nil, nil, err
	}
	canon, err := EncodeCanonical(m)
	if err != nil {
		return nil, nil, err
	}
	score, _ := parseInt(m["risk_score"])
	verified, _ := m["attestation_verified"].(bool)
	return &Record{
		M: m, RecordID: str(m, "record_id"), RunID: str(m, "run_id"),
		SubmittedBy: str(m, "submitted_by_spiffe_id"), Ecosystem: str(m, "ecosystem"),
		Package: str(m, "package"), Version: str(m, "version"), Digest: str(m, "artifact_digest"),
		RiskScore: score, RiskBand: str(m, "risk_band"), Decision: str(m, "decision"),
		PolicyVersion: str(m, "policy_version"), AttestationVerified: verified,
		ScorerKeyID: str(m, "scorer_key_id"),
	}, canon, nil
}
