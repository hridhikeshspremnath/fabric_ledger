package main

// Business logic. Deterministic only: time comes from the Fabric tx
// timestamp, there are no external calls and no map-order dependence.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Config names the two organisations' MSPs.
type Config struct {
	AttestaMSP string
	AuditorMSP string
}

// Service implements the chaincode functions over a State.
type Service struct {
	st  State
	cfg Config
}

func NewService(st State, cfg Config) *Service { return &Service{st: st, cfg: cfg} }

// Meta is per-record bookkeeping written at submission time.
type Meta struct {
	TxID              string `json:"tx_id"`
	TxTime            int64  `json:"tx_time"`
	SubmittedMSP      string `json:"submitted_msp"`
	EffectiveDecision string `json:"effective_decision"`
}

// Override is an append-only auditor override.
type Override struct {
	TxID             string `json:"tx_id"`
	TxTime           int64  `json:"tx_time"`
	Decision         string `json:"decision"`
	PreviousDecision string `json:"previous_decision"`
	Reason           string `json:"reason"`
	ByMSP            string `json:"by_msp"`
}

const (
	marker     = "1" // index entries need a non-empty value
	defaultPg  = 50
	maxPg      = 100
	maxReason  = 512
	cfgKeyType = "cfg"
)

// ---- authorization -------------------------------------------------------

func (s *Service) requireMSP(msp string) (Caller, error) {
	c, err := s.st.Caller()
	if err != nil {
		return c, err
	}
	if c.MSPID != msp {
		return c, fmt.Errorf("caller MSP %q is not permitted (need %q)", c.MSPID, msp)
	}
	return c, nil
}

func (s *Service) requireAdmin() error {
	c, err := s.requireMSP(s.cfg.AttestaMSP)
	if err != nil {
		return err
	}
	if !c.Admin {
		return errors.New("admin certificate (OU=admin) required")
	}
	return nil
}

// ---- small helpers -------------------------------------------------------

func (s *Service) exists(key string) (bool, error) {
	v, err := s.st.Get(key)
	return err == nil && len(v) > 0, err
}

func (s *Service) loadJSON(key string, out any) (bool, error) {
	v, err := s.st.Get(key)
	if err != nil || len(v) == 0 {
		return false, err
	}
	return true, json.Unmarshal(v, out)
}

func (s *Service) saveJSON(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.st.Put(key, raw)
}

func pageSize(n int) int {
	if n <= 0 {
		return defaultPg
	}
	if n > maxPg {
		return maxPg
	}
	return n
}

func (s *Service) activePolicy() (*Policy, error) {
	kr := &keyer{st: s.st}
	ptr := kr.key(cfgKeyType, "active_policy")
	if kr.err != nil {
		return nil, kr.err
	}
	v, err := s.st.Get(ptr)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 {
		return nil, errors.New("no active policy set")
	}
	return s.policyByVersion(string(v))
}

func (s *Service) policyByVersion(version string) (*Policy, error) {
	kr := &keyer{st: s.st}
	k := kr.key("pol", version)
	if kr.err != nil {
		return nil, kr.err
	}
	var p Policy
	ok, err := s.loadJSON(k, &p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("policy not found: %s", version)
	}
	return &p, nil
}

func (s *Service) scorerKey(id string) (*ScorerKey, error) {
	kr := &keyer{st: s.st}
	k := kr.key("skey", id)
	if kr.err != nil {
		return nil, kr.err
	}
	var key ScorerKey
	ok, err := s.loadJSON(k, &key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("unknown scorer key: %s", id)
	}
	return &key, nil
}

func (s *Service) meta(recordID string) (*Meta, error) {
	kr := &keyer{st: s.st}
	k := kr.key("meta", recordID)
	if kr.err != nil {
		return nil, kr.err
	}
	var m Meta
	ok, err := s.loadJSON(k, &m)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("record not found: %s", recordID)
	}
	return &m, nil
}

func (s *Service) emit(name string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.st.Emit(name, raw)
}

// ---- RecordDecision ------------------------------------------------------

// RecordDecision validates and stores a signed TrustRecord. Only the Attesta
// org may submit. The record is re-canonicalised here; nothing the caller
// pre-computed is trusted.
func (s *Service) RecordDecision(recordJSON string) (string, error) {
	caller, err := s.requireMSP(s.cfg.AttestaMSP)
	if err != nil {
		return "", err
	}
	rec, canon, err := ParseRecord([]byte(recordJSON))
	if err != nil {
		return "", fmt.Errorf("invalid record: %w", err)
	}
	pol, err := s.activePolicy()
	if err != nil {
		return "", err
	}
	if rec.PolicyVersion != pol.PolicyVersion {
		return "", fmt.Errorf("policy_version %q is not the active policy %q", rec.PolicyVersion, pol.PolicyVersion)
	}
	if rec.SubmittedBy != pol.AllowedScorerID {
		return "", errors.New("submitted_by_spiffe_id is not the allowed scorer")
	}
	txTime, err := s.st.TxTime()
	if err != nil {
		return "", err
	}
	key, err := s.scorerKey(rec.ScorerKeyID)
	if err != nil {
		return "", err
	}
	if err := key.ActiveAt(txTime); err != nil {
		return "", err
	}
	if err := VerifyScorerSignature(rec.M, key.PublicKey); err != nil {
		return "", err
	}
	band, decision, err := pol.Evaluate(rec.RiskScore, rec.AttestationVerified)
	if err != nil {
		return "", err
	}
	if band != rec.RiskBand || decision != rec.Decision {
		return "", fmt.Errorf("risk_band/decision do not match policy (expected %s/%s)", band, decision)
	}

	kr := &keyer{st: s.st}
	recK := kr.key("rec", rec.RecordID)
	runK := kr.key("run", rec.RunID)
	metaK := kr.key("meta", rec.RecordID)
	pkgK := kr.key("pkg", rec.Ecosystem, rec.Package, rec.Version, rec.RecordID)
	statK := kr.key("status", rec.Decision, rec.RecordID)
	artK := kr.key("art", rec.Digest, rec.RecordID)
	ordK := kr.key("ord", fmt.Sprintf("%020d", txTime), s.st.TxID(), rec.RecordID)
	if kr.err != nil {
		return "", kr.err
	}
	if dup, err := s.exists(runK); err != nil || dup {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("duplicate run_id: %s", rec.RunID)
	}
	if dup, err := s.exists(recK); err != nil || dup {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("duplicate record_id: %s", rec.RecordID)
	}

	meta := Meta{TxID: s.st.TxID(), TxTime: txTime, SubmittedMSP: caller.MSPID, EffectiveDecision: rec.Decision}
	puts := []struct {
		k string
		v []byte
	}{{recK, canon}, {runK, []byte(rec.RecordID)}, {pkgK, []byte(marker)}, {statK, []byte(marker)}, {artK, []byte(marker)}, {ordK, []byte(marker)}}
	for _, p := range puts {
		if err := s.st.Put(p.k, p.v); err != nil {
			return "", err
		}
	}
	if err := s.saveJSON(metaK, meta); err != nil {
		return "", err
	}
	out := map[string]any{"record_id": rec.RecordID, "run_id": rec.RunID, "decision": rec.Decision,
		"tx_id": meta.TxID, "tx_time": txTime}
	if err := s.emit("RecordDecision", out); err != nil {
		return "", err
	}
	raw, err := json.Marshal(out)
	return string(raw), err
}

// ---- reads ---------------------------------------------------------------

type recordView struct {
	Record    json.RawMessage `json:"record"`
	Meta      Meta            `json:"meta"`
	Overrides []Override      `json:"overrides,omitempty"`
}

func (s *Service) view(recordID string, withHistory bool) (string, error) {
	if !reUUID.MatchString(recordID) {
		return "", errors.New("invalid record_id")
	}
	kr := &keyer{st: s.st}
	recK := kr.key("rec", recordID)
	if kr.err != nil {
		return "", kr.err
	}
	canon, err := s.st.Get(recK)
	if err != nil {
		return "", err
	}
	if len(canon) == 0 {
		return "", fmt.Errorf("record not found: %s", recordID)
	}
	meta, err := s.meta(recordID)
	if err != nil {
		return "", err
	}
	v := recordView{Record: canon, Meta: *meta}
	if withHistory {
		items, _, err := s.st.Scan("ovr", []string{recordID}, maxPg, "")
		if err != nil {
			return "", err
		}
		for _, kv := range items {
			var o Override
			if err := json.Unmarshal(kv.Value, &o); err != nil {
				return "", err
			}
			v.Overrides = append(v.Overrides, o)
		}
	}
	raw, err := json.Marshal(v)
	return string(raw), err
}

// GetRecord returns the canonical record and its bookkeeping.
func (s *Service) GetRecord(recordID string) (string, error) { return s.view(recordID, false) }

// GetHistory returns the record plus every override in order.
func (s *Service) GetHistory(recordID string) (string, error) { return s.view(recordID, true) }

type listItem struct {
	RecordID          string `json:"record_id"`
	EffectiveDecision string `json:"effective_decision"`
}

type listPage struct {
	Items    []listItem `json:"items"`
	Bookmark string     `json:"bookmark"`
}

func (s *Service) list(objectType string, attrs []string, size int, bookmark string) (string, error) {
	items, next, err := s.st.Scan(objectType, attrs, pageSize(size), bookmark)
	if err != nil {
		return "", err
	}
	page := listPage{Items: []listItem{}, Bookmark: next}
	for _, kv := range items {
		id := kv.Attrs[len(kv.Attrs)-1]
		meta, err := s.meta(id)
		if err != nil {
			return "", err
		}
		page.Items = append(page.Items, listItem{RecordID: id, EffectiveDecision: meta.EffectiveDecision})
	}
	raw, err := json.Marshal(page)
	return string(raw), err
}

type recentPage struct {
	Items    []json.RawMessage `json:"items"`
	Bookmark string            `json:"bookmark"`
}

// ListRecent pages through all records oldest-first (by tx time, then tx id),
// returning full record views. The bookmark is opaque to callers.
func (s *Service) ListRecent(size int, bookmark string) (string, error) {
	items, next, err := s.st.Scan("ord", nil, pageSize(size), bookmark)
	if err != nil {
		return "", err
	}
	page := recentPage{Items: []json.RawMessage{}, Bookmark: next}
	for _, kv := range items {
		v, err := s.view(kv.Attrs[len(kv.Attrs)-1], false)
		if err != nil {
			return "", err
		}
		page.Items = append(page.Items, json.RawMessage(v))
	}
	raw, err := json.Marshal(page)
	return string(raw), err
}

// ListByPackage pages through records for ecosystem/package[/version].
func (s *Service) ListByPackage(ecosystem, pkg, version string, size int, bookmark string) (string, error) {
	if !reEcosystem.MatchString(ecosystem) || !reName.MatchString(pkg) {
		return "", errors.New("invalid ecosystem or package")
	}
	attrs := []string{ecosystem, pkg}
	if version != "" {
		if !reName.MatchString(version) {
			return "", errors.New("invalid version")
		}
		attrs = append(attrs, version)
	}
	return s.list("pkg", attrs, size, bookmark)
}

// ListByStatus pages through records whose effective decision is `decision`.
func (s *Service) ListByStatus(decision string, size int, bookmark string) (string, error) {
	if !inEnum(decision, enumDecision) {
		return "", errors.New("invalid decision")
	}
	return s.list("status", []string{decision}, size, bookmark)
}

// ---- VerifyArtifact ------------------------------------------------------

type artifactRecord struct {
	RecordID          string `json:"record_id"`
	EffectiveDecision string `json:"effective_decision"`
	TxTime            int64  `json:"tx_time"`
	TxID              string `json:"tx_id"`
}

type artifactView struct {
	ArtifactDigest          string           `json:"artifact_digest"`
	Found                   bool             `json:"found"`
	LatestRecordID          string           `json:"latest_record_id,omitempty"`
	LatestEffectiveDecision string           `json:"latest_effective_decision,omitempty"`
	Records                 []artifactRecord `json:"records"`
}

// VerifyArtifact reports every decision recorded for an artifact digest and
// the latest effective one (by transaction time, then tx id).
func (s *Service) VerifyArtifact(digest string) (string, error) {
	if !reSHA256.MatchString(digest) {
		return "", errors.New("invalid artifact digest")
	}
	items, _, err := s.st.Scan("art", []string{digest}, maxPg, "")
	if err != nil {
		return "", err
	}
	out := artifactView{ArtifactDigest: digest, Records: []artifactRecord{}}
	var latest *artifactRecord
	for _, kv := range items {
		id := kv.Attrs[len(kv.Attrs)-1]
		meta, err := s.meta(id)
		if err != nil {
			return "", err
		}
		r := artifactRecord{RecordID: id, EffectiveDecision: meta.EffectiveDecision, TxTime: meta.TxTime, TxID: meta.TxID}
		out.Records = append(out.Records, r)
		if latest == nil || r.TxTime > latest.TxTime || (r.TxTime == latest.TxTime && r.TxID > latest.TxID) {
			cp := r
			latest = &cp
		}
	}
	if latest != nil {
		out.Found = true
		out.LatestRecordID = latest.RecordID
		out.LatestEffectiveDecision = latest.EffectiveDecision
	}
	raw, err := json.Marshal(out)
	return string(raw), err
}

// ---- RecordOverride (Auditor only) ----------------------------------------

func validReason(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("a reason is required")
	}
	if len(reason) > maxReason {
		return fmt.Errorf("reason longer than %d bytes", maxReason)
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return errors.New("reason contains control characters")
		}
	}
	return nil
}

// RecordOverride lets the Auditor org change a record's effective decision.
// The original record is never modified; the override is appended.
func (s *Service) RecordOverride(recordID, newDecision, reason string) (string, error) {
	caller, err := s.requireMSP(s.cfg.AuditorMSP)
	if err != nil {
		return "", err
	}
	if !reUUID.MatchString(recordID) {
		return "", errors.New("invalid record_id")
	}
	if !inEnum(newDecision, enumDecision) {
		return "", errors.New("invalid decision")
	}
	if err := validReason(reason); err != nil {
		return "", err
	}
	meta, err := s.meta(recordID)
	if err != nil {
		return "", err
	}
	txTime, err := s.st.TxTime()
	if err != nil {
		return "", err
	}
	o := Override{TxID: s.st.TxID(), TxTime: txTime, Decision: newDecision,
		PreviousDecision: meta.EffectiveDecision, Reason: reason, ByMSP: caller.MSPID}

	kr := &keyer{st: s.st}
	ovrK := kr.key("ovr", recordID, fmt.Sprintf("%020d", txTime), o.TxID)
	oldStat := kr.key("status", meta.EffectiveDecision, recordID)
	newStat := kr.key("status", newDecision, recordID)
	metaK := kr.key("meta", recordID)
	if kr.err != nil {
		return "", kr.err
	}
	if err := s.saveJSON(ovrK, o); err != nil {
		return "", err
	}
	if oldStat != newStat {
		if err := s.st.Del(oldStat); err != nil {
			return "", err
		}
		if err := s.st.Put(newStat, []byte(marker)); err != nil {
			return "", err
		}
	}
	meta.EffectiveDecision = newDecision
	if err := s.saveJSON(metaK, meta); err != nil {
		return "", err
	}
	if err := s.emit("RecordOverride", map[string]any{"record_id": recordID, "decision": newDecision, "tx_id": o.TxID}); err != nil {
		return "", err
	}
	raw, err := json.Marshal(o)
	return string(raw), err
}

// ---- admin: scorer keys, policy, checkpoints --------------------------------

// RegisterScorerKey adds a scorer public key (immutable except for revocation).
func (s *Service) RegisterScorerKey(keyJSON string) error {
	if err := s.requireAdmin(); err != nil {
		return err
	}
	var key ScorerKey
	if err := json.Unmarshal([]byte(keyJSON), &key); err != nil {
		return fmt.Errorf("invalid key JSON: %w", err)
	}
	key.Revoked = false
	if err := key.Validate(); err != nil {
		return err
	}
	kr := &keyer{st: s.st}
	k := kr.key("skey", key.KeyID)
	if kr.err != nil {
		return kr.err
	}
	if dup, err := s.exists(k); err != nil || dup {
		if err != nil {
			return err
		}
		return fmt.Errorf("scorer key already registered: %s", key.KeyID)
	}
	return s.saveJSON(k, key)
}

// RevokeScorerKey marks a key revoked; it stays in the registry for audit.
func (s *Service) RevokeScorerKey(keyID string) error {
	if err := s.requireAdmin(); err != nil {
		return err
	}
	key, err := s.scorerKey(keyID)
	if err != nil {
		return err
	}
	key.Revoked = true
	kr := &keyer{st: s.st}
	k := kr.key("skey", keyID)
	if kr.err != nil {
		return kr.err
	}
	return s.saveJSON(k, key)
}

// GetScorerKey returns a registry entry.
func (s *Service) GetScorerKey(keyID string) (string, error) {
	key, err := s.scorerKey(keyID)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(key)
	return string(raw), err
}

// SetPolicy stores a new (immutable) policy version and makes it active.
func (s *Service) SetPolicy(policyJSON string) error {
	if err := s.requireAdmin(); err != nil {
		return err
	}
	var p Policy
	if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
		return fmt.Errorf("invalid policy JSON: %w", err)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	kr := &keyer{st: s.st}
	k := kr.key("pol", p.PolicyVersion)
	ptr := kr.key(cfgKeyType, "active_policy")
	if kr.err != nil {
		return kr.err
	}
	if dup, err := s.exists(k); err != nil || dup {
		if err != nil {
			return err
		}
		return fmt.Errorf("policy version already exists: %s", p.PolicyVersion)
	}
	if err := s.saveJSON(k, p); err != nil {
		return err
	}
	return s.st.Put(ptr, []byte(p.PolicyVersion))
}

// GetPolicy returns a policy version, or the active one when version is "".
func (s *Service) GetPolicy(version string) (string, error) {
	var (
		p   *Policy
		err error
	)
	if version == "" {
		p, err = s.activePolicy()
	} else {
		p, err = s.policyByVersion(version)
	}
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(p)
	return string(raw), err
}

// Checkpoint is an off-chain Merkle root notarised on the ledger.
type Checkpoint struct {
	CheckpointID string `json:"checkpoint_id"`
	MerkleRoot   string `json:"merkle_root"`
	RecordCount  int64  `json:"record_count"`
	Source       string `json:"source"`
	TxID         string `json:"tx_id"`
	TxTime       int64  `json:"tx_time"`
}

// AnchorCheckpoint notarises an externally computed checkpoint (admin only).
func (s *Service) AnchorCheckpoint(id, merkleRoot string, recordCount int, source string) (string, error) {
	if err := s.requireAdmin(); err != nil {
		return "", err
	}
	if !reID.MatchString(id) || !reID.MatchString(source) || !reHex64.MatchString(merkleRoot) || recordCount < 0 {
		return "", errors.New("invalid checkpoint arguments")
	}
	txTime, err := s.st.TxTime()
	if err != nil {
		return "", err
	}
	kr := &keyer{st: s.st}
	k := kr.key("chk", id)
	if kr.err != nil {
		return "", kr.err
	}
	if dup, err := s.exists(k); err != nil || dup {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("checkpoint already anchored: %s", id)
	}
	c := Checkpoint{CheckpointID: id, MerkleRoot: merkleRoot, RecordCount: int64(recordCount),
		Source: source, TxID: s.st.TxID(), TxTime: txTime}
	if err := s.saveJSON(k, c); err != nil {
		return "", err
	}
	raw, err := json.Marshal(c)
	return string(raw), err
}

// GetCheckpoint returns an anchored checkpoint.
func (s *Service) GetCheckpoint(id string) (string, error) {
	if !reID.MatchString(id) {
		return "", errors.New("invalid checkpoint id")
	}
	kr := &keyer{st: s.st}
	k := kr.key("chk", id)
	if kr.err != nil {
		return "", kr.err
	}
	v, err := s.st.Get(k)
	if err != nil {
		return "", err
	}
	if len(v) == 0 {
		return "", fmt.Errorf("checkpoint not found: %s", id)
	}
	return string(v), nil
}
