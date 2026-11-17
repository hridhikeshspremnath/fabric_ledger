package main

import (
	"errors"
	"fmt"
	"sort"
)

// Band maps a permille score range to a decision.
type Band struct {
	Name     string `json:"name"`
	MinScore int64  `json:"min_score"`
	MaxScore int64  `json:"max_score"`
	Decision string `json:"decision"`
}

// Policy is the on-chain scoring policy (same bands as config/policy.yaml).
type Policy struct {
	PolicyVersion   string `json:"policy_version"`
	AllowedScorerID string `json:"allowed_scorer_spiffe_id"`
	Bands           []Band `json:"bands"`
}

// decisionRank orders decisions from least to most strict.
var decisionRank = map[string]int{"ALLOW": 0, "WARN": 1, "REVIEW": 2, "BLOCK": 3}

// Validate requires contiguous bands covering 0..1000 with known names/decisions.
func (p Policy) Validate() error {
	if !reID.MatchString(p.PolicyVersion) {
		return errors.New("invalid policy_version")
	}
	if !reSpiffe.MatchString(p.AllowedScorerID) {
		return errors.New("invalid allowed_scorer_spiffe_id")
	}
	bands := append([]Band(nil), p.Bands...)
	sort.Slice(bands, func(i, j int) bool { return bands[i].MinScore < bands[j].MinScore })
	next := int64(0)
	for _, b := range bands {
		if !inEnum(b.Name, enumBand) || !inEnum(b.Decision, enumDecision) {
			return fmt.Errorf("invalid band: %s/%s", b.Name, b.Decision)
		}
		if b.MinScore != next || b.MaxScore < b.MinScore {
			return errors.New("policy bands must be contiguous, starting at 0")
		}
		next = b.MaxScore + 1
	}
	if next != 1001 {
		return errors.New("policy bands must end at 1000")
	}
	return nil
}

// Evaluate returns the band name and decision for a score. Missing runner
// attestation downgrades ALLOW/WARN to REVIEW; REVIEW and BLOCK are kept.
func (p Policy) Evaluate(score int64, attestationVerified bool) (band string, decision string, err error) {
	for _, b := range p.Bands {
		if score >= b.MinScore && score <= b.MaxScore {
			decision = b.Decision
			if !attestationVerified && (decision == "ALLOW" || decision == "WARN") {
				decision = "REVIEW"
			}
			return b.Name, decision, nil
		}
	}
	return "", "", fmt.Errorf("score out of range: %d", score)
}
