package main

import (
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func validEnv() map[string]string {
	return map[string]string{
		"BRIDGE_PEER_ENDPOINT": "peer0.attesta.example.com:7051",
		"BRIDGE_PEER_TLS_CA":   "/crypto/ca.pem",
		"BRIDGE_MSP_ID":        "AttestaMSP",
		"BRIDGE_CERT_PATH":     "/crypto/cert.pem",
		"BRIDGE_KEY_PATH":      "/crypto/key.pem",
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(envMap(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Role != "gateway" || cfg.Channel != "attesta-ch" || cfg.Chaincode != "attesta-trust" ||
		cfg.AllowedClientID != "spiffe://attesta.example.org/gateway" || cfg.Listen != ":8444" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestConfigAuditorRoleDefaultsToAuditorID(t *testing.T) {
	env := validEnv()
	env["BRIDGE_ROLE"] = "auditor"
	cfg, err := LoadConfig(envMap(env))
	if err != nil || cfg.AllowedClientID != "spiffe://attesta.example.org/auditor" {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestConfigRejectsBadRoleAndMissingSettings(t *testing.T) {
	env := validEnv()
	env["BRIDGE_ROLE"] = "root"
	if _, err := LoadConfig(envMap(env)); err == nil {
		t.Fatal("bad role accepted")
	}
	delete(env, "BRIDGE_ROLE")
	delete(env, "BRIDGE_KEY_PATH")
	_, err := LoadConfig(envMap(env))
	if err == nil || !strings.Contains(err.Error(), "BRIDGE_KEY_PATH") {
		t.Fatalf("want missing BRIDGE_KEY_PATH, got %v", err)
	}
	env = validEnv()
	env["BRIDGE_ALLOWED_CLIENT_ID"] = "gateway"
	if _, err := LoadConfig(envMap(env)); err == nil {
		t.Fatal("non-SPIFFE client id accepted")
	}
}
