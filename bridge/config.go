package main

import (
	"errors"
	"fmt"
	"strings"
)

// Config comes from environment variables (BRIDGE_*), never from files in git.
type Config struct {
	Role            string // "gateway" (submit records) or "auditor" (submit overrides)
	Listen          string
	AllowedClientID string // the only SPIFFE ID allowed to call this bridge
	SpiffeSocket    string // optional; empty uses SPIFFE_ENDPOINT_SOCKET
	PeerEndpoint    string
	PeerTLSCAPath   string
	PeerHostAlias   string
	MSPID           string
	CertPath        string
	KeyPath         string
	Channel         string
	Chaincode       string
}

var defaultClientIDs = map[string]string{
	"gateway": "spiffe://attesta.example.org/gateway",
	"auditor": "spiffe://attesta.example.org/auditor",
}

// LoadConfig reads and validates settings through getenv (injectable for tests).
func LoadConfig(getenv func(string) string) (Config, error) {
	get := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	cfg := Config{
		Role:          get("BRIDGE_ROLE", "gateway"),
		Listen:        get("BRIDGE_LISTEN", ":8444"),
		SpiffeSocket:  getenv("BRIDGE_SPIFFE_SOCKET"),
		PeerEndpoint:  getenv("BRIDGE_PEER_ENDPOINT"),
		PeerTLSCAPath: getenv("BRIDGE_PEER_TLS_CA"),
		PeerHostAlias: getenv("BRIDGE_PEER_HOST_ALIAS"),
		MSPID:         getenv("BRIDGE_MSP_ID"),
		CertPath:      getenv("BRIDGE_CERT_PATH"),
		KeyPath:       getenv("BRIDGE_KEY_PATH"),
		Channel:       get("BRIDGE_CHANNEL", "attesta-ch"),
		Chaincode:     get("BRIDGE_CHAINCODE", "attesta-trust"),
	}
	def, ok := defaultClientIDs[cfg.Role]
	if !ok {
		return cfg, fmt.Errorf("BRIDGE_ROLE must be gateway or auditor, got %q", cfg.Role)
	}
	cfg.AllowedClientID = get("BRIDGE_ALLOWED_CLIENT_ID", def)
	if !strings.HasPrefix(cfg.AllowedClientID, "spiffe://") {
		return cfg, errors.New("BRIDGE_ALLOWED_CLIENT_ID must be a SPIFFE ID")
	}
	required := map[string]string{
		"BRIDGE_PEER_ENDPOINT": cfg.PeerEndpoint, "BRIDGE_PEER_TLS_CA": cfg.PeerTLSCAPath,
		"BRIDGE_MSP_ID": cfg.MSPID, "BRIDGE_CERT_PATH": cfg.CertPath, "BRIDGE_KEY_PATH": cfg.KeyPath,
	}
	var missing []string
	for _, k := range []string{"BRIDGE_PEER_ENDPOINT", "BRIDGE_PEER_TLS_CA", "BRIDGE_MSP_ID", "BRIDGE_CERT_PATH", "BRIDGE_KEY_PATH"} {
		if required[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required settings: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}
