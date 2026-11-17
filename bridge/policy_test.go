package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetPolicyAsksForTheActiveVersion(t *testing.T) {
	f := &fakeLedger{evalOut: `{"policy_version":"bundle-1","bundle_hash":"sha256:ab"}`}
	srv := serve(t, "gateway", f)
	code, body := do(t, "GET", srv.URL+"/v1/policy", "")
	if code != http.StatusOK || f.evalFn != "GetPolicy" || len(f.evalArgs) != 1 || f.evalArgs[0] != "" {
		t.Fatalf("code=%d fn=%s args=%q", code, f.evalFn, f.evalArgs)
	}
	if !strings.Contains(body, `"policy_version":"bundle-1"`) {
		t.Fatalf("body: %s", body)
	}
}
