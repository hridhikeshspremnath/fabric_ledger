package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testID = "11111111-1111-4111-8111-111111111111"

// fakeLedger records calls and returns canned results.
type fakeLedger struct {
	submitFn    string
	submitArgs  []string
	submitErr   error
	evalFn      string
	evalArgs    []string
	evalOut     string
	evalErr     error
	proof       *ProofInfo
	chain       *ChainInfo
}

func (f *fakeLedger) Submit(fn string, args ...string) (*TxResult, error) {
	f.submitFn, f.submitArgs = fn, args
	if f.submitErr != nil {
		return nil, f.submitErr
	}
	return &TxResult{TxID: "tx1", BlockNumber: 7, Result: json.RawMessage(`{"ok":true}`)}, nil
}

func (f *fakeLedger) Evaluate(fn string, args ...string) ([]byte, error) {
	f.evalFn, f.evalArgs = fn, args
	return []byte(f.evalOut), f.evalErr
}

func (f *fakeLedger) Proof(txID string) (*ProofInfo, error) { return f.proof, nil }
func (f *fakeLedger) ChainInfo() (*ChainInfo, error)        { return f.chain, nil }

func serve(t *testing.T, role string, f *fakeLedger) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer((&API{L: f, Role: role}).Routes())
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestPostRecordPassesBodyThroughAndReturnsTx(t *testing.T) {
	f := &fakeLedger{}
	srv := serve(t, "gateway", f)
	code, body := do(t, "POST", srv.URL+"/v1/records", `{"record_id":"x"}`)
	if code != http.StatusCreated || f.submitFn != "RecordDecision" || f.submitArgs[0] != `{"record_id":"x"}` {
		t.Fatalf("code=%d fn=%s args=%v", code, f.submitFn, f.submitArgs)
	}
	if !strings.Contains(body, `"tx_id":"tx1"`) || !strings.Contains(body, `"block_number":7`) {
		t.Fatalf("body: %s", body)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{&LedgerError{Kind: KindRejected, Msg: "duplicate run_id: r1"}, http.StatusConflict},
		{&LedgerError{Kind: KindRejected, Msg: "invalid scorer signature"}, http.StatusUnprocessableEntity},
		{&LedgerError{Kind: KindUnavailable, Msg: "peer down"}, http.StatusServiceUnavailable},
		{&LedgerError{Kind: KindNotFound, Msg: "record not found"}, http.StatusNotFound},
		{&LedgerError{Kind: KindOther, Msg: "boom"}, http.StatusBadGateway},
	}
	for _, c := range cases {
		srv := serve(t, "gateway", &fakeLedger{submitErr: c.err})
		if code, _ := do(t, "POST", srv.URL+"/v1/records", `{}`); code != c.want {
			t.Fatalf("%v: got %d, want %d", c.err, code, c.want)
		}
	}
}

func TestRoleGatesWriteEndpoints(t *testing.T) {
	gw := serve(t, "gateway", &fakeLedger{})
	if code, _ := do(t, "POST", gw.URL+"/v1/overrides", `{}`); code == http.StatusCreated || code == http.StatusBadRequest {
		t.Fatalf("gateway role must not expose overrides, got %d", code)
	}
	au := serve(t, "auditor", &fakeLedger{})
	if code, _ := do(t, "POST", au.URL+"/v1/records", `{}`); code == http.StatusCreated {
		t.Fatal("auditor role must not accept records")
	}
}

func TestOverrideValidatesAndSubmits(t *testing.T) {
	f := &fakeLedger{}
	srv := serve(t, "auditor", f)
	good := `{"record_id":"` + testID + `","decision":"BLOCK","reason":"found malware"}`
	if code, _ := do(t, "POST", srv.URL+"/v1/overrides", good); code != http.StatusCreated || f.submitFn != "RecordOverride" ||
		f.submitArgs[1] != "BLOCK" || f.submitArgs[2] != "found malware" {
		t.Fatalf("override not submitted: %s %v", f.submitFn, f.submitArgs)
	}
	for _, bad := range []string{`{"record_id":"nope","decision":"BLOCK"}`,
		`{"record_id":"` + testID + `","decision":"MAYBE"}`,
		`{"record_id":"` + testID + `","decision":"BLOCK","extra":1}`} {
		if code, _ := do(t, "POST", srv.URL+"/v1/overrides", bad); code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", bad, code)
		}
	}
}

func TestIDValidationBeforeChaincode(t *testing.T) {
	f := &fakeLedger{evalOut: `{}`}
	srv := serve(t, "gateway", f)
	for _, path := range []string{"/v1/records/not-a-uuid", "/v1/proof/not-a-uuid",
		"/v1/artifacts/md5:abc", "/v1/status/MAYBE", "/v1/packages?ecosystem=&package=x"} {
		if code, _ := do(t, "GET", srv.URL+path, ""); code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", path, code)
		}
	}
	if f.evalFn != "" {
		t.Fatalf("chaincode was called for an invalid request: %s", f.evalFn)
	}
}

func TestListUsesOpaqueCursor(t *testing.T) {
	bookmark := "\x00ord\x00000\x00tx\x00id\x00"
	f := &fakeLedger{evalOut: `{"items":[],"bookmark":` + mustJSON(bookmark) + `}`}
	srv := serve(t, "gateway", f)
	code, body := do(t, "GET", srv.URL+"/v1/records?limit=500", "")
	if code != http.StatusOK || f.evalFn != "ListRecent" || f.evalArgs[0] != "100" {
		t.Fatalf("code=%d fn=%s args=%v", code, f.evalFn, f.evalArgs)
	}
	var page struct {
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(body), &page); err != nil || page.NextCursor == "" {
		t.Fatalf("no cursor in %s", body)
	}
	if strings.ContainsRune(page.NextCursor, 0) {
		t.Fatal("cursor must be URL-safe")
	}
	// Sending it back reaches the chaincode as the original bookmark.
	do(t, "GET", srv.URL+"/v1/records?cursor="+page.NextCursor, "")
	if f.evalArgs[1] != bookmark {
		t.Fatalf("bookmark not restored: %q", f.evalArgs[1])
	}
	if code, _ := do(t, "GET", srv.URL+"/v1/records?cursor=***", ""); code != http.StatusBadRequest {
		t.Fatalf("bad cursor: got %d", code)
	}
	_ = base64.RawURLEncoding
}

func TestProofLooksUpTxIDFromRecordMeta(t *testing.T) {
	f := &fakeLedger{
		evalOut: `{"record":{},"meta":{"tx_id":"abc123"}}`,
		proof:   &ProofInfo{TxID: "abc123", BlockNumber: 9, BlockHash: "aa"},
	}
	srv := serve(t, "gateway", f)
	code, body := do(t, "GET", srv.URL+"/v1/proof/"+testID, "")
	if code != http.StatusOK || !strings.Contains(body, `"block_number":9`) || f.evalFn != "GetRecord" {
		t.Fatalf("code=%d body=%s", code, body)
	}
}

func TestCheckpointReturnsChainInfo(t *testing.T) {
	f := &fakeLedger{chain: &ChainInfo{Channel: "attesta-ch", Height: 12, CurrentBlockHash: "bb"}}
	srv := serve(t, "gateway", f)
	code, body := do(t, "GET", srv.URL+"/v1/checkpoint", "")
	if code != http.StatusOK || !strings.Contains(body, `"height":12`) {
		t.Fatalf("code=%d body=%s", code, body)
	}
}

func mustJSON(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
