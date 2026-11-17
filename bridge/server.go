package main

// HTTP/JSON API in front of the Fabric ledger. It only ever listens behind
// SPIFFE mTLS (see spiffe.go) and trusts nothing the client sends: record
// bytes go to the chaincode, which validates and re-canonicalises them.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxBody    = 64 << 10
	maxCursor  = 2048
	defaultLim = 50
	maxLim     = 100
)

var (
	reRecordID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reDigest   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reDecision = regexp.MustCompile(`^(ALLOW|WARN|REVIEW|BLOCK)$`)
	reToken    = regexp.MustCompile(`^[A-Za-z0-9._@/+:-]{1,214}$`)
)

// API holds the handlers. Role decides which write endpoint exists.
type API struct {
	L    Ledger
	Role string
}

func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "role": a.Role})
	})
	mux.HandleFunc("GET /v1/records", a.listRecords)
	mux.HandleFunc("GET /v1/records/{id}", a.getRecord)
	mux.HandleFunc("GET /v1/proof/{id}", a.getProof)
	mux.HandleFunc("GET /v1/checkpoint", a.getCheckpoint)
	mux.HandleFunc("GET /v1/artifacts/{digest}", a.getArtifact)
	mux.HandleFunc("GET /v1/status/{decision}", a.listByStatus)
	mux.HandleFunc("GET /v1/packages", a.listByPackage)
	mux.HandleFunc("GET /v1/policy", a.getPolicy)
	switch a.Role {
	case "gateway":
		mux.HandleFunc("POST /v1/records", a.postRecord)
	case "auditor":
		mux.HandleFunc("POST /v1/overrides", a.postOverride)
	}
	return mux
}

// ---- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeError(w http.ResponseWriter, err error) {
	var le *LedgerError
	status, msg := http.StatusBadGateway, err.Error()
	if errors.As(err, &le) {
		msg = le.Msg
		switch le.Kind {
		case KindNotFound:
			status = http.StatusNotFound
		case KindUnavailable:
			status = http.StatusServiceUnavailable
		case KindRejected:
			status = http.StatusUnprocessableEntity
			if strings.Contains(strings.ToLower(msg), "duplicate") {
				status = http.StatusConflict
			}
		}
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

func limitParam(r *http.Request) string {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		n = defaultLim
	}
	if n > maxLim {
		n = maxLim
	}
	return strconv.Itoa(n)
}

// decodeCursor turns the client's opaque base64url cursor into the chaincode
// bookmark (a composite key containing NUL bytes, unsafe in URLs).
func decodeCursor(c string) (string, error) {
	if c == "" {
		return "", nil
	}
	if len(c) > maxCursor {
		return "", errors.New("cursor too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", errors.New("invalid cursor")
	}
	return string(raw), nil
}

// pageResponse rewrites chaincode {"items":...,"bookmark":...} to {"items":...,"next_cursor":...}.
func pageResponse(raw []byte) ([]byte, error) {
	var page struct {
		Items    json.RawMessage `json:"items"`
		Bookmark string          `json:"bookmark"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, err
	}
	cursor := ""
	if page.Bookmark != "" {
		cursor = base64.RawURLEncoding.EncodeToString([]byte(page.Bookmark))
	}
	return json.Marshal(map[string]any{"items": page.Items, "next_cursor": cursor})
}

func (a *API) evaluatePage(w http.ResponseWriter, fn string, args ...string) {
	raw, err := a.L.Evaluate(fn, args...)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := pageResponse(raw)
	if err != nil {
		writeError(w, &LedgerError{Kind: KindOther, Msg: err.Error()})
		return
	}
	writeRaw(w, http.StatusOK, out)
}

// ---- handlers ---------------------------------------------------------------

func (a *API) postRecord(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) == 0 || len(body) > maxBody {
		badRequest(w, "body must be 1..65536 bytes of JSON")
		return
	}
	res, err := a.L.Submit("RecordDecision", string(body))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (a *API) postOverride(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RecordID string `json:"record_id"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		badRequest(w, "invalid JSON body")
		return
	}
	if !reRecordID.MatchString(in.RecordID) || !reDecision.MatchString(in.Decision) {
		badRequest(w, "invalid record_id or decision")
		return
	}
	res, err := a.L.Submit("RecordOverride", in.RecordID, in.Decision, in.Reason)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (a *API) getRecord(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reRecordID.MatchString(id) {
		badRequest(w, "invalid record id")
		return
	}
	raw, err := a.L.Evaluate("GetHistory", id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) listRecords(w http.ResponseWriter, r *http.Request) {
	bookmark, err := decodeCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	a.evaluatePage(w, "ListRecent", limitParam(r), bookmark)
}

func (a *API) listByStatus(w http.ResponseWriter, r *http.Request) {
	decision := r.PathValue("decision")
	bookmark, err := decodeCursor(r.URL.Query().Get("cursor"))
	if !reDecision.MatchString(decision) || err != nil {
		badRequest(w, "invalid decision or cursor")
		return
	}
	a.evaluatePage(w, "ListByStatus", decision, limitParam(r), bookmark)
}

func (a *API) listByPackage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bookmark, err := decodeCursor(q.Get("cursor"))
	version := q.Get("version")
	if err != nil || !reToken.MatchString(q.Get("ecosystem")) || !reToken.MatchString(q.Get("package")) ||
		(version != "" && !reToken.MatchString(version)) {
		badRequest(w, "invalid ecosystem, package, version or cursor")
		return
	}
	a.evaluatePage(w, "ListByPackage", q.Get("ecosystem"), q.Get("package"), version, limitParam(r), bookmark)
}

func (a *API) getArtifact(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	if !reDigest.MatchString(digest) {
		badRequest(w, "invalid artifact digest")
		return
	}
	raw, err := a.L.Evaluate("VerifyArtifact", digest)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

// getPolicy returns the active on-chain policy (bands, allowed scorer, pinned bundle hash).
func (a *API) getPolicy(w http.ResponseWriter, _ *http.Request) {
	raw, err := a.L.Evaluate("GetPolicy", "")
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) getProof(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reRecordID.MatchString(id) {
		badRequest(w, "invalid record id")
		return
	}
	raw, err := a.L.Evaluate("GetRecord", id)
	if err != nil {
		writeError(w, err)
		return
	}
	var view struct {
		Meta struct {
			TxID string `json:"tx_id"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &view); err != nil || view.Meta.TxID == "" {
		writeError(w, &LedgerError{Kind: KindOther, Msg: "record has no transaction id"})
		return
	}
	proof, err := a.L.Proof(view.Meta.TxID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"record_id": id, "proof": proof})
}

func (a *API) getCheckpoint(w http.ResponseWriter, _ *http.Request) {
	info, err := a.L.ChainInfo()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}
