// Mock server that simulates STS GetCallerIdentity and Security Hub
// BatchImportFindings. Used for local integration tests and Minikube E2E.
//
// Endpoints:
//
//	POST /                   → STS GetCallerIdentity (AWS query protocol, XML response)
//	POST /findings/import    → Security Hub BatchImportFindings (REST-JSON)
//	GET  /mock/findings      → Returns all captured findings as JSON (test helper)
//	DELETE /mock/findings    → Clears captured findings (test helper)
//	GET  /healthz            → Health check
package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// ── STS response types ────────────────────────────────────────────────────────

type getCallerIdentityResponse struct {
	XMLName xml.Name                      `xml:"GetCallerIdentityResponse"`
	Result  getCallerIdentityResult       `xml:"GetCallerIdentityResult"`
	Meta    responseMetadata              `xml:"ResponseMetadata"`
}

type getCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserID  string `xml:"UserId"`
	Account string `xml:"Account"`
}

type responseMetadata struct {
	RequestID string `xml:"RequestId"`
}

// ── Security Hub response types ───────────────────────────────────────────────

type batchImportFindingsResponse struct {
	FailedCount    int32         `json:"FailedCount"`
	SuccessCount   int32         `json:"SuccessCount"`
	FailedFindings []interface{} `json:"FailedFindings"`
}

// ── In-memory store ───────────────────────────────────────────────────────────

type store struct {
	mu       sync.Mutex
	findings []json.RawMessage
}

func (s *store) add(raw []json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, raw...)
}

func (s *store) all() []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]json.RawMessage, len(s.findings))
	copy(out, s.findings)
	return out
}

func (s *store) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = nil
}

func main() {
	port := os.Getenv("MOCK_PORT")
	if port == "" {
		port = "4566"
	}
	account := os.Getenv("MOCK_ACCOUNT_ID")
	if account == "" {
		account = "123456789012"
	}
	region := os.Getenv("MOCK_REGION")
	if region == "" {
		region = "eu-central-1"
	}

	db := &store{}
	mux := http.NewServeMux()

	// ── STS: POST / ─────────────────────────────────────────────────────────
	// The AWS SDK sends Action=GetCallerIdentity in the body (query protocol).
	// Any other request to "/" also lands here; we check the Action field.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "GetCallerIdentity") {
			http.Error(w, "unexpected STS action", http.StatusBadRequest)
			log.Printf("STS: unexpected body: %s", body)
			return
		}

		resp := getCallerIdentityResponse{
			Result: getCallerIdentityResult{
				Account: account,
				UserID:  account,
				Arn:     fmt.Sprintf("arn:aws:iam::%s:root", account),
			},
			Meta: responseMetadata{RequestID: "mock-request-id"},
		}

		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_ = xml.NewEncoder(w).Encode(resp)
		log.Printf("STS: GetCallerIdentity → account %s", account)
	})

	// ── Security Hub: POST /findings/import ──────────────────────────────────
	mux.HandleFunc("/findings/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}

		var payload struct {
			Findings []json.RawMessage `json:"Findings"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			log.Printf("SecurityHub: invalid JSON: %v", err)
			return
		}

		db.add(payload.Findings)
		log.Printf("SecurityHub: BatchImportFindings received %d findings (total: %d)",
			len(payload.Findings), len(db.all()))

		resp := batchImportFindingsResponse{
			FailedCount:    0,
			SuccessCount:   int32(len(payload.Findings)),
			FailedFindings: []interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	// ── Test helpers ─────────────────────────────────────────────────────────

	// GET /mock/findings → returns all captured findings
	mux.HandleFunc("/mock/findings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(db.all())
		case http.MethodDelete:
			db.clear()
			w.WriteHeader(http.StatusNoContent)
			log.Printf("mock: findings cleared")
		default:
			http.NotFound(w, r)
		}
	})

	// GET /healthz
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	addr := ":" + port
	log.Printf("Mock Security Hub listening on %s (account=%s, region=%s)", addr, account, region)
	log.Fatal(http.ListenAndServe(addr, mux))
}
