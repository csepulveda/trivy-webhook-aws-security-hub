// Integration tests for the trivy-webhook-aws-security-hub service.
//
// Requires:  INTEGRATION=true
// Setup:     hack/integration-test.sh handles starting the mock and webhook.
// Manually:  go test ./tests/integration/... -v -count=1 (with services running)
package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	webhookBase = "http://localhost:8080"
	mockBase    = "http://localhost:4566"
)

func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION") != "true" {
		fmt.Println("Skipping integration tests (set INTEGRATION=true to run)")
		os.Exit(0)
	}

	require := func(service, url string) {
		if err := waitForService(url, 30*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "%s not ready at %s: %v\n", service, url, err)
			os.Exit(1)
		}
	}

	require("mock-security-hub", mockBase+"/healthz")
	require("webhook", webhookBase+"/healthz")

	os.Exit(m.Run())
}

// ── helpers ───────────────────────────────────────────────────────────────────

func postWebhook(t *testing.T, fixturePath string) *http.Response {
	t.Helper()
	body, err := os.ReadFile(fixturePath)
	require.NoError(t, err)
	resp, err := http.Post(webhookBase+"/trivy-webhook", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	return resp
}

func capturedFindings(t *testing.T) []map[string]interface{} {
	t.Helper()
	resp, err := http.Get(mockBase + "/mock/findings")
	require.NoError(t, err)
	defer resp.Body.Close()
	var findings []map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&findings))
	return findings
}

func clearFindings(t *testing.T) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, mockBase+"/mock/findings", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
}

func findingIDs(findings []map[string]interface{}) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		if id, ok := f["Id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func waitForService(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("timeout after %s", timeout)
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestHealthEndpoint(t *testing.T) {
	resp, err := http.Get(webhookBase + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestVulnerabilityReport_ThreeCVEsImported(t *testing.T) {
	clearFindings(t)

	resp := postWebhook(t, "fixtures/vulnerability-report.json")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "response: %s", body)

	findings := capturedFindings(t)
	require.Len(t, findings, 3, "expected 3 findings for 3 CVEs in the fixture")

	ids := strings.Join(findingIDs(findings), " ")
	assert.Contains(t, ids, "CVE-2023-44487", "HIGH CVE should be imported")
	assert.Contains(t, ids, "CVE-2023-5678", "MEDIUM CVE should be imported")
	assert.Contains(t, ids, "CVE-2024-0001", "LOW CVE should be imported")
}

func TestVulnerabilityReport_NamespaceInFindingID(t *testing.T) {
	clearFindings(t)

	resp := postWebhook(t, "fixtures/vulnerability-report.json")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	findings := capturedFindings(t)
	require.NotEmpty(t, findings)

	// Fixture namespace is "payments"
	for _, f := range findings {
		id := f["Id"].(string)
		assert.Contains(t, id, "payments", "namespace should be in finding ID, got: %s", id)
	}
}

func TestVulnerabilityReport_SeveritiesPreserved(t *testing.T) {
	clearFindings(t)
	postWebhook(t, "fixtures/vulnerability-report.json")

	severities := map[string]string{}
	for _, f := range capturedFindings(t) {
		id := f["Id"].(string)
		if sev, ok := f["Severity"].(map[string]interface{}); ok {
			severities[id] = sev["Label"].(string)
		}
	}

	for id, label := range severities {
		switch {
		case strings.Contains(id, "CVE-2023-44487"):
			assert.Equal(t, "HIGH", label)
		case strings.Contains(id, "CVE-2023-5678"):
			assert.Equal(t, "MEDIUM", label)
		case strings.Contains(id, "CVE-2024-0001"):
			assert.Equal(t, "LOW", label)
		}
	}
}

func TestConfigAuditReport_ThreeChecksImported(t *testing.T) {
	clearFindings(t)

	resp := postWebhook(t, "fixtures/config-audit-report.json")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "response: %s", body)

	findings := capturedFindings(t)
	assert.Len(t, findings, 3, "expected 3 findings for 3 config audit checks")

	ids := strings.Join(findingIDs(findings), " ")
	assert.Contains(t, ids, "KSV001")
	assert.Contains(t, ids, "KSV003")
	assert.Contains(t, ids, "KSV014")
}

func TestUnknownReportTypeRejected(t *testing.T) {
	payload := []byte(`{"kind":"UnknownReport","apiVersion":"aquasecurity.github.io/v1alpha1"}`)
	resp, err := http.Post(webhookBase+"/trivy-webhook", "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEmptyBodyRejected(t *testing.T) {
	resp, err := http.Post(webhookBase+"/trivy-webhook", "application/json", bytes.NewReader([]byte{}))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestInvalidJSONRejected(t *testing.T) {
	resp, err := http.Post(webhookBase+"/trivy-webhook", "application/json", bytes.NewReader([]byte(`{not json`)))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
