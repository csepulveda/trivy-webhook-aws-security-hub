package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	webhookURL   = "http://localhost:8080/trivy-webhook"
	localstackURL = "http://localhost:4566"
)

// finding represents a minimal Security Hub finding for assertion.
type finding struct {
	Id    string `json:"Id"`
	Title string `json:"Title"`
}

func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION") != "true" {
		fmt.Println("Skipping integration tests (set INTEGRATION=true to run)")
		os.Exit(0)
	}

	if err := waitForService(localstackURL+"/_localstack/health", 30*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "LocalStack not ready: %v\n", err)
		os.Exit(1)
	}

	if err := setupLocalStack(); err != nil {
		fmt.Fprintf(os.Stderr, "LocalStack setup failed: %v\n", err)
		os.Exit(1)
	}

	if err := waitForService(webhookURL[:len(webhookURL)-len("/trivy-webhook")]+"/healthz", 15*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Webhook not ready: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func setupLocalStack() error {
	// Enable Security Hub in LocalStack
	cmd := exec.Command("aws", "--endpoint-url", localstackURL,
		"securityhub", "enable-security-hub",
		"--region", "eu-central-1")
	cmd.Env = append(os.Environ(),
		"AWS_ACCESS_KEY_ID=test",
		"AWS_SECRET_ACCESS_KEY=test",
		"AWS_DEFAULT_REGION=eu-central-1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Already enabled is fine
		if bytes.Contains(out, []byte("already")) || bytes.Contains(out, []byte("EnableSecurityHub")) {
			return nil
		}
		return fmt.Errorf("enable-security-hub: %v — %s", err, out)
	}
	return nil
}

func TestVulnerabilityReportImported(t *testing.T) {
	body, err := os.ReadFile("fixtures/vulnerability-report.json")
	require.NoError(t, err)

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "webhook response: %s", respBody)

	findings := listFindings(t)
	require.NotEmpty(t, findings, "expected findings in Security Hub after VulnerabilityReport")

	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.Id
	}

	assert.Contains(t, fmt.Sprint(ids), "CVE-2023-44487", "HIGH CVE finding expected")
	assert.Contains(t, fmt.Sprint(ids), "CVE-2023-5678", "MEDIUM CVE finding expected")
	assert.Contains(t, fmt.Sprint(ids), "CVE-2024-0001", "LOW CVE finding expected")
}

func TestConfigAuditReportImported(t *testing.T) {
	body, err := os.ReadFile("fixtures/config-audit-report.json")
	require.NoError(t, err)

	// Enable config audit via env (webhook must be started with CONFIG_AUDIT_ENABLE=true)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "webhook response: %s", respBody)
}

func TestHealthEndpoint(t *testing.T) {
	resp, err := http.Get(webhookURL[:len(webhookURL)-len("/trivy-webhook")] + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestUnknownReportTypeRejected(t *testing.T) {
	payload := []byte(`{"kind":"UnknownReport","apiVersion":"aquasecurity.github.io/v1alpha1"}`)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestEmptyBodyRejected(t *testing.T) {
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader([]byte{}))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// listFindings queries LocalStack Security Hub for imported findings.
func listFindings(t *testing.T) []finding {
	t.Helper()

	cmd := exec.Command("aws", "--endpoint-url", localstackURL,
		"securityhub", "get-findings",
		"--region", "eu-central-1",
		"--output", "json")
	cmd.Env = append(os.Environ(),
		"AWS_ACCESS_KEY_ID=test",
		"AWS_SECRET_ACCESS_KEY=test",
		"AWS_DEFAULT_REGION=eu-central-1",
	)
	out, err := cmd.Output()
	require.NoError(t, err, "get-findings failed")

	var result struct {
		Findings []finding `json:"Findings"`
	}
	require.NoError(t, json.Unmarshal(out, &result))
	return result.Findings
}

func waitForService(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode < 500 {
			resp.Body.Close()
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("service at %s not ready after %s", url, timeout)
}
