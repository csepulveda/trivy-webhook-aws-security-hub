package main

import (
	"strings"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildVulnerabilityReportFindingsIncludesNamespace(t *testing.T) {
	report := &v1alpha1.VulnerabilityReport{
		TypeMeta: metav1.TypeMeta{
			Kind:       "VulnerabilityReport",
			APIVersion: "aquasecurity.github.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-nginx-7c9d",
			Namespace: "payments",
			Labels: map[string]string{
				"trivy-operator.container.name": "nginx",
			},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Registry: v1alpha1.Registry{Server: "111122223333.dkr.ecr.eu-central-1.amazonaws.com"},
			Artifact: v1alpha1.Artifact{
				Repository: "platform/nginx",
				Tag:        "1.25.0",
			},
			Vulnerabilities: []v1alpha1.Vulnerability{
				{
					VulnerabilityID:  "CVE-2026-0001",
					Resource:         "openssl",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.0.1",
					Severity:         v1alpha1.SeverityHigh,
					Title:            "test vulnerability",
				},
			},
		},
	}

	findings := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1")

	require.Len(t, findings, 1)

	finding := findings[0]
	assert.Contains(t, aws.ToString(finding.Id), "payments-")
	assert.Contains(t, aws.ToString(finding.Title), "payments/")
	assert.Equal(t, "payments", finding.ProductFields["Namespace"])

	require.Len(t, finding.Resources, 1)
	assert.Equal(t, "payments/111122223333.dkr.ecr.eu-central-1.amazonaws.com/platform/nginx", aws.ToString(finding.Resources[0].Id))
	assert.Equal(t, "payments", finding.Resources[0].Details.Other["Kubernetes Namespace"])
	assert.Equal(t, "replicaset-nginx-7c9d", finding.Resources[0].Details.Other["Kubernetes Report"])
}

func TestBuildVulnerabilityReportFindingsTruncatesSecurityHubFields(t *testing.T) {
	longNamespace := strings.Repeat("namespace-", 20)
	longRegistry := strings.Repeat("registry", 25) + ".example.com"
	longRepository := strings.Repeat("repository/", 40) + "image"
	longContainer := strings.Repeat("container-", 20)
	longTag := strings.Repeat("tag", 100)
	longVulnerabilityID := "CVE-" + strings.Repeat("2026-", 100)

	report := &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "long-report",
			Namespace: longNamespace,
			Labels: map[string]string{
				"trivy-operator.container.name": longContainer,
			},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Registry: v1alpha1.Registry{Server: longRegistry},
			Artifact: v1alpha1.Artifact{
				Repository: longRepository,
				Tag:        longTag,
			},
			Vulnerabilities: []v1alpha1.Vulnerability{
				{
					VulnerabilityID: longVulnerabilityID,
					Severity:        v1alpha1.SeverityHigh,
					Title:           "test vulnerability",
				},
			},
		},
	}

	findings := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1")

	require.Len(t, findings, 1)
	assert.LessOrEqual(t, len([]rune(aws.ToString(findings[0].Id))), 512)
	assert.LessOrEqual(t, len([]rune(aws.ToString(findings[0].Title))), 256)
	require.Len(t, findings[0].Resources, 1)
	assert.LessOrEqual(t, len([]rune(aws.ToString(findings[0].Resources[0].Id))), 512)
}

func TestTruncateWithHash(t *testing.T) {
	short := "short-value"
	assert.Equal(t, short, truncateWithHash(short, 512))

	long := strings.Repeat("a", 600)
	truncated := truncateWithHash(long, 512)

	assert.Len(t, []rune(truncated), 512)
	assert.Equal(t, truncated, truncateWithHash(long, 512))
	assert.NotEqual(t, truncated, truncateWithHash(long+"b", 512))
	assert.Contains(t, truncated, "-")
}
