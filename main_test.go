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

	findings := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1", false, "")

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

	findings := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1", false, "")

	require.Len(t, findings, 1)
	assert.LessOrEqual(t, len([]rune(aws.ToString(findings[0].Id))), 512)
	assert.LessOrEqual(t, len([]rune(aws.ToString(findings[0].Title))), 256)
	require.Len(t, findings[0].Resources, 1)
	assert.LessOrEqual(t, len([]rune(aws.ToString(findings[0].Resources[0].Id))), 512)
}

func TestBuildVulnerabilityReportFindingsIncludesAccountID(t *testing.T) {
	report := &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-nginx-7c9d",
			Namespace: "payments",
			Labels:    map[string]string{"trivy-operator.container.name": "nginx"},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Registry: v1alpha1.Registry{Server: "docker.io"},
			Artifact: v1alpha1.Artifact{Repository: "library/nginx", Tag: "1.25.0"},
			Vulnerabilities: []v1alpha1.Vulnerability{
				{VulnerabilityID: "CVE-2026-0001", Severity: v1alpha1.SeverityHigh, Title: "test"},
			},
		},
	}

	withoutAccount := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1", false, "")
	withAccount := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1", true, "")

	require.Len(t, withAccount, 1)
	assert.Contains(t, aws.ToString(withAccount[0].Id), "123456789012-")
	assert.NotContains(t, aws.ToString(withoutAccount[0].Id), "123456789012-")
}

func TestBuildVulnerabilityReportFindingsClusterName(t *testing.T) {
	report := &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-nginx-7c9d",
			Namespace: "payments",
			Labels:    map[string]string{"trivy-operator.container.name": "nginx"},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Registry: v1alpha1.Registry{Server: "docker.io"},
			Artifact: v1alpha1.Artifact{Repository: "library/nginx", Tag: "1.25.0"},
			Vulnerabilities: []v1alpha1.Vulnerability{
				{VulnerabilityID: "CVE-2026-0001", Severity: v1alpha1.SeverityHigh, Title: "test"},
			},
		},
	}

	withCluster := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1", false, "prod-cluster")
	withoutCluster := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1", false, "")

	require.Len(t, withCluster, 1)
	assert.Contains(t, aws.ToString(withCluster[0].Id), "prod-cluster-")
	assert.Equal(t, "prod-cluster", withCluster[0].ProductFields["ClusterName"])

	assert.NotContains(t, aws.ToString(withoutCluster[0].Id), "prod-cluster-")
	assert.Empty(t, withoutCluster[0].ProductFields["ClusterName"])

	// findings from two clusters for the same CVE must have different IDs
	devCluster := buildVulnerabilityReportFindings(report, "123456789012", "eu-central-1", false, "dev-cluster")
	assert.NotEqual(t, aws.ToString(withCluster[0].Id), aws.ToString(devCluster[0].Id))
}

func TestBuildConfigAuditReportFindingsNoOwnerReferences(t *testing.T) {
	report := &v1alpha1.ConfigAuditReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "cluster-level-report",
			OwnerReferences: nil,
		},
		Report: v1alpha1.ConfigAuditReportData{
			Checks: []v1alpha1.Check{
				{
					ID:       "KSV001",
					Title:    "no privileged containers",
					Severity: "HIGH",
					Messages: []string{"container foo is privileged"},
				},
			},
		},
	}

	findings := buildConfigAuditReportFindings(report, "123456789012", "eu-central-1", Config{})

	require.Len(t, findings, 1)
	assert.Contains(t, aws.ToString(findings[0].Id), "cluster-level-report")
	assert.Equal(t, "container foo is privileged", findings[0].Resources[0].Details.Other["Message"])
}

func TestBuildConfigAuditReportFindingsEmptyMessages(t *testing.T) {
	report := &v1alpha1.ConfigAuditReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-report",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "nginx"},
			},
		},
		Report: v1alpha1.ConfigAuditReportData{
			Checks: []v1alpha1.Check{
				{
					ID:       "KSV002",
					Title:    "check with no messages",
					Severity: "LOW",
					Messages: nil,
				},
			},
		},
	}

	findings := buildConfigAuditReportFindings(report, "123456789012", "eu-central-1", Config{})

	require.Len(t, findings, 1)
	assert.Equal(t, "", findings[0].Resources[0].Details.Other["Message"])
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
