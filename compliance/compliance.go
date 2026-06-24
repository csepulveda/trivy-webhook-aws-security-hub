// compliance/compliance.go
package compliance

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/sirupsen/logrus"
)

// ComplianceReport represents the payload for a Cluster Compliance Report.
type ComplianceReport struct {
	ClusterName   string    `json:"clusterName"`
	Passed        bool      `json:"passed"`
	FailedRules   []string  `json:"failedRules"`
	ReportDetails string    `json:"reportDetails,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// ProcessComplianceReport validates, converts, and sends a compliance report to AWS Security Hub.
func ProcessComplianceReport(report *ComplianceReport) error {
	// Basic validation.
	if report.ClusterName == "" {
		return errors.New("compliance report is missing 'clusterName'")
	}

	// Convert the compliance report into an AWS Security Hub Finding.
	finding, err := convertToSecurityHubFinding(report)
	if err != nil {
		logrus.Errorf("failed to convert compliance report: %v", err)
		return err
	}

	// Send the finding to AWS Security Hub.
	if err := sendFindingToSecurityHub(finding); err != nil {
		logrus.Errorf("failed to send compliance finding: %v", err)
		return err
	}

	logrus.Infof("Successfully processed compliance report for cluster: %s", report.ClusterName)
	return nil
}

// convertToSecurityHubFinding transforms a ComplianceReport into a Security Hub Finding.
// The conversion logic is modeled after the vulnerability report conversion.
func convertToSecurityHubFinding(report *ComplianceReport) (*securityhub.AwsSecurityFinding, error) {
	// Determine the severity based on compliance status.
	severityLabel := "INFORMATIONAL"
	if !report.Passed {
		severityLabel = "HIGH"
	}

	// Construct the finding details.
	// Adjust the fields as necessary to match your Security Hub integration requirements.
	finding := &securityhub.AwsSecurityFinding{
		ProductArn:   aws.String("arn:aws:securityhub:<region>:<account-id>:product/aquasecurity/aquasecurity"),
		AwsAccountId: aws.String("<account-id>"),
		Id:           aws.String("compliance-" + report.ClusterName + "-" + report.Timestamp.Format("20060102150405")),
		Title:        aws.String("Kubernetes Cluster Compliance Report"),
		Description:  aws.String(report.ReportDetails),
		CreatedAt:    aws.String(report.Timestamp.Format(time.RFC3339)),
		UpdatedAt:    aws.String(report.Timestamp.Format(time.RFC3339)),
		Severity: &securityhub.Severity{
			Label: aws.String(severityLabel),
		},
		// Additional fields (Resources, Types, etc.) can be set here as needed.
	}
	return finding, nil
}

// sendFindingToSecurityHub sends a single finding to AWS Security Hub.
func sendFindingToSecurityHub(finding *securityhub.AwsSecurityFinding) error {
	// Create a new AWS session (consider reusing sessions in production code).
	sess, err := session.NewSession()
	if err != nil {
		return err
	}
	svc := securityhub.New(sess)

	input := &securityhub.BatchImportFindingsInput{
		Findings: []*securityhub.AwsSecurityFinding{finding},
	}
	_, err = svc.BatchImportFindings(input)
	return err
}
