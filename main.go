package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/csepulveda/trivy-webhook-aws-security-hub/tools"
	"github.com/gorilla/mux"
)

type webhook struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
}

// ProcessTrivyWebhook processes incoming vulnerability reports
func ProcessTrivyWebhook(w http.ResponseWriter, r *http.Request) {
	var report webhook

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		log.Printf("Error reading request body: %v", err)
		return
	}

	// Validate request body is not empty
	if len(body) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		log.Printf("Empty request body")
		return
	}

	// Decode JSON
	err = json.Unmarshal(body, &report)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		log.Printf("Error decoding JSON: %v", err)
		return
	}

	var findings []types.AwsSecurityFinding
	switch report.Kind {
	case "ConfigAuditReport":
		findings, err = getConfigAuditReportFindings(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
	case "InfraAssessmentReport":
		findings, err = getInfraAssessmentReport(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
	case "ClusterComplianceReport":
		findings, err = getClusterComplianceReport(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
	case "VulnerabilityReport":
		findings, err = getVulnerabilityReportFindings(body)
		if err != nil {
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return
		}
		fmt.Println("--VulnerabilityReport--")
		// dump the findings
		for _, finding := range findings {
			fmt.Println(finding)
		}
	default: // Unknown report type
		http.Error(w, "unknown report type", http.StatusBadRequest)
		log.Printf("unknown report type: %s", report.Kind)
		return
	}

	//send findings to security hub
	err = importFindingsToSecurityHub(findings)
	if err != nil {
		http.Error(w, "Error importing findings to Security Hub", http.StatusInternalServerError)
		log.Printf("Error importing findings to Security Hub: %v", err)
		return
	}

	// Return a success response
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte("Vulnerabilities processed and imported to Security Hub"))
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}

}

func getConfigAuditReportFindings(body []byte) ([]types.AwsSecurityFinding, error) {
	configAuditReport := &v1alpha1.ConfigAuditReport{}

	// Decode JSON
	err := json.Unmarshal(body, &configAuditReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", configAuditReport.Name)

	// Prepare findings for AWS Security Hub BatchImportFindings API
	var findings []types.AwsSecurityFinding

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	// Create AWS STS clients
	stsClient := sts.NewFromConfig(cfg)
	callerIdentity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Prepare variables
	AWSAccountID := aws.ToString(callerIdentity.Account)
	AWSRegion := cfg.Region
	ProductArn := fmt.Sprintf("arn:aws:securityhub:%s::product/aquasecurity/aquasecurity", AWSRegion)
	Name := fmt.Sprintf("%s/%s", configAuditReport.OwnerReferences[0].Kind, configAuditReport.OwnerReferences[0].Name)

	// Handle Checks
	for _, check := range configAuditReport.Report.Checks {
		severity := check.Severity
		if severity == "UNKNOWN" {
			severity = "INFORMATIONAL"
		}

		// Truncate description if too long
		description := check.Description
		if len(description) > 512 {
			description = description[:512] + "..."
		}

		findings = append(findings, types.AwsSecurityFinding{
			SchemaVersion: aws.String("2018-10-08"),
			Id:            aws.String(fmt.Sprintf("%s-%s", check.ID, Name)),
			ProductArn:    aws.String(ProductArn),
			GeneratorId:   aws.String(fmt.Sprintf("Trivy/%s", check.ID)),
			AwsAccountId:  aws.String(AWSAccountID),
			Types:         []string{"Software and Configuration Checks"},
			CreatedAt:     aws.String(time.Now().Format(time.RFC3339)),
			UpdatedAt:     aws.String(time.Now().Format(time.RFC3339)),
			Severity:      &types.Severity{Label: types.SeverityLabel(severity)},
			Title:         aws.String(fmt.Sprintf("Trivy found a misconfiguration in %s: %s", Name, check.Title)),
			Description:   aws.String(description),
			Remediation: &types.Remediation{
				Recommendation: &types.Recommendation{
					Text: aws.String(check.Remediation),
				},
			},
			ProductFields: map[string]string{"Product Name": "Trivy"},
			Resources: []types.Resource{
				{
					Type:      aws.String("Other"),
					Id:        aws.String(Name),
					Partition: types.PartitionAws,
					Region:    aws.String(AWSRegion),
					Details: &types.ResourceDetails{
						Other: map[string]string{
							"Message": check.Messages[0],
						},
					},
				},
			},
			RecordState: types.RecordStateActive,
		})
	}

	return findings, nil
}

func getInfraAssessmentReport(body []byte) ([]types.AwsSecurityFinding, error) {
	infraAssessmentReport := &v1alpha1.InfraAssessmentReport{}

	// Decode JSON
	err := json.Unmarshal(body, &infraAssessmentReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", infraAssessmentReport.Name)

	// by the moment, only print the report for debugging purposes
	reportJSON, err := json.MarshalIndent(infraAssessmentReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error encoding JSON: %v", err)
	}
	log.Printf("Report: %s", reportJSON)

	// Prepare findings for AWS Security Hub BatchImportFindings API
	var findings []types.AwsSecurityFinding

	return findings, nil
}

func getClusterComplianceReport(body []byte) ([]types.AwsSecurityFinding, error) {
	clusterComplianceReport := &v1alpha1.ClusterComplianceReport{}

	// Decode JSON
	err := json.Unmarshal(body, &clusterComplianceReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", clusterComplianceReport.Name)

	// by the moment, only print the report for debugging purposes
	reportJSON, err := json.MarshalIndent(clusterComplianceReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error encoding JSON: %v", err)
	}
	log.Printf("Report: %s", reportJSON)

	// Prepare findings for AWS Security Hub BatchImportFindings API
	var findings []types.AwsSecurityFinding

	return findings, nil
}

func getVulnerabilityReportFindings(body []byte) ([]types.AwsSecurityFinding, error) {
	vulnerabilityReport := &v1alpha1.VulnerabilityReport{}

	// Decode JSON
	err := json.Unmarshal(body, &vulnerabilityReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", vulnerabilityReport.Name)
	// Load AWS SDK config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	// Create AWS STS clients
	stsClient := sts.NewFromConfig(cfg)
	callerIdentity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Prepare variables
	AWSAccountID := aws.ToString(callerIdentity.Account)
	AWSRegion := cfg.Region
	ProductArn := fmt.Sprintf("arn:aws:securityhub:%s::product/aquasecurity/aquasecurity", AWSRegion)
	Container := vulnerabilityReport.Labels["trivy-operator.container.name"]
	Registry := vulnerabilityReport.Report.Registry.Server
	Repository := vulnerabilityReport.Report.Artifact.Repository
	Digest := vulnerabilityReport.Report.Artifact.Digest
	FullImageName := fmt.Sprintf("%s/%s:%s", Registry, Repository, Digest)
	ImageName := fmt.Sprintf("%s/%s", Registry, Repository)

	// Prepare findings for AWS Security Hub BatchImportFindings API
	var findings []types.AwsSecurityFinding

	// Handle Vulnerabilities
	for _, vulnerabilities := range vulnerabilityReport.Report.Vulnerabilities {
		severity := vulnerabilities.Severity
		if severity == "UNKNOWN" {
			severity = "INFORMATIONAL"
		}

		// Truncate description if too long
		description := vulnerabilities.Title
		if len(description) > 1024 {
			description = description[:1024] + "..."
		}

		// dump the findings with key values
		fmt.Println("Id: %s-%s", FullImageName, vulnerabilities.VulnerabilityID)
		fmt.Println("ProductArn: %s", ProductArn)
		fmt.Println("GeneratorId: %s", fmt.Sprintf("Trivy/%s", vulnerabilities.VulnerabilityID))
		fmt.Println("AwsAccountId: %s", AWSAccountID)
		fmt.Println("Types: %s", []string{"Software and Configuration Checks/Vulnerabilities/CVE"})
		fmt.Println("CreatedAt: %s", time.Now().Format(time.RFC3339))
		fmt.Println("UpdatedAt: %s", time.Now().Format(time.RFC3339))
		fmt.Println("Severity: %s", severity)
		fmt.Println("Title: %s", fmt.Sprintf("Trivy found a vulnerability in %s/%s related to %s", ImageName, Container, vulnerabilities.VulnerabilityID))
		fmt.Println("Description: %s", description)
		fmt.Println("Remediation: %s", fmt.Sprintf("Upgrade to version %s", vulnerabilities.FixedVersion))
		fmt.Println("Url: %s", vulnerabilities.PrimaryLink)
		fmt.Println("ProductFields: %s", map[string]string{"Product Name": "Trivy"})
		fmt.Println("Container Image: %s", ImageName)
		fmt.Println("CVE ID: %s", vulnerabilities.VulnerabilityID)
		fmt.Println("CVE Title: %s", vulnerabilities.Title)
		fmt.Println("PkgName: %s", vulnerabilities.Resource)
		fmt.Println("Installed Package: %s", vulnerabilities.InstalledVersion)
		fmt.Println("Patched Package: %s", vulnerabilities.FixedVersion)
		fmt.Println("NvdCvssScoreV3: %f", tools.GetVulnScore(vulnerabilities))
		fmt.Println("NvdCvssVectorV3: %s", "")
			
		findings = append(findings, types.AwsSecurityFinding{
			SchemaVersion: aws.String("2018-10-08"),
			Id:            aws.String(fmt.Sprintf("%s-%s", FullImageName, vulnerabilities.VulnerabilityID)),
			ProductArn:    aws.String(ProductArn),
			GeneratorId:   aws.String(fmt.Sprintf("Trivy/%s", vulnerabilities.VulnerabilityID)),
			AwsAccountId:  aws.String(AWSAccountID),
			Types:         []string{"Software and Configuration Checks/Vulnerabilities/CVE"},
			CreatedAt:     aws.String(time.Now().Format(time.RFC3339)),
			UpdatedAt:     aws.String(time.Now().Format(time.RFC3339)),
			Severity:      &types.Severity{Label: types.SeverityLabel(severity)},
			Title:         aws.String(fmt.Sprintf("Trivy found a vulnerability in %s/%s related to %s", ImageName, Container, vulnerabilities.VulnerabilityID)),
			Description:   aws.String(description),
			Remediation: &types.Remediation{
				Recommendation: &types.Recommendation{
					Text: aws.String("Upgrade to version " + vulnerabilities.FixedVersion),
					Url:  aws.String(vulnerabilities.PrimaryLink),
				},
			},
			ProductFields: map[string]string{"Product Name": "Trivy"},
			Resources: []types.Resource{
				{
					Type:      aws.String("Container"),
					Id:        aws.String(ImageName),
					Partition: types.PartitionAws,
					Region:    aws.String(AWSRegion),
					Details: &types.ResourceDetails{
						Other: map[string]string{
							"Container Image":   ImageName,
							"CVE ID":            vulnerabilities.VulnerabilityID,
							"CVE Title":         vulnerabilities.Title,
							"PkgName":           vulnerabilities.Resource,
							"Installed Package": vulnerabilities.InstalledVersion,
							"Patched Package":   vulnerabilities.FixedVersion,
							"NvdCvssScoreV3":    fmt.Sprintf("%f", tools.GetVulnScore(vulnerabilities)),
							"NvdCvssVectorV3":   "",
						},
					},
				},
			},
			RecordState: types.RecordStateActive,
		})
	}

	return findings, err
}

// Import findings to AWS Security Hub in batches of 100
func importFindingsToSecurityHub(findings []types.AwsSecurityFinding) error {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("unable to load SDK config: %v", err)
	}

	client := securityhub.NewFromConfig(cfg)

	batchSize := 100
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}

		batch := findings[i:end]

		input := &securityhub.BatchImportFindingsInput{
			Findings: batch,
		}

		// Call BatchImportFindings API
		_, err := client.BatchImportFindings(context.TODO(), input)
		if err != nil {
			return fmt.Errorf("error importing findings to Security Hub: %v", err)
		}
	}

	log.Printf("%d Findings imported to Security Hub", len(findings))
	return nil
}

func main() {
	r := mux.NewRouter()

	// Define route
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Printf("Error writing response: %v", err)
		}

	}).Methods("GET")

	r.HandleFunc("/trivy-webhook", ProcessTrivyWebhook).Methods("POST")

	// Start the server
	port := ":8080"
	fmt.Println("Starting server on port", port)
	log.Fatal(http.ListenAndServe(port, r))
}
