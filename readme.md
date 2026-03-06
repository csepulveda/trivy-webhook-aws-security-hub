
# Trivy Webhook AWS Security Hub

This application processes vulnerability reports from **Trivy**, a vulnerability scanning tool for containers, and imports the findings into **AWS Security Hub**. It acts as a webhook receiver that listens for vulnerability reports sent by Trivy and processes them before forwarding the results to AWS Security Hub.

## Features

- Receives vulnerability reports via an HTTP POST request.
- Supports importing CVE findings into **AWS Security Hub**.
- Designed for integration with **container image scanning** and **Kubernetes environments**.
- Selectively process different types of reports using **configurable environment variables**.
- Logs and reports errors for easier troubleshooting.

## How It Works

1. **Vulnerability Report**: The application listens for incoming vulnerability reports in JSON format from Trivy via a `/trivy-webhook` endpoint.
2. **Validation**: The incoming report is validated based on its type (e.g., `VulnerabilityReport`, `ConfigAuditReport`).
3. **AWS Security Hub Integration**: Vulnerabilities and other security findings are imported into AWS Security Hub.
4. **Health Check**: The `/healthz` endpoint provides a simple health check for the application.

## Prerequisites

- **AWS Account**: This application uses AWS Security Hub to store and manage security findings, so you must have an active AWS account and the necessary permissions.
- **Trivy**: You must set up Trivy to scan container images and send reports to the webhook endpoint.
- **Go**: The application is written in Go, so you'll need Go installed to build and run it.
- **Security Hub Product Subscription**: You must accept findings from `Aqua Security: Aqua Security` in AWS Security Hub. This allows the application to import findings into Security Hub.

## Setup and Installation

### 1. Clone the repository

```bash
git clone https://github.com/csepulveda/trivy-webhook-aws-security-hub.git
cd trivy-webhook-aws-security-hub
```

### 2. Build the application

Make sure Go is installed and set up correctly:

```bash
go mod tidy
go build -o trivy-webhook-aws-security-hub
```

### 3. Run the application

Start the application locally:

```bash
./trivy-webhook-aws-security-hub
```

The server will start and listen on port `8080`.

### 4. Set up Trivy to send reports

Configure Trivy to send vulnerability reports to the `/trivy-webhook` endpoint of the running application.

Example:

```bash
trivy image --format json --output result.json <image>
curl -X POST -H "Content-Type: application/json" --data @result.json http://localhost:8080/trivy-webhook
```

## ⚙️ Environment Variables

| Variable Name                          | Description                                                                   | Default |
| -------------------------------------- | ----------------------------------------------------------------------------- | ------- |
| `INFRA_ASSESSMENT_ENABLE`              | Enable processing of InfraAssessmentReport                                    | `false` |
| `CONFIG_AUDIT_ENABLE`                  | Enable processing of ConfigAuditReport                                        | `false` |
| `CLUSTER_COMPLIANCE_ENABLE`            | Enable processing of ClusterComplianceReport                                  | `false` |
| `VULNERABILITY_ENABLE`                 | Enable processing of VulnerabilityReport                                      | `true`  |
| `INCLUDE_ACCOUNT_ID_IN_FINDING_ID`     | Include AWS Account ID in the finding ID to ensure uniqueness across accounts | `false` |
| `AWS_ACCESS_KEY_ID`                    | AWS Access Key (standard AWS SDK var)                                         | *N/A*   |
| `AWS_SECRET_ACCESS_KEY`                | AWS Secret Key (standard AWS SDK var)                                         | *N/A*   |
| `AWS_REGION`                           | AWS Region where Security Hub is enabled                                      | *N/A*   |

Example configuration:

```yaml
env:
  - name: INFRA_ASSESSMENT_ENABLE
    value: "true"
  - name: CONFIG_AUDIT_ENABLE
    value: "true"
  - name: CLUSTER_COMPLIANCE_ENABLE
    value: "true"
  - name: VULNERABILITY_ENABLE
    value: "true"
```

## API Endpoints

| Method | Path             | Description                                      |
|-------|------------------|--------------------------------------------------|
| POST  | `/trivy-webhook`  | Receives vulnerability or security reports and imports them to AWS Security Hub. |
| GET   | `/healthz`        | Health check endpoint that returns `OK`.        |

## Example Vulnerability Report (from Trivy)

```json
{
  "kind": "VulnerabilityReport",
  "metadata": {
    "name": "example",
    "labels": {
      "trivy-operator.container.name": "example-container"
    }
  },
  "report": {
    "registry": {
      "server": "docker.io"
    },
    "artifact": {
      "repository": "library/nginx",
      "digest": "sha256:exampledigest"
    },
    "vulnerabilities": [
      {
        "vulnerabilityID": "CVE-2021-12345",
        "title": "Example Vulnerability",
        "severity": "HIGH",
        "resource": "nginx",
        "installedVersion": "1.18.0",
        "fixedVersion": "1.19.0",
        "primaryLink": "https://example.com/CVE-2021-12345"
      }
    ]
  }
}
```

## 📦 Helm Chart

To deploy this application on Kubernetes, a Helm chart is included in the `charts/` directory.

```bash
helm install trivy-webhook charts/trivy-webhook-aws-security-hub
```

## 🚀 Contributing

We welcome contributions! Please follow the standard GitHub workflow: Fork, branch, commit, push, and open a pull request.

## 📜 License

Licensed under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for details.
