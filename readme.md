
# Trivy Webhook AWS Security Hub

A webhook receiver that processes security reports from [Trivy Operator](https://github.com/aquasecurity/trivy-operator) and imports the findings into [AWS Security Hub](https://aws.amazon.com/security-hub/).

## How It Works

1. Trivy Operator scans workloads and generates reports (`VulnerabilityReport`, `ConfigAuditReport`, etc.)
2. Trivy Operator calls this webhook's `/trivy-webhook` endpoint with the report payload
3. The webhook maps the findings to the [AWS Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) and imports them via `BatchImportFindings`

## Prerequisites

- An AWS account with Security Hub enabled
- The **Aqua Security** product integration accepted in Security Hub (`Aqua Security: Aqua Security`)
- AWS credentials with `securityhub:BatchImportFindings` permission
- Trivy Operator installed in your Kubernetes cluster

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `VULNERABILITY_ENABLE` | Process `VulnerabilityReport` | `true` |
| `CONFIG_AUDIT_ENABLE` | Process `ConfigAuditReport` | `true` |
| `INFRA_ASSESSMENT_ENABLE` | Process `InfraAssessmentReport` | `true` |
| `CLUSTER_COMPLIANCE_ENABLE` | Process `ClusterComplianceReport` | `true` |
| `INCLUDE_ACCOUNT_ID_IN_FINDING_ID` | Prefix finding IDs with the AWS Account ID — useful in multi-account Security Hub organizations where the same CVE can appear across member accounts | `false` |
| `AWS_REGION` | AWS region where Security Hub is enabled | — |
| `AWS_ACCESS_KEY_ID` | AWS access key (standard SDK env var) | — |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key (standard SDK env var) | — |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/trivy-webhook` | Receives Trivy Operator report payloads |
| `GET` | `/healthz` | Health check — returns `OK` |

## Deploy with Helm

```bash
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=eu-central-1 \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/trivy-webhook
```

Full values reference: [`charts/trivy-webhook-aws-security-hub/values.yaml`](charts/trivy-webhook-aws-security-hub/values.yaml)

## Development

### Requirements

| Tool | Version | Purpose |
|---|---|---|
| Go | ≥ 1.26 | Build and tests |
| Docker | any | Image build and E2E |
| Minikube | any | E2E tests only |
| Helm | ≥ 3 | E2E tests only |

### Testing pipeline

Before opening a PR, run the full local gate:

```bash
make check             # unit tests + docker build (required)
make integration-test  # end-to-end with mock Security Hub
make e2e-test          # full E2E in Minikube
```

The same tests run automatically in GitHub Actions on every PR.

#### Unit tests

Pure Go tests, no external dependencies:

```bash
go test ./... -count=1
```

#### Integration tests

Tests the full request lifecycle: webhook binary → mock Security Hub. No AWS account or external services needed.

```bash
./hack/integration-test.sh
```

The script starts a mock Security Hub server (`tests/mock-security-hub/`) that implements the real STS and Security Hub HTTP APIs, then runs Go tests that POST sample `VulnerabilityReport` and `ConfigAuditReport` payloads and assert the findings arrived correctly.

#### E2E tests in Minikube

Full end-to-end inside a real Kubernetes cluster:

```bash
minikube start --cpus=2 --memory=4096   # skip if already running
./hack/minikube-e2e.sh
```

The script:
1. Verifies Minikube is running (exits with instructions if not)
2. Builds both images into Minikube's Docker daemon
3. Deploys the webhook via Helm and the mock Security Hub as a Pod
4. Installs Trivy Operator CRDs and creates sample `VulnerabilityReport` / `ConfigAuditReport` objects
5. Reads those CRDs from the cluster and sends them to the webhook (simulating Trivy Operator's webhook call)
6. Verifies all expected findings (3 CVEs + 3 config checks) appear in the mock
7. Cleans up everything: CRDs, Pods, namespace

### Mock Security Hub

`tests/mock-security-hub/` is a standalone Go HTTP server that implements:

| Endpoint | Description |
|---|---|
| `POST /` | STS `GetCallerIdentity` — returns a fixed account ID |
| `POST /findings/import` | Security Hub `BatchImportFindings` — stores findings in memory |
| `GET /mock/findings` | Returns all captured findings (test helper) |
| `DELETE /mock/findings` | Clears findings between tests |
| `GET /healthz` | Health check |

Configure via env vars: `MOCK_PORT` (default `4566`), `MOCK_ACCOUNT_ID`, `MOCK_REGION`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow, coding guidelines, and release process.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
