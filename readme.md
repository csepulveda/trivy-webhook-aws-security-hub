
# Trivy Webhook AWS Security Hub

A webhook receiver that processes security reports from [Trivy Operator](https://github.com/aquasecurity/trivy-operator) and imports the findings into [AWS Security Hub](https://aws.amazon.com/security-hub/).

## How It Works

1. Trivy Operator scans workloads and generates reports (`VulnerabilityReport`, `ConfigAuditReport`, etc.)
2. Trivy Operator calls this webhook's `/trivy-webhook` endpoint with the report payload
3. The webhook maps the findings to the [AWS Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) and imports them via `BatchImportFindings`

## Prerequisites

- An AWS account with Security Hub enabled
- The **Aqua Security** product integration enabled in Security Hub — **this must be done before deploying the webhook**, otherwise all imports will fail with `AccessDeniedException`:
  ```bash
  aws securityhub enable-import-findings-for-product \
    --product-arn arn:aws:securityhub:<region>::product/aquasecurity/aquasecurity \
    --region <region>
  ```
- An IAM role with `securityhub:BatchImportFindings` permission, associated to the webhook pod via [IRSA](#iam-setup-irsa)
- Trivy Operator installed in your Kubernetes cluster

## Deployment Scenarios

### Single account, single cluster

The simplest setup. The webhook sends findings directly to Security Hub in the same account and region where the cluster runs.

```
EKS Cluster ──→ Security Hub (same account, same region)
```

No additional configuration needed beyond the prerequisites. `CLUSTER_NAME` is optional.

```bash
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=us-east-1 \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/trivy-webhook
```

---

### Single account, multiple clusters

When multiple clusters share the same account, the same CVE in the same workload produces identical finding IDs — Security Hub uses the `Id` field as a deduplication key, so findings from different clusters overwrite each other.

**Set `CLUSTER_NAME` on each deployment** to make finding IDs unique and traceable to their origin:

```
EKS Cluster dev  ──→ Security Hub (account 123456789012)
EKS Cluster prod ──→ Security Hub (account 123456789012)
```

```bash
# dev cluster
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=us-east-1 \
  --set config.CLUSTER_NAME=dev \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/trivy-webhook

# prod cluster
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=us-east-1 \
  --set config.CLUSTER_NAME=prod \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/trivy-webhook
```

`CLUSTER_NAME` is included in the finding `Id` and in `ProductFields`, so you can filter findings by cluster in Security Hub.

---

### Multi-account, multiple clusters with AWS Organizations integration

The recommended architecture for organizations with multiple AWS accounts. Each webhook instance sends findings to **its own account's Security Hub** — never cross-account. The AWS Organizations integration with a delegated administrator account handles aggregation centrally.

```
Account A / Cluster A ──→ Security Hub (Account A)  ──┐
Account B / Cluster B ──→ Security Hub (Account B)  ──┤──→ Delegated administrator account
Account C / Cluster C ──→ Security Hub (Account C)  ──┘     (central visibility)
```

Each account must have the Aqua Security product enabled (see Prerequisites). The delegated administrator account natively shows the `AwsAccountId` and region of every finding, so **`INCLUDE_ACCOUNT_ID_IN_FINDING_ID` is not needed** in this setup. Use `CLUSTER_NAME` if multiple clusters exist within the same account:

```bash
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=us-east-1 \
  --set config.CLUSTER_NAME=prod-cluster \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/trivy-webhook
```

**AWS Organizations integration setup** (one-time, run from the management account):

```bash
# Designate a delegated administrator account for Security Hub
aws securityhub enable-organization-admin-account \
  --admin-account-id <delegated-administrator-account-id>

# From the delegated administrator account, enable auto-enrollment for new member accounts
aws securityhub update-organization-configuration \
  --auto-enable \
  --auto-enable-standards DEFAULT

# Optionally configure a finding aggregator to consolidate findings across regions
aws securityhub create-finding-aggregator \
  --region-linking-type ALL_REGIONS
```

See the [AWS Security Hub with AWS Organizations documentation](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-accounts-orgs.html) for the full setup guide.

---

## IAM Setup (IRSA)

Create an IAM role with the following minimum policy and associate it to the webhook's service account via IRSA:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "securityhub:BatchImportFindings",
    "Resource": "*"
  }]
}
```

```bash
# 1. Associate the OIDC provider with your cluster (if not already done)
eksctl utils associate-iam-oidc-provider \
  --cluster <cluster-name> --region <region> --approve

# 2. Create the IAM role with the appropriate trust policy for your cluster's OIDC provider
#    (see https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html)

# 3. Deploy the webhook referencing that role
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=<region> \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::<account-id>:role/<role-name>
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `VULNERABILITY_ENABLE` | Process `VulnerabilityReport` | `true` |
| `CONFIG_AUDIT_ENABLE` | Process `ConfigAuditReport` | `true` |
| `INFRA_ASSESSMENT_ENABLE` | Process `InfraAssessmentReport` | `true` |
| `CLUSTER_COMPLIANCE_ENABLE` | Process `ClusterComplianceReport` | `true` |
| `CLUSTER_NAME` | Cluster identifier included in finding IDs and `ProductFields` — required when multiple clusters share the same account to prevent finding ID collisions | `""` |
| `INCLUDE_ACCOUNT_ID_IN_FINDING_ID` | Prefix finding IDs with the AWS Account ID. Supported but not recommended — when using the AWS Organizations integration, the delegated administrator account already shows `AwsAccountId` and region natively for every finding | `false` |
| `AWS_REGION` | AWS region where Security Hub is enabled | — |
| `AWS_ACCESS_KEY_ID` | AWS access key (standard SDK env var) | — |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key (standard SDK env var) | — |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/trivy-webhook` | Receives Trivy Operator report payloads |
| `GET` | `/healthz` | Health check — returns `OK` |

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
