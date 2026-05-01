# trivy-webhook-aws-security-hub

A webhook receiver that processes security reports from [Trivy Operator](https://github.com/aquasecurity/trivy-operator) and imports the findings into [AWS Security Hub](https://aws.amazon.com/security-hub/).

## How It Works

1. Trivy Operator scans workloads and generates reports (`VulnerabilityReport`, `ConfigAuditReport`, `InfraAssessmentReport`, `ClusterComplianceReport`).
2. Trivy Operator calls this webhook's `/trivy-webhook` endpoint with the report payload.
3. The webhook maps each finding to the [AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) and imports it via `BatchImportFindings`.

## Prerequisites

- AWS account with [Security Hub](https://aws.amazon.com/security-hub/) enabled.
- The **Aqua Security** product integration enabled in Security Hub — **must be done before deploying**, otherwise all imports will fail with `AccessDeniedException`:
  ```bash
  aws securityhub enable-import-findings-for-product \
    --product-arn arn:aws:securityhub:<region>::product/aquasecurity/aquasecurity \
    --region <region>
  ```
- Kubernetes cluster with [Trivy Operator](https://github.com/aquasecurity/trivy-operator) installed.
- [Helm](https://helm.sh/) ≥ 3.
- IAM role with `securityhub:BatchImportFindings` permission, associated via [IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html).

## Installation

```bash
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=eu-central-1 \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/trivy-webhook
```

Then point Trivy Operator at the webhook:

```bash
helm upgrade trivy-operator aquasecurity/trivy-operator \
  --set operator.webhookBroadcastURL=http://trivy-webhook.default/trivy-webhook
```

Replace `trivy-webhook.default` with `<release-name>.<namespace>` matching your installation.

## Configuration

### App settings (`config` block)

| Parameter | Description | Default |
|---|---|---|
| `config.AWS_REGION` | AWS region where Security Hub is enabled | `eu-central-1` |
| `config.VULNERABILITY_ENABLE` | Process `VulnerabilityReport` | `"true"` |
| `config.CONFIG_AUDIT_ENABLE` | Process `ConfigAuditReport` | `"false"` |
| `config.INFRA_ASSESSMENT_ENABLE` | Process `InfraAssessmentReport` | `"false"` |
| `config.CLUSTER_COMPLIANCE_ENABLE` | Process `ClusterComplianceReport` | `"false"` |
| `config.INCLUDE_ACCOUNT_ID_IN_FINDING_ID` | Prefix finding IDs with the AWS account ID — recommended in multi-account Security Hub organizations | `"false"` |
| `config.CLUSTER_NAME` | Cluster identifier included in finding IDs and `ProductFields` — required when multiple clusters share the same account to prevent finding ID collisions | `""` |

### Extra environment variables

Use `extraenvs` to pass additional env vars (e.g. static credentials or endpoint overrides):

```yaml
extraenvs:
  - name: AWS_ACCESS_KEY_ID
    value: AKIAIOSFODNN7EXAMPLE
  - name: AWS_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: aws-credentials
        key: secret-access-key
```

### Common parameters

| Parameter | Description | Default |
|---|---|---|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Docker image repository | `ghcr.io/csepulveda/trivy-webhook-aws-security-hub` |
| `image.tag` | Image tag (defaults to chart `appVersion`) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `nameOverride` | Override release name | `""` |
| `fullnameOverride` | Override full release name | `""` |
| `imagePullSecrets` | List of image pull secrets | `[]` |

### Service account

| Parameter | Description | Default |
|---|---|---|
| `serviceAccount.create` | Create a ServiceAccount | `true` |
| `serviceAccount.automount` | Auto-mount API credentials | `true` |
| `serviceAccount.annotations` | Annotations (e.g. IRSA role ARN) | `{}` |
| `serviceAccount.name` | Name (auto-generated if empty) | `""` |

### Pod settings

| Parameter | Description | Default |
|---|---|---|
| `podAnnotations` | Extra pod annotations | `{}` |
| `podLabels` | Extra pod labels | `{}` |
| `podSecurityContext` | Pod-level security context | `{}` |
| `securityContext` | Container-level security context | `{}` |
| `resources.limits` | Container resource limits | `{}` |
| `resources.requests` | Container resource requests | `{}` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `volumes` | Additional volumes | `[]` |
| `volumeMounts` | Additional volume mounts | `[]` |

### Service

| Parameter | Description | Default |
|---|---|---|
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `80` |

### Probes

| Parameter | Description | Default |
|---|---|---|
| `livenessProbe.httpGet.path` | Liveness probe path | `/healthz` |
| `livenessProbe.httpGet.port` | Liveness probe port | `http` |
| `readinessProbe.httpGet.path` | Readiness probe path | `/healthz` |
| `readinessProbe.httpGet.port` | Readiness probe port | `http` |

### Autoscaling

| Parameter | Description | Default |
|---|---|---|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `1` |
| `autoscaling.maxReplicas` | Maximum replicas | `2` |
| `autoscaling.targetCPUUtilizationPercentage` | CPU target | `80` |

## IAM permissions

Minimum IAM policy required:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "securityhub:BatchImportFindings",
      "Resource": "*"
    }
  ]
}
```

The recommended approach is to use [IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) (IAM Roles for Service Accounts) via `serviceAccount.annotations`:

```bash
helm install trivy-webhook oci://ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub \
  --set config.AWS_REGION=eu-central-1 \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/trivy-webhook
```

## License

Licensed under the [GNU General Public License v3.0](https://github.com/csepulveda/trivy-webhook-aws-security-hub/blob/main/LICENSE).
