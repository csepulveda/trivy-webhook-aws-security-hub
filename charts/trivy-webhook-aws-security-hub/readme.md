
# Trivy Webhook for AWS Security Hub

This application integrates [Trivy](https://github.com/aquasecurity/trivy), a popular container vulnerability scanning tool, with [AWS Security Hub](https://aws.amazon.com/security-hub/). It acts as a webhook receiver that listens for vulnerability reports sent by Trivy and imports the findings into AWS Security Hub, enabling centralized vulnerability management for container images in your AWS environment.

## Features
- **Webhook Receiver**: Accepts vulnerability reports in JSON format from Trivy.
- **AWS Security Hub Integration**: Automatically imports container vulnerabilities as findings into AWS Security Hub.
- **Seamless Kubernetes Integration**: Works with the Trivy Operator in Kubernetes for automated vulnerability scans.

## Prerequisites
- AWS account with [Security Hub](https://aws.amazon.com/security-hub/) enabled.
- Kubernetes cluster with [Trivy Operator](https://github.com/aquasecurity/trivy-operator) installed.
- [Helm](https://helm.sh/) installed for deployment.
- IAM role created with access to AWS Security Hub or set the AWS env Variables.

## How to Install
Add the Helm repository:

```bash
helm repo add trivy-webhook-aws-security-hub https://csepulveda.github.io/trivy-webhook-aws-security-hub/
```

Install the Helm chart:

```bash
helm install trivy-webhook trivy-webhook-aws-security-hub/trivy-webhook-aws-security-hub \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::xxx:role/trivy-webhook-aws-security-hub-role"
```

- Replace `arn:aws:iam::xxx:role/trivy-webhook-aws-security-hub-role` with your actual IAM role ARN.
- The IAM role should have permissions to write findings into AWS Security Hub.

### Explanation:
- The `serviceAccount.annotations` sets the necessary IAM role for the service to access AWS resources securely.
- By specifying `eks.amazonaws.com/role-arn`, the Trivy webhook can assume the specified IAM role and import vulnerability findings into Security Hub.

## ⚙️ Configuration

All configuration is done via `values.yaml` or `--set` in the Helm CLI.

### Common Parameters

| Name                      | Description                                                   | Type      | Default   |
|--------------------------|---------------------------------------------------------------|-----------|-----------|
| `replicaCount`            | Number of trivy-webhook replicas                             | `integer` | `1`       |
| `image.repository`        | Docker image repository                                      | `string`  | `ghcr.io/csepulveda/trivy-webhook-aws-security-hub` |
| `image.pullPolicy`        | Image pull policy                                            | `string`  | `IfNotPresent` |
| `image.tag`               | Image tag (defaults to chart's AppVersion)                   | `string`  | `""`      |
| `imagePullSecrets`        | List of image pull secrets                                   | `list`    | `[]`      |
| `nameOverride`            | Override for the release name                                | `string`  | `""`      |
| `fullnameOverride`        | Override for full release name                               | `string`  | `""`      |

---

### App Configuration (`config` block)

| Name                                      | Description                                                                   | Default         |
|-------------------------------------------|-------------------------------------------------------------------------------|-----------------|
| `config.AWS_REGION`                       | AWS region for Security Hub                                                   | `eu-central-1`  |
| `config.INFRA_ASSESSMENT_ENABLE`          | Enable Infra Assessment report processing                                     | `"false"`       |
| `config.CONFIG_AUDIT_ENABLE`              | Enable Config Audit report processing                                         | `"false"`       |
| `config.CLUSTER_COMPLIANCE_ENABLE`        | Enable Cluster Compliance report processing                                   | `"false"`       |
| `config.VULNERABILITY_ENABLE`             | Enable Vulnerability report processing                                        | `"true"`        |
| `config.INCLUDE_ACCOUNT_ID_IN_FINDING_ID` | Include AWS Account ID in the finding ID to ensure uniqueness across accounts | `"true"`        |
> These environment variables control what types of Trivy reports are processed and sent to AWS Security Hub.

---

### Extra Environment Variables

| Name             | Description                                | Type  | Default |
|------------------|--------------------------------------------|-------|---------|
| `extraenvs`      | List of additional environment variables   | `list`| `[]`    |

---

### Kubernetes & Pod Settings

| Name                      | Description                                                   | Type     | Default   |
|--------------------------|---------------------------------------------------------------|----------|-----------|
| `serviceAccount.create`   | Whether to create a ServiceAccount                           | `bool`   | `true`    |
| `serviceAccount.automount`| Auto-mount API credentials                                    | `bool`   | `true`    |
| `serviceAccount.annotations`| Annotations for the ServiceAccount                         | `object` | `{}`      |
| `serviceAccount.name`     | Name of the ServiceAccount (auto-generated if empty)         | `string` | `""`      |
| `podAnnotations`          | Pod annotations                                               | `object` | `{}`      |
| `podLabels`               | Pod labels                                                    | `object` | `{}`      |
| `podSecurityContext`      | Security context for pod                                      | `object` | `{}`      |
| `securityContext`         | Security context for container                               | `object` | `{}`      |
| `nodeSelector`            | Node selector for pod scheduling                             | `object` | `{}`      |
| `tolerations`             | Tolerations for pod scheduling                               | `list`   | `[]`      |
| `affinity`                | Affinity rules for pod scheduling                            | `object` | `{}`      |

---

### Service

| Name             | Description                                | Type   | Default   |
|------------------|--------------------------------------------|--------|-----------|
| `service.type`   | Kubernetes service type                    | `string`| `ClusterIP`|
| `service.port`   | Service port                               | `int`  | `80`      |

---

### Resources

| Name                   | Description                          | Type   | Default  |
|-----------------------|--------------------------------------|--------|----------|
| `resources.limits`     | Resource limits                      | `object`| `{}`    |
| `resources.requests`   | Resource requests                    | `object`| `{}`    |

---

### Probes

| Name                                 | Description                      | Type   | Default   |
|--------------------------------------|----------------------------------|--------|-----------|
| `livenessProbe.httpGet.path`          | Path for liveness probe          | `string`| `/healthz`|
| `livenessProbe.httpGet.port`          | Port for liveness probe          | `string`| `http`    |
| `readinessProbe.httpGet.path`         | Path for readiness probe         | `string`| `/healthz`|
| `readinessProbe.httpGet.port`         | Port for readiness probe         | `string`| `http`    |

---

### Autoscaling

| Name                                         | Description                          | Type    | Default |
|----------------------------------------------|--------------------------------------|---------|---------|
| `autoscaling.enabled`                        | Enable autoscaling                   | `bool`  | `false` |
| `autoscaling.minReplicas`                    | Minimum replicas                     | `int`   | `1`     |
| `autoscaling.maxReplicas`                    | Maximum replicas                     | `int`   | `2`     |
| `autoscaling.targetCPUUtilizationPercentage` | CPU target percentage                | `int`   | `80`    |

---

### Volumes and Mounts

| Name             | Description                                | Type  | Default |
|------------------|--------------------------------------------|-------|---------|
| `volumes`        | Additional volumes to mount                | `list`| `[]`    |
| `volumeMounts`   | Additional volume mounts for containers    | `list`| `[]`    |

## Setting Up Trivy Operator

To send vulnerability reports from the Trivy Operator to the webhook, configure the following setting in the `trivy-operator` Helm chart:

```bash
--set operator.webhookBroadcastURL=http://<service-name>.<namespace>/trivy-webhook
```

Example:

```bash
--set operator.webhookBroadcastURL=http://trivy-webhook-aws-security-hub.default/trivy-webhook
```

This ensures that the Trivy Operator sends its scan results to the Trivy webhook, which will then process and forward them to AWS Security Hub.

## How It Works

1. **Trivy Scan**: Trivy scans container images for vulnerabilities.
2. **Webhook**: The Trivy Operator sends the scan report to the Trivy Webhook via the `/trivy-webhook` endpoint.
3. **AWS Security Hub**: The webhook processes the report and imports the findings into AWS Security Hub, enabling centralized vulnerability management.

## Customization

You can customize various parameters of the Helm chart, such as:
- **ServiceAccount annotations** for IAM role-based access.
- **Replicas** to scale the webhook deployment.
- **Resource requests and limits** for container sizing.

For a full list of configurable values, refer to the `values.yaml` file in the Helm chart.

## License

This project is licensed under the GNU General Public License v3.0.
