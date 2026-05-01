#!/usr/bin/env bash
# E2E test in Minikube:
#
#   1. Verify Minikube is running
#   2. Build images and deploy the service + mock in Minikube
#   3. Install trivy-operator CRDs and create sample VulnerabilityReport
#      and ConfigAuditReport objects in the cluster
#   4. Read the CRDs from the cluster and send them to the webhook (simulating
#      what trivy-operator would do when calling the webhook)
#   5. Validate that mock Security Hub received all expected findings
#   6. Clean up everything: CRDs, mock, webhook, namespace
#
# Usage:
#   ./hack/minikube-e2e.sh           # run the full test
#   ./hack/minikube-e2e.sh --cleanup # clean up without running tests
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="trivy-e2e"
RELEASE="trivy-webhook"
WEBHOOK_IMAGE="trivy-webhook-aws-security-hub:e2e"
MOCK_IMAGE="trivy-mock-security-hub:e2e"
MOCK_SVC_URL="http://mock-security-hub:4566"   # cluster-internal URL

# ── 1. VERIFY MINIKUBE ────────────────────────────────────────────────────────
if ! minikube status 2>/dev/null | grep -q "Running"; then
  echo ""
  echo "ERROR: Minikube is not running."
  echo ""
  echo "  Start it with:  minikube start --cpus=2 --memory=4096"
  echo "  Then run:       ./hack/minikube-e2e.sh"
  echo ""
  exit 1
fi

# Force kubectl and helm to use ONLY the Minikube context.
# This prevents accidentally deploying to real clusters (staging/prod).
KUBECONFIG="$(mktemp)"
export KUBECONFIG
minikube update-context
echo "Active context: $(kubectl config current-context)"

# ── Utility functions ──────────────────────────────────────────────────────────

wait_for_url() {
  local url=$1 label=$2 timeout=${3:-30}
  echo -n "  Waiting for $label..."
  for i in $(seq 1 "$timeout"); do
    if curl -sf "$url" > /dev/null 2>&1; then
      echo " ready."
      return 0
    fi
    sleep 1
    echo -n "."
  done
  echo ""
  echo "ERROR: $label did not respond within $timeout seconds ($url)"
  return 1
}

cleanup() {
  echo ""
  echo "=== [6/5] Cleanup ==="
  kill "$WH_PF" "$MOCK_PF" 2>/dev/null || true
  helm uninstall "$RELEASE" -n "$NAMESPACE" 2>/dev/null || true
  kubectl delete ns "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  rm -f "$KUBECONFIG"
  echo "Cleanup complete."
}

if [[ "${1:-}" == "--cleanup" ]]; then
  cleanup
  exit 0
fi
trap cleanup EXIT

# Point Docker to Minikube's daemon so images are available inside the cluster
eval "$(minikube docker-env)"

# ── 2. BUILD AND DEPLOY ───────────────────────────────────────────────────────

echo ""
echo "=== [2/5] Building images ==="

echo "  Building webhook..."
docker build -t "$WEBHOOK_IMAGE" "$ROOT" -q

echo "  Building mock Security Hub..."
docker build -t "$MOCK_IMAGE" -f - "$ROOT" -q <<'DOCKERFILE'
FROM golang:1.26-alpine3.22 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o mock-server ./tests/mock-security-hub/
FROM alpine:3.22
WORKDIR /app
COPY --from=builder /app/mock-server .
EXPOSE 4566
ENTRYPOINT ["./mock-server"]
DOCKERFILE

echo "  Images built."

echo ""
echo "=== [2/5] Deploying in Minikube ==="

kubectl create ns "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Deploy mock Security Hub
kubectl apply -n "$NAMESPACE" -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mock-security-hub
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mock-security-hub
  template:
    metadata:
      labels:
        app: mock-security-hub
    spec:
      containers:
      - name: mock
        image: $MOCK_IMAGE
        imagePullPolicy: Never
        env:
        - name: MOCK_PORT
          value: "4566"
        - name: MOCK_ACCOUNT_ID
          value: "123456789012"
        - name: MOCK_REGION
          value: eu-central-1
        ports:
        - containerPort: 4566
        readinessProbe:
          httpGet:
            path: /healthz
            port: 4566
          initialDelaySeconds: 2
          periodSeconds: 3
---
apiVersion: v1
kind: Service
metadata:
  name: mock-security-hub
  namespace: $NAMESPACE
spec:
  selector:
    app: mock-security-hub
  ports:
  - port: 4566
    targetPort: 4566
EOF

kubectl wait --for=condition=ready pod -l app=mock-security-hub \
  -n "$NAMESPACE" --timeout=60s

# Deploy webhook via Helm pointing to the mock
helm upgrade --install "$RELEASE" "$ROOT/charts/trivy-webhook-aws-security-hub" \
  --namespace "$NAMESPACE" \
  --set image.repository="${WEBHOOK_IMAGE%:*}" \
  --set image.tag="e2e" \
  --set image.pullPolicy=Never \
  --set config.AWS_REGION=eu-central-1 \
  --set config.VULNERABILITY_ENABLE=true \
  --set config.CONFIG_AUDIT_ENABLE=true \
  --set "extraenvs[0].name=AWS_ACCESS_KEY_ID" \
  --set "extraenvs[0].value=test" \
  --set "extraenvs[1].name=AWS_SECRET_ACCESS_KEY" \
  --set "extraenvs[1].value=test" \
  --set "extraenvs[2].name=AWS_ENDPOINT_URL" \
  --set "extraenvs[2].value=$MOCK_SVC_URL" \
  --wait --timeout=60s

echo "  Deploy OK."

# Port-forward to localhost so the test can access both services
WEBHOOK_SVC=$(kubectl get svc -n "$NAMESPACE" \
  -l "app.kubernetes.io/instance=$RELEASE" \
  -o jsonpath='{.items[0].metadata.name}')

kubectl port-forward "svc/$WEBHOOK_SVC" 8080:80 -n "$NAMESPACE" > /dev/null 2>&1 &
WH_PF=$!
kubectl port-forward svc/mock-security-hub 4566:4566 -n "$NAMESPACE" > /dev/null 2>&1 &
MOCK_PF=$!

wait_for_url "http://localhost:8080/healthz" "webhook" 30
wait_for_url "http://localhost:4566/healthz"  "mock Security Hub" 30

# ── 3. CREATE CRDs IN THE CLUSTER ─────────────────────────────────────────────

echo ""
echo "=== [3/5] Installing trivy-operator CRDs and creating sample objects ==="

# Minimal CRDs defined inline: no network dependency, works offline.
# They only define the group/version/kind needed for kubectl to accept
# the objects — no full validation schema to keep the test simple.
kubectl apply -f - <<'EOF'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: vulnerabilityreports.aquasecurity.github.io
spec:
  group: aquasecurity.github.io
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        x-kubernetes-preserve-unknown-fields: true
  scope: Namespaced
  names:
    plural: vulnerabilityreports
    singular: vulnerabilityreport
    kind: VulnerabilityReport
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: configauditreports.aquasecurity.github.io
spec:
  group: aquasecurity.github.io
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        x-kubernetes-preserve-unknown-fields: true
  scope: Namespaced
  names:
    plural: configauditreports
    singular: configauditreport
    kind: ConfigAuditReport
EOF

echo "  CRDs installed."

# Create VulnerabilityReport objects in the cluster using sample data
kubectl apply -n "$NAMESPACE" -f - <<'EOF'
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  name: replicaset-nginx-7c9d
  namespace: trivy-e2e
  labels:
    trivy-operator.container.name: nginx
    trivy-operator.resource.kind: ReplicaSet
    trivy-operator.resource.name: nginx-7c9d
report:
  registry:
    server: docker.io
  artifact:
    repository: library/nginx
    tag: "1.25.0"
    digest: "sha256:abc123def456"
  vulnerabilities:
  - vulnerabilityID: CVE-2023-44487
    resource: nghttp2
    installedVersion: "1.52.0"
    fixedVersion: "1.57.0"
    severity: HIGH
    title: "HTTP/2 Rapid Reset Attack"
    description: "Denial of service via request cancellation resetting many streams."
    primaryLink: "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"
    score: 7.5
  - vulnerabilityID: CVE-2023-5678
    resource: openssl
    installedVersion: "3.0.8"
    fixedVersion: "3.0.12"
    severity: MEDIUM
    title: "OpenSSL DH key generation issue"
    description: "Generating excessively long X9.42 DH keys may be very slow."
    primaryLink: "https://nvd.nist.gov/vuln/detail/CVE-2023-5678"
    score: 5.3
  - vulnerabilityID: CVE-2024-0001
    resource: zlib
    installedVersion: "1.2.13"
    fixedVersion: ""
    severity: LOW
    title: "zlib heap buffer overflow"
    description: ""
    primaryLink: "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
    score: 3.1
  summary:
    criticalCount: 0
    highCount: 1
    mediumCount: 1
    lowCount: 1
    unknownCount: 0
  updateTimestamp: "2026-01-01T00:00:00Z"
EOF

kubectl apply -n "$NAMESPACE" -f - <<'EOF'
apiVersion: aquasecurity.github.io/v1alpha1
kind: ConfigAuditReport
metadata:
  name: replicaset-nginx-7c9d
  namespace: trivy-e2e
  ownerReferences:
  - apiVersion: apps/v1
    kind: ReplicaSet
    name: nginx-7c9d
    uid: abc123
report:
  checks:
  - checkID: KSV001
    title: Process can elevate its own privileges
    severity: MEDIUM
    description: A program inside the container can elevate its own privileges.
    remediation: Set allowPrivilegeEscalation to false in the container SecurityContext.
    messages:
    - "Container 'nginx' should set allowPrivilegeEscalation to false"
    success: false
  - checkID: KSV003
    title: Default capabilities not dropped
    severity: LOW
    description: The container should drop all default capabilities.
    remediation: Add ALL to securityContext.capabilities.drop.
    messages:
    - "Container 'nginx' should drop all capabilities"
    success: false
  - checkID: KSV014
    title: Root filesystem is not read-only
    severity: HIGH
    description: An immutable root filesystem prevents malicious binaries in PATH.
    remediation: Change readOnlyRootFilesystem to true.
    messages:
    - "Container 'nginx' should set readOnlyRootFilesystem to true"
    success: false
  summary:
    criticalCount: 0
    highCount: 1
    mediumCount: 1
    lowCount: 1
    unknownCount: 0
  updateTimestamp: "2026-01-01T00:00:00Z"
EOF

echo "  CRDs created in Minikube:"
kubectl get vulnerabilityreports,configauditreports -n "$NAMESPACE"

# ── 4. SEND CRDs TO THE WEBHOOK ───────────────────────────────────────────────

echo ""
echo "=== [4/5] Reading CRDs from cluster and sending to webhook ==="
echo "  (simulates the call that trivy-operator would make to the webhook)"

# Read the VulnerabilityReport from the cluster as JSON and send it
echo "  -> VulnerabilityReport (3 CVEs)..."
kubectl get vulnerabilityreport replicaset-nginx-7c9d \
  -n "$NAMESPACE" -o json | \
  curl -sf -X POST http://localhost:8080/trivy-webhook \
    -H "Content-Type: application/json" \
    -d @-
echo " sent."

# Read the ConfigAuditReport from the cluster as JSON and send it
echo "  -> ConfigAuditReport (3 checks)..."
kubectl get configauditreport replicaset-nginx-7c9d \
  -n "$NAMESPACE" -o json | \
  curl -sf -X POST http://localhost:8080/trivy-webhook \
    -H "Content-Type: application/json" \
    -d @-
echo " sent."

sleep 2

# ── 5. VALIDATE FINDINGS IN THE MOCK ──────────────────────────────────────────

echo ""
echo "=== [5/5] Validating findings in mock Security Hub ==="

FINDINGS_JSON=$(curl -sf http://localhost:4566/mock/findings)
COUNT=$(echo "$FINDINGS_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

echo "  Findings received: $COUNT"
echo ""
echo "$FINDINGS_JSON" | python3 -c "
import sys, json
findings = json.load(sys.stdin)
for f in findings:
    sev = f.get('Severity', {}).get('Label', '?')
    fid = f.get('Id', '?')
    print(f'  [{sev:12s}] {fid}')
"
echo ""

EXPECTED=6  # 3 CVEs + 3 config checks
if [[ "$COUNT" -lt "$EXPECTED" ]]; then
  echo "FAIL: expected at least $EXPECTED findings, got $COUNT"
  exit 1
fi

# Verify expected CVEs are present
for cve in CVE-2023-44487 CVE-2023-5678 CVE-2024-0001; do
  if ! echo "$FINDINGS_JSON" | grep -q "$cve"; then
    echo "FAIL: $cve not found in findings"
    exit 1
  fi
  echo "  ✓ $cve present"
done

for check in KSV001 KSV003 KSV014; do
  if ! echo "$FINDINGS_JSON" | grep -q "$check"; then
    echo "FAIL: $check not found in findings"
    exit 1
  fi
  echo "  ✓ $check present"
done

echo ""
echo "E2E test passed: $COUNT/$EXPECTED findings verified end-to-end in Minikube."
