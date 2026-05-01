#!/usr/bin/env bash
# Full E2E test in Minikube:
#   1. Starts Minikube + LocalStack inside the cluster
#   2. Installs the Helm chart pointing to mock Security Hub
#   3. Applies sample Trivy VulnerabilityReport CRDs manually
#   4. Posts the CRD payloads to the webhook (simulating trivy-operator)
#   5. Verifies findings appear in mock Security Hub
#
# Prerequisites: minikube, helm, kubectl, docker
#
# Usage:
#   ./hack/minikube-e2e.sh
#   ./hack/minikube-e2e.sh --cleanup
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="trivy-test"
RELEASE="trivy-webhook"
IMAGE="trivy-webhook-aws-security-hub:e2e"

cleanup() {
  echo "--- E2E cleanup ---"
  helm uninstall "$RELEASE" -n "$NAMESPACE" 2>/dev/null || true
  kubectl delete ns "$NAMESPACE" 2>/dev/null || true
  kubectl delete ns localstack 2>/dev/null || true
  echo "Done."
}

if [[ "${1:-}" == "--cleanup" ]]; then
  cleanup
  exit 0
fi

# ── Start Minikube ───────────────────────────────────────────────────
if ! minikube status | grep -q "Running"; then
  echo "=== Starting Minikube ==="
  minikube start --cpus=2 --memory=4096
fi

eval "$(minikube docker-env)"

# ── Build image into Minikube's Docker daemon ─────────────────────────
echo "=== Building image into Minikube ==="
docker build -t "$IMAGE" "$ROOT"

# ── Deploy LocalStack in Minikube ─────────────────────────────────────
echo "=== Deploying LocalStack in Minikube ==="
kubectl create ns localstack --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: localstack
  namespace: localstack
spec:
  replicas: 1
  selector:
    matchLabels:
      app: localstack
  template:
    metadata:
      labels:
        app: localstack
    spec:
      containers:
      - name: localstack
        image: localstack/localstack:3
        env:
        - name: SERVICES
          value: securityhub,sts
        - name: DEFAULT_REGION
          value: eu-central-1
        ports:
        - containerPort: 4566
---
apiVersion: v1
kind: Service
metadata:
  name: localstack
  namespace: localstack
spec:
  selector:
    app: localstack
  ports:
  - port: 4566
    targetPort: 4566
EOF

echo "Waiting for LocalStack pod..."
kubectl wait --for=condition=ready pod -l app=localstack -n localstack --timeout=60s

# Enable Security Hub via port-forward
kubectl port-forward svc/localstack 4566:4566 -n localstack &
PF_PID=$!
sleep 3
aws --endpoint-url http://localhost:4566 securityhub enable-security-hub --region eu-central-1 2>/dev/null || true
kill $PF_PID 2>/dev/null || true

LOCALSTACK_URL="http://localstack.localstack.svc.cluster.local:4566"

# ── Install webhook via Helm ──────────────────────────────────────────
echo "=== Installing webhook Helm chart ==="
kubectl create ns "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install "$RELEASE" "$ROOT/charts/trivy-webhook-aws-security-hub" \
  --namespace "$NAMESPACE" \
  --set image.repository="$IMAGE" \
  --set image.tag="latest" \
  --set image.pullPolicy=Never \
  --set config.AWS_REGION=eu-central-1 \
  --set config.VULNERABILITY_ENABLE=true \
  --set config.CONFIG_AUDIT_ENABLE=true \
  --set "extraenvs[0].name=AWS_ACCESS_KEY_ID" \
  --set "extraenvs[0].value=test" \
  --set "extraenvs[1].name=AWS_SECRET_ACCESS_KEY" \
  --set "extraenvs[1].value=test" \
  --set "extraenvs[2].name=AWS_ENDPOINT_URL" \
  --set "extraenvs[2].value=$LOCALSTACK_URL"

echo "Waiting for webhook pod..."
kubectl wait --for=condition=ready pod -l "app.kubernetes.io/name=trivy-webhook-aws-security-hub" \
  -n "$NAMESPACE" --timeout=60s

# ── Port-forward the webhook ──────────────────────────────────────────
kubectl port-forward svc/"$RELEASE-trivy-webhook-aws-security-hub" 8080:80 -n "$NAMESPACE" &
WH_PF_PID=$!
trap "kill $WH_PF_PID 2>/dev/null || true" EXIT
sleep 3

# ── Health check ──────────────────────────────────────────────────────
echo "=== Webhook health check ==="
curl -sf http://localhost:8080/healthz
echo " OK"

# ── POST sample CRD payloads (simulating trivy-operator webhook) ──────
echo "=== Posting VulnerabilityReport ==="
curl -sf -X POST http://localhost:8080/trivy-webhook \
  -H "Content-Type: application/json" \
  -d @"$ROOT/tests/integration/fixtures/vulnerability-report.json"
echo " sent"

echo "=== Posting ConfigAuditReport ==="
curl -sf -X POST http://localhost:8080/trivy-webhook \
  -H "Content-Type: application/json" \
  -d @"$ROOT/tests/integration/fixtures/config-audit-report.json"
echo " sent"

sleep 2

# ── Verify findings in LocalStack ─────────────────────────────────────
echo "=== Checking findings in Security Hub (LocalStack) ==="
kubectl port-forward svc/localstack 4567:4566 -n localstack &
LS_PF_PID=$!
trap "kill $WH_PF_PID $LS_PF_PID 2>/dev/null || true" EXIT
sleep 2

FINDINGS=$(AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:4567 \
  securityhub get-findings --region eu-central-1 \
  --output json | jq '.Findings | length')

echo "Findings imported to Security Hub: $FINDINGS"

if [[ "$FINDINGS" -lt 3 ]]; then
  echo "ERROR: expected at least 3 findings, got $FINDINGS"
  exit 1
fi

echo ""
echo "E2E test passed. $FINDINGS findings verified in mock Security Hub."
