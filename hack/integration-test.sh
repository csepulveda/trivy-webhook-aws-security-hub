#!/usr/bin/env bash
# Full local integration test:
#   1. Starts LocalStack (mock Security Hub)
#   2. Starts the webhook binary pointing to LocalStack
#   3. Runs Go integration tests that POST sample Trivy CRD payloads
#
# Usage:
#   ./hack/integration-test.sh              # run all integration tests
#   ./hack/integration-test.sh --cleanup    # tear everything down
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBHOOK_PID_FILE="/tmp/trivy-webhook.pid"
COMPOSE_FILE="$ROOT/docker-compose.integration.yml"

cleanup() {
  echo "--- Cleaning up ---"
  if [[ -f "$WEBHOOK_PID_FILE" ]]; then
    kill "$(cat "$WEBHOOK_PID_FILE")" 2>/dev/null || true
    rm -f "$WEBHOOK_PID_FILE"
  fi
  docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
  echo "Done."
}

if [[ "${1:-}" == "--cleanup" ]]; then
  cleanup
  exit 0
fi

trap cleanup EXIT

# ── Step 1: unit tests ──────────────────────────────────────────────
echo "=== Unit tests ==="
cd "$ROOT"
go test ./... -count=1
echo "Unit tests passed."

# ── Step 2: Docker image build ──────────────────────────────────────
echo "=== Docker build ==="
IMAGE="trivy-webhook-aws-security-hub:integration-test"
docker build -t "$IMAGE" "$ROOT"
echo "Docker build OK: $IMAGE"

# ── Step 3: Start LocalStack ─────────────────────────────────────────
echo "=== Starting LocalStack ==="
docker compose -f "$COMPOSE_FILE" up -d
echo "Waiting for LocalStack..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:4566/_localstack/health > /dev/null 2>&1; then
    echo "LocalStack ready."
    break
  fi
  sleep 2
done

# Enable Security Hub in LocalStack (ignore "already enabled" errors)
aws --endpoint-url http://localhost:4566 \
  securityhub enable-security-hub \
  --region eu-central-1 2>/dev/null || true

# ── Step 4: Start the webhook binary ─────────────────────────────────
echo "=== Starting webhook ==="
go build -o /tmp/trivy-webhook-bin "$ROOT/main.go"

AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=test \
AWS_DEFAULT_REGION=eu-central-1 \
AWS_ENDPOINT_URL=http://localhost:4566 \
VULNERABILITY_ENABLE=true \
CONFIG_AUDIT_ENABLE=true \
INFRA_ASSESSMENT_ENABLE=false \
CLUSTER_COMPLIANCE_ENABLE=false \
  /tmp/trivy-webhook-bin > /tmp/trivy-webhook.log 2>&1 &

echo $! > "$WEBHOOK_PID_FILE"
echo "Webhook PID: $(cat $WEBHOOK_PID_FILE)"

echo "Waiting for webhook /healthz..."
for i in $(seq 1 15); do
  if curl -sf http://localhost:8080/healthz > /dev/null 2>&1; then
    echo "Webhook ready."
    break
  fi
  sleep 1
done

# ── Step 5: Run integration tests ─────────────────────────────────────
echo "=== Integration tests ==="
INTEGRATION=true go test ./tests/integration/... -v -count=1 -timeout 60s

echo ""
echo "All tests passed."
