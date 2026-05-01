#!/usr/bin/env bash
# Local integration test pipeline:
#   1. Unit tests
#   2. Docker image build
#   3. Start mock Security Hub (Go binary, no external deps)
#   4. Start the webhook binary pointing to the mock
#   5. Run Go integration tests
#
# Usage:
#   ./hack/integration-test.sh           # run everything
#   ./hack/integration-test.sh --cleanup # kill background processes
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_PID_FILE="/tmp/trivy-mock.pid"
WEBHOOK_PID_FILE="/tmp/trivy-webhook.pid"
MOCK_PORT=4566
WEBHOOK_PORT=8080

cleanup() {
  echo "--- Cleanup ---"
  [[ -f "$MOCK_PID_FILE" ]]    && kill "$(cat "$MOCK_PID_FILE")"    2>/dev/null || true
  [[ -f "$WEBHOOK_PID_FILE" ]] && kill "$(cat "$WEBHOOK_PID_FILE")" 2>/dev/null || true
  rm -f "$MOCK_PID_FILE" "$WEBHOOK_PID_FILE" /tmp/trivy-mock-bin /tmp/trivy-webhook-bin
}

if [[ "${1:-}" == "--cleanup" ]]; then cleanup; exit 0; fi
trap cleanup EXIT

cd "$ROOT"

# ── 1. Unit tests ─────────────────────────────────────────────────────────────
echo "=== [1/5] Unit tests ==="
go test ./... -count=1
echo "OK"

# ── 2. Docker image build ──────────────────────────────────────────────────────
echo "=== [2/5] Docker build ==="
docker build -t trivy-webhook-aws-security-hub:integration-test . -q
echo "OK"

# ── 3. Start mock Security Hub ─────────────────────────────────────────────────
echo "=== [3/5] Starting mock Security Hub on :$MOCK_PORT ==="
go build -o /tmp/trivy-mock-bin ./tests/mock-security-hub/

MOCK_PORT=$MOCK_PORT \
MOCK_ACCOUNT_ID=123456789012 \
MOCK_REGION=eu-central-1 \
  /tmp/trivy-mock-bin > /tmp/trivy-mock.log 2>&1 &
echo $! > "$MOCK_PID_FILE"

for i in $(seq 1 10); do
  curl -sf http://localhost:$MOCK_PORT/healthz > /dev/null 2>&1 && break || sleep 1
done
echo "Mock ready (PID $(cat $MOCK_PID_FILE))"

# ── 4. Start webhook binary ────────────────────────────────────────────────────
echo "=== [4/5] Starting webhook on :$WEBHOOK_PORT ==="
go build -o /tmp/trivy-webhook-bin .

AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=test \
AWS_DEFAULT_REGION=eu-central-1 \
AWS_ENDPOINT_URL=http://localhost:$MOCK_PORT \
VULNERABILITY_ENABLE=true \
CONFIG_AUDIT_ENABLE=true \
INFRA_ASSESSMENT_ENABLE=false \
CLUSTER_COMPLIANCE_ENABLE=false \
  /tmp/trivy-webhook-bin > /tmp/trivy-webhook.log 2>&1 &
echo $! > "$WEBHOOK_PID_FILE"

for i in $(seq 1 10); do
  curl -sf http://localhost:$WEBHOOK_PORT/healthz > /dev/null 2>&1 && break || sleep 1
done
echo "Webhook ready (PID $(cat $WEBHOOK_PID_FILE))"

# ── 5. Integration tests ───────────────────────────────────────────────────────
echo "=== [5/5] Integration tests ==="
INTEGRATION=true go test ./tests/integration/... -v -count=1 -timeout 60s

echo ""
echo "All integration tests passed."
