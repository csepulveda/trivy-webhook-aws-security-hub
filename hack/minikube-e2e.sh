#!/usr/bin/env bash
# E2E test in Minikube:
#
#   1. Verifica que Minikube esté corriendo
#   2. Construye las imágenes y despliega el servicio + mock en Minikube
#   3. Instala los CRDs de trivy-operator y crea objetos VulnerabilityReport
#      y ConfigAuditReport de ejemplo en el cluster
#   4. Lee los CRDs desde el cluster y los envía al webhook (simulando
#      lo que haría trivy-operator al llamar el webhook)
#   5. Valida que el mock Security Hub recibió todos los findings esperados
#   6. Limpia todo: CRDs, mock, webhook, namespace
#
# Uso:
#   ./hack/minikube-e2e.sh           # correr el test completo
#   ./hack/minikube-e2e.sh --cleanup # limpiar sin correr tests
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="trivy-e2e"
RELEASE="trivy-webhook"
WEBHOOK_IMAGE="trivy-webhook-aws-security-hub:e2e"
MOCK_IMAGE="trivy-mock-security-hub:e2e"
MOCK_SVC_URL="http://mock-security-hub:4566"   # URL interna al cluster

# ── 1. VERIFICAR MINIKUBE ─────────────────────────────────────────────────────
if ! minikube status 2>/dev/null | grep -q "Running"; then
  echo ""
  echo "ERROR: Minikube no está corriendo."
  echo ""
  echo "  Inícialo con:  minikube start --cpus=2 --memory=4096"
  echo "  Luego ejecuta: ./hack/minikube-e2e.sh"
  echo ""
  exit 1
fi

# Fuerza kubectl y helm a usar SOLO el contexto de Minikube.
# Esto evita deployar accidentalmente en clusters reales (staging/prod).
KUBECONFIG="$(mktemp)"
export KUBECONFIG
minikube update-context
echo "Contexto activo: $(kubectl config current-context)"

# ── Funciones de utilidad ──────────────────────────────────────────────────────

wait_for_url() {
  local url=$1 label=$2 timeout=${3:-30}
  echo -n "  Esperando $label..."
  for i in $(seq 1 "$timeout"); do
    if curl -sf "$url" > /dev/null 2>&1; then
      echo " listo."
      return 0
    fi
    sleep 1
    echo -n "."
  done
  echo ""
  echo "ERROR: $label no respondió en $timeout segundos ($url)"
  return 1
}

cleanup() {
  echo ""
  echo "=== [6/5] Limpieza ==="
  kill "$WH_PF" "$MOCK_PF" 2>/dev/null || true
  helm uninstall "$RELEASE" -n "$NAMESPACE" 2>/dev/null || true
  kubectl delete ns "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  rm -f "$KUBECONFIG"
  echo "Limpieza completa."
}

if [[ "${1:-}" == "--cleanup" ]]; then
  cleanup
  exit 0
fi
trap cleanup EXIT

# Apunta Docker al daemon de Minikube para que las imágenes queden dentro del cluster
eval "$(minikube docker-env)"

# ── 2. BUILD Y DEPLOY ─────────────────────────────────────────────────────────

echo ""
echo "=== [2/5] Build de imágenes ==="

echo "  Construyendo webhook..."
docker build -t "$WEBHOOK_IMAGE" "$ROOT" -q

echo "  Construyendo mock Security Hub..."
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

echo "  Imágenes OK."

echo ""
echo "=== [2/5] Deploy en Minikube ==="

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

# Deploy webhook via Helm apuntando al mock
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

# Port-forwards al localhost para que el test pueda acceder
WEBHOOK_SVC=$(kubectl get svc -n "$NAMESPACE" \
  -l "app.kubernetes.io/instance=$RELEASE" \
  -o jsonpath='{.items[0].metadata.name}')

kubectl port-forward "svc/$WEBHOOK_SVC" 8080:80 -n "$NAMESPACE" > /dev/null 2>&1 &
WH_PF=$!
kubectl port-forward svc/mock-security-hub 4566:4566 -n "$NAMESPACE" > /dev/null 2>&1 &
MOCK_PF=$!

wait_for_url "http://localhost:8080/healthz" "webhook" 30
wait_for_url "http://localhost:4566/healthz"  "mock Security Hub" 30

# ── 3. CREAR CRDs EN EL CLUSTER ───────────────────────────────────────────────

echo ""
echo "=== [3/5] Instalando CRDs de trivy-operator y creando objetos de ejemplo ==="

# CRDs mínimos incluidos inline: sin dependencia de red, funciona offline.
# Solo definen el grupo/versión/kind necesarios para que kubectl acepte
# los objetos — sin validation schema completo para simplificar el test.
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

echo "  CRDs instalados."

# Crea objetos VulnerabilityReport en el cluster usando los fixtures
# (convertimos el JSON del fixture a un objeto Kubernetes aplicable)
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

echo "  CRDs creados en Minikube:"
kubectl get vulnerabilityreports,configauditreports -n "$NAMESPACE"

# ── 4. ENVIAR CRDs AL WEBHOOK ─────────────────────────────────────────────────

echo ""
echo "=== [4/5] Leyendo CRDs del cluster y enviando al webhook ==="
echo "  (simula la llamada que haría trivy-operator al webhook)"

# Lee el VulnerabilityReport desde el cluster como JSON y lo envía
echo "  → VulnerabilityReport (3 CVEs)..."
kubectl get vulnerabilityreport replicaset-nginx-7c9d \
  -n "$NAMESPACE" -o json | \
  curl -sf -X POST http://localhost:8080/trivy-webhook \
    -H "Content-Type: application/json" \
    -d @-
echo " enviado."

# Lee el ConfigAuditReport desde el cluster como JSON y lo envía
echo "  → ConfigAuditReport (3 checks)..."
kubectl get configauditreport replicaset-nginx-7c9d \
  -n "$NAMESPACE" -o json | \
  curl -sf -X POST http://localhost:8080/trivy-webhook \
    -H "Content-Type: application/json" \
    -d @-
echo " enviado."

sleep 2

# ── 5. VALIDAR FINDINGS EN EL MOCK ────────────────────────────────────────────

echo ""
echo "=== [5/5] Validando findings en mock Security Hub ==="

FINDINGS_JSON=$(curl -sf http://localhost:4566/mock/findings)
COUNT=$(echo "$FINDINGS_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

echo "  Findings recibidos: $COUNT"
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
  echo "FALLO: se esperaban al menos $EXPECTED findings, se recibieron $COUNT"
  exit 1
fi

# Verifica que los CVEs esperados están presentes
for cve in CVE-2023-44487 CVE-2023-5678 CVE-2024-0001; do
  if ! echo "$FINDINGS_JSON" | grep -q "$cve"; then
    echo "FALLO: no se encontró $cve en los findings"
    exit 1
  fi
  echo "  ✓ $cve presente"
done

for check in KSV001 KSV003 KSV014; do
  if ! echo "$FINDINGS_JSON" | grep -q "$check"; then
    echo "FALLO: no se encontró $check en los findings"
    exit 1
  fi
  echo "  ✓ $check presente"
done

echo ""
echo "E2E test exitoso: $COUNT/$EXPECTED findings verificados end-to-end en Minikube."
