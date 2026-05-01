# Contributing

Thank you for your interest in contributing to `trivy-webhook-aws-security-hub`.

## Development setup

| Tool     | Version  | Purpose                        |
|----------|----------|--------------------------------|
| Go       | ≥ 1.26   | Build and unit tests           |
| Docker   | any      | Image build, integration tests |
| Minikube | any      | E2E tests only                 |
| Helm     | ≥ 3      | E2E tests only                 |

Clone the repository and verify the setup:

```bash
git clone https://github.com/csepulveda/trivy-webhook-aws-security-hub.git
cd trivy-webhook-aws-security-hub
make check   # unit tests + docker build
```

## Making changes

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. Make your changes. Keep commits focused — one logical change per commit.

3. Run the full local test gate before pushing:
   ```bash
   make check             # unit tests + docker build (required)
   make integration-test  # webhook binary + mock Security Hub
   make e2e-test          # full E2E in Minikube
   ```
   All three must pass. The same tests run automatically in CI on every PR.

4. Push your branch and open a pull request against `main`. Include in the PR description:
   - **What** changed and **why**
   - How you tested it (which test levels you ran)
   - Any relevant context for reviewers

## Testing levels

### Unit tests

Pure Go tests with no external dependencies:

```bash
go test ./... -count=1
```

### Integration tests

Tests the full request lifecycle against a mock Security Hub — no AWS account or external services needed:

```bash
make integration-test
# or directly:
./hack/integration-test.sh
```

The script compiles and runs a local mock server (`tests/mock-security-hub/`) that implements the real STS and Security Hub HTTP APIs, starts the webhook binary pointing at it, and runs Go integration tests that POST sample reports and assert the findings arrived correctly.

### E2E tests (Minikube)

Full end-to-end inside a real Kubernetes cluster:

```bash
minikube start --cpus=2 --memory=4096   # skip if already running
make e2e-test
# or directly:
./hack/minikube-e2e.sh
```

The script verifies Minikube is running, builds both images into Minikube's Docker daemon, deploys the webhook via Helm and the mock Security Hub as a pod, creates sample `VulnerabilityReport` and `ConfigAuditReport` objects, sends them to the webhook, and asserts that all 6 expected findings appear in the mock.

## Code guidelines

- No comments unless the **why** is non-obvious (hidden constraint, subtle invariant, workaround for a specific external bug).
- No half-finished implementations — if a feature isn't complete, don't merge it.
- Keep changes minimal and focused. Don't refactor or add abstractions beyond what the task requires.

## Release process (maintainers only)

Releases are fully automated by GitHub Actions. To cut a release:

1. Ensure all changes are merged to `main` and CI is green.
2. Create and push a semver tag:
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
3. The `release.yml` workflow triggers automatically and:
   - Builds and pushes the Docker image to `ghcr.io/csepulveda/trivy-webhook-aws-security-hub:<tag>`
   - Packages the Helm chart (overriding `version` and `appVersion` from the tag) and publishes it to the OCI registry at `ghcr.io/csepulveda/charts/trivy-webhook-aws-security-hub`
   - Creates a GitHub Release via `chart-releaser`

No manual Chart.yaml version bump is needed — the workflow derives the chart version from the git tag at package time.
