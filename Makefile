IMAGE ?= trivy-webhook-aws-security-hub
TAG   ?= dev

.PHONY: test build integration-test e2e-test check

## Run unit tests
test:
	go test ./... -count=1

## Build Docker image locally (required before any push/merge)
build:
	docker build -t $(IMAGE):$(TAG) .
	@echo "Image built: $(IMAGE):$(TAG)"

## Run unit tests + Docker build (required gate before pushing)
check: test build

## Run full integration tests (mock Security Hub + webhook binary)
integration-test:
	./hack/integration-test.sh

## Run full E2E test in Minikube
e2e-test:
	./hack/minikube-e2e.sh

## Tear down integration environment
integration-clean:
	./hack/integration-test.sh --cleanup

## Tear down E2E environment
e2e-clean:
	./hack/minikube-e2e.sh --cleanup
