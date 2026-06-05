# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Image URL to use all building/pushing image targets
IMG ?= webservice:latest

## Tool Binaries
KUBECTL ?= kubectl
KUBECTL-PAAS ?= $(LOCALBIN)/kubectl-paas
KIND ?= $(LOCALBIN)/kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize

## Tool Versions
KIND_VERSION ?= v0.30.0
KUSTOMIZE_VERSION ?= v5.7.0
KUBECTL-PAAS_VERSION ?= latest

.PHONY: kind
kind: $(KIND) ## Download kind locally if necessary.
$(KIND): $(LOCALBIN)
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: kubectl-paas
kubectl-paas: $(KUBECTL-PAAS) ## Download kustomize locally if necessary.
$(KUBECTL-PAAS): $(LOCALBIN)
	go build -mod=mod -o $(KUBECTL-PAAS) github.com/belastingdienst/opr-paas-cli/v2/cmd

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter & yamllint
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: test
test: fmt unittest vet

.PHONY: unittest
unittest: fmt gotest-coverage ## Run fmt, vet and tests with coverage.
	go test $$(go list ./... | grep -v /e2e) -coverprofile=./cover.out -coverpkg=./...

.PHONY: install-go-test-coverage
install-go-test-coverage:
	go install github.com/vladopajic/go-test-coverage/v2@latest

.PHONY: check-coverage
check-coverage: install-go-test-coverage unittest
	${GOTEST_COVERAGE} --config=./.testcoverage.yaml

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
GOTEST_COVERAGE = $(LOCALBIN)/go-test-coverage

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.5.0
GOTEST_COVERAGE_VERSION ?= latest

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: gotest-coverage
gotest-coverage: $(GOTEST_COVERAGE) ## Download go-test-coverage locally if necessary.
$(GOTEST_COVERAGE): $(LOCALBIN)
	$(call go-install-tool,$(GOTEST_COVERAGE),github.com/vladopajic/go-test-coverage/v2,$(GOTEST_COVERAGE_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: image-build
image-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: kind-image-load
kind-image-load: ## Build docker image with the manager.
	${KIND} load image-archive <(${CONTAINER_TOOL} save ${IMG})

.PHONY: refresh-kind
refresh-kind: kind kind-delete-cluster kind-create-cluster

.PHONY: kind-create-cluster
kind-create-cluster: kind
	$(KIND) create cluster

.PHONY: kind-delete-cluster
kind-delete-cluster: kind
	$(KIND) delete cluster || echo "no existing kind cluster"

.PHONY: stage-opr-paas
stage-opr-paas: kubectl-paas
	# First server-side apply creates the CRDs; the CRs (e.g. PaasConfig) fail here
	# because their CRDs are not established yet, so we ignore the error.
	${KUBECTL} apply --server-side -k test/e2e/manifests/opr-paas-stage/ || true
	# Wait for the CRDs to be established before re-applying so the CRs succeed.
	${KUBECTL} wait --for=condition=Established --timeout=60s \
		crd/paas.cpet.belastingdienst.nl \
		crd/paasconfig.cpet.belastingdienst.nl \
		crd/paasns.cpet.belastingdienst.nl
	# Second server-side apply now succeeds for the CRs.
	${KUBECTL} apply --server-side -k test/e2e/manifests/opr-paas-stage/
	${KUBECTL-PAAS} generate -o yaml | ${KUBECTL} apply -f -

.PHONY: deploy-webservice
deploy-webservice:
ifeq ($(CONTAINER_TOOL),podman)
	$(KUBECTL) apply -k test/e2e/manifests/local-e2e-podman
else
	$(KUBECTL) apply -k test/e2e/manifests/webservice
endif
	# Using server-side apply to support re-running and to avoid annotation size limits on CRDs
	# Wait a bit as the paas-context files rely on the previous deployed mocks
	${KUBECTL} wait --for=condition=Available deployment/opr-paas-webservice -n paas-system --timeout=120s

.PHONY: redeploy-webservice
redeploy-webservice:
	kubectl delete -n paas-system pod -l app.kubernetes.io/component=webservice --timeout=120s
	kubectl wait --for=condition=Available deployment/opr-paas-webservice -n paas-system --timeout=120s

.PHONY: setup-e2e
setup-e2e: refresh-kind stage-opr-paas image-build kind-image-load deploy-webservice

.PHONY: test-e2e
test-e2e:
	#go test -v ./test/e2e
