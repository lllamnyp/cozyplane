# Cozyplane — aggregated API server + controllers for the sdn.cozystack.io group.

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: generate
generate: ## Run code generation (deepcopy, conversion, defaults, openapi, clientset).
	hack/update-codegen.sh

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run Go unit tests.
	go test ./...

##@ Build

.PHONY: build
build: fmt vet ## Build all binaries.
	go build -o bin/cozyplane-apiserver ./cmd/apiserver
	go build -o bin/sdn-controller ./cmd/sdn-controller
	go build -o bin/cozyplane-responder ./cmd/responder
