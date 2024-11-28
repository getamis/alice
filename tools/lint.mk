ENV_GOPATH ?= $(shell go env GOPATH)
GOTOOL_GOPATH ?= $(shell echo "$(ENV_GOPATH)" | awk '{n=split($$1, a, ":"); print a[n]}')
GOLINTER ?= $(GOTOOL_GOPATH)/bin/golangci-lint
GOLINTER_VERSION := v1.62.0

# install go-linter
PHONY += install-golinter
install-golinter:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOTOOL_GOPATH)/bin $(GOLINTER_VERSION)

# run go-linter
PHONY += lint
lint:
	GOMAXPROCS=4 $(GOLINTER) run --timeout 5m
