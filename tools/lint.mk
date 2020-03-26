ENV_GOPATH ?= $(shell go env GOPATH)
GOTOOL_GOPATH ?= $(shell echo "$(ENV_GOPATH)" | awk '{n=split($$1, a, ":"); print a[n]}')
GOLINT ?= $(GOTOOL_GOPATH)/bin/golangci-lint

# lint
$(GOLINT):
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(GOTOOL_GOPATH)/bin v1.24.0

PHONY += lint
lint: $(GOLINT)
	$(GOLINT) run --deadline 5m

