GO_TEST_COVER_MODE ?= atomic
GO_UNIT_TEST_TIMEOUT ?= 60m
SHELL := /bin/bash
TOOL_DIR := $(CURDIR)/tools
TOOL_BIN_DIR := $(TOOL_DIR)/bin
TOOL_TEMP_DIR := $(TOOL_DIR)/tmp
GOROOT := $(shell go env GOROOT)
DIRS := \
	$(TOOL_BIN_DIR) \
	$(TOOL_TEMP_DIR)
export PATH := $(TOOL_BIN_DIR):$(PATH)
include $(wildcard $(TOOL_DIR)/*.mk)

PROTOS := \
	**/*.proto

$(DIRS):
	mkdir -p $@

PHONY+= init
init: 
	git submodule init
	git submodule update

PHONY+= tools
tools: $(DIRS) $(PROTOC)
	@go install \
		google.golang.org/protobuf/cmd/protoc-gen-go 

PHONY += protobuf
protobuf:
	@for d in $$(find "crypto" -type f -name "*.proto"); do		\
		protoc -I$(GOPATH)/src --go_out=$(GOPATH)/src $(CURDIR)/$$d; \
	done;

PHONY += coverage.txt
coverage.txt:
	@echo "mode: $(GO_TEST_COVER_MODE)" > $@

PHONY += unit-test
unit-test: coverage.txt
	@for d in $$(go list ./... | grep -v example); do		\
		set -o pipefail;		\
		go test -timeout $(GO_UNIT_TEST_TIMEOUT) -v -coverprofile=profile.out -covermode=$(GO_TEST_COVER_MODE) $$d 2>&1;	\
		if [ $$? -eq 0 ]; then						\
			if [ -f profile.out ]; then				\
				tail -n +2 profile.out | grep -v .pb.go >> coverage.txt;		\
			fi							\
		else								\
			echo "\033[31mFAIL\033[0m:\t$$d";			\
			exit -1;						\
		fi								\
	done;

PHONY += tss-example
tss-example:
	cd example && go build

.PHONY: $(PHONY)
