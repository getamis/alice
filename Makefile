GO_TEST_COVER_MODE ?= atomic
GO_UNIT_TEST_TIMEOUT ?= 60m
SHELL := /bin/bash
TOOL_DIR := $(CURDIR)/tools
include $(wildcard $(TOOL_DIR)/*.mk)

PHONY += coverage.txt
coverage.txt:
	@echo "mode: $(GO_TEST_COVER_MODE)" > $@

PHONY += unit-test
unit-test: coverage.txt
	@for d in $$(go list ./...); do		\
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
