SHELL := /bin/sh

GO ?= go
NPM ?= npm
GOCACHE ?= $(CURDIR)/.cache/go-build
CONSOLE_DIR := apps/release-console
VERSION ?= 0.1.0-p0
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf 'development')
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

BUILDINFO_PACKAGE := xminds-release-platform/internal/platform/buildinfo
LDFLAGS := -s -w \
	-X '$(BUILDINFO_PACKAGE).version=$(VERSION)' \
	-X '$(BUILDINFO_PACKAGE).commit=$(COMMIT)' \
	-X '$(BUILDINFO_PACKAGE).buildTime=$(BUILD_TIME)'
GO_FILES := $(shell find apps internal scripts tests -type f -name '*.go' 2>/dev/null)

.PHONY: fmt fmt-check lint golangci test test-integration build boundary-check metadata-check console-install console-lint console-typecheck console-test console-build console-e2e console-verify verify clean

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	@unformatted="$$(gofmt -l $(GO_FILES))"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files require formatting:\n%s\n' "$$unformatted" >&2; \
		exit 1; \
	fi

lint: fmt-check
	GOCACHE="$(GOCACHE)" $(GO) vet ./...

golangci:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo 'golangci-lint v2 is required for this target' >&2; \
		exit 1; \
	}
	golangci-lint config verify
	golangci-lint run

test:
	GOCACHE="$(GOCACHE)" $(GO) test ./... -race -count=1

test-integration:
	@test -n "$$XMINDS_RELEASE_TEST_DATABASE_URL" || { \
		echo 'XMINDS_RELEASE_TEST_DATABASE_URL is required' >&2; \
		exit 1; \
	}
	GOCACHE="$(GOCACHE)" $(GO) test ./tests/integration -race -count=1 -v

build:
	mkdir -p bin
	GOCACHE="$(GOCACHE)" $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/release-api ./apps/release-api
	GOCACHE="$(GOCACHE)" $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/release-worker ./apps/release-worker
	GOCACHE="$(GOCACHE)" $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/breach-corpus ./scripts/breach-corpus

boundary-check:
	./scripts/check-boundaries.sh

metadata-check:
	./scripts/check-macos-metadata.sh

console-install:
	cd $(CONSOLE_DIR) && $(NPM) ci

console-lint:
	cd $(CONSOLE_DIR) && $(NPM) run lint

console-typecheck:
	cd $(CONSOLE_DIR) && $(NPM) run typecheck

console-test:
	cd $(CONSOLE_DIR) && $(NPM) run test:run

console-build:
	cd $(CONSOLE_DIR) && $(NPM) run build

console-e2e:
	cd $(CONSOLE_DIR) && $(NPM) run e2e

console-verify: console-lint console-typecheck console-test console-build

verify: lint test build boundary-check metadata-check console-verify

clean:
	$(GO) clean -cache -testcache
	rm -rf bin .cache coverage
