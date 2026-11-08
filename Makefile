# AIrtg SNMP Poller - builds.
#
#   make              vet, format check and tests, then cross-build every
#                     platform into dist/ (same as `make all`)
#   make dist         cross-build every platform, without the checks
#   make build        build for this machine: ./snmp-poller
#   make check        vet, format check and tests
#   make clean        remove dist/ and ./snmp-poller
#
# Binaries are static (CGO_ENABLED=0) and carry the version from
# `git describe` (override with `make VERSION=1.2.3`).

BINARY    := snmp-poller
PKG       := ./cmd/snmp-poller
DIST      := dist
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
GO        ?= go
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64

os   = $(word 1,$(subst /, ,$1))
arch = $(word 2,$(subst /, ,$1))
ext  = $(if $(filter windows,$(call os,$1)),.exe)
out  = $(DIST)/$(BINARY)-$(call os,$1)-$(call arch,$1)$(call ext,$1)

.DEFAULT_GOAL := all
.PHONY: all dist build check test vet fmt-check clean help $(PLATFORMS)

# The checks run once, on this machine, before any binary is built: a
# failure stops the build. Make runs prerequisites in order unless -j is
# given, so the recursive call keeps "checks first" true with -j too.
all: check ## Checks, then cross-build every platform into dist/
	@$(MAKE) --no-print-directory dist

dist: $(PLATFORMS) ## Cross-build every platform into dist/, without the checks

$(PLATFORMS):
	CGO_ENABLED=0 GOOS=$(call os,$@) GOARCH=$(call arch,$@) \
		$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(call out,$@) $(PKG)
	@echo "built $(call out,$@)"

build: ## Build for this machine: ./snmp-poller
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY)$(if $(filter windows,$(shell $(GO) env GOOS)),.exe) $(PKG)

check: vet fmt-check test ## Vet, format check and tests

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt-check:
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "not gofmt'ed:"; echo "$$files"; exit 1; fi

clean: ## Remove build outputs
	rm -rf $(DIST) $(BINARY) $(BINARY).exe

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
