# AIrtg snmp-poller - builds.
#
#   make              vet, format check and tests, then cross-build every
#                     platform into dist/ (same as `make all`)
#   make dist         cross-build every platform, without the checks
#   make build        build for this machine: ./snmp-poller
#   make check        vet, format check and tests
#   make package      dist, then release archives and SHA256SUMS in dist/
#   make clean        remove dist/ and ./snmp-poller
#
# Binaries are static (CGO_ENABLED=0) and carry the version of the VERSION
# file and the git commit (snmp-poller -version). A new version in VERSION
# pushed to main makes CI create the tag v<version> and its GitHub release.

BINARY    := snmp-poller
PKG       := ./cmd/snmp-poller
DIST      := dist
VERSION   ?= $(shell cat VERSION 2>/dev/null || echo dev)
COMMIT    ?= $(shell git describe --always --dirty --exclude '*' 2>/dev/null || echo unknown)
LDFLAGS   := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GO        ?= go
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64

os   = $(word 1,$(subst /, ,$1))
arch = $(word 2,$(subst /, ,$1))
ext  = $(if $(filter windows,$(call os,$1)),.exe)
out  = $(DIST)/$(BINARY)-$(call os,$1)-$(call arch,$1)$(call ext,$1)

.DEFAULT_GOAL := all
.PHONY: all dist package build check test vet fmt-check clean help $(PLATFORMS)

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

# One archive per platform: the binary, etc/ (configuration and conf.d),
# README.md and LICENSE, in a snmp-poller-<version>-<os>-<arch> directory;
# .zip for Windows, .tar.gz otherwise. Files come from the git commit, not
# the working tree, so local edits or encrypted credentials never ship.
package: dist ## Release archives (binary, etc/, README, LICENSE) and SHA256SUMS in dist/
	@set -e; rm -rf $(DIST)/pkg; \
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		name=$(BINARY)-$(VERSION)-$$os-$$arch; dir=$(DIST)/pkg/$$name; \
		mkdir -p $$dir; \
		git archive HEAD etc README.md LICENSE | tar -x -C $$dir; \
		cp $(DIST)/$(BINARY)-$$os-$$arch$$ext $$dir/$(BINARY)$$ext; \
		if [ $$os = windows ]; then \
			rm -f $(DIST)/$$name.zip; (cd $(DIST)/pkg && zip -qr ../$$name.zip $$name); \
		else \
			tar -C $(DIST)/pkg -czf $(DIST)/$$name.tar.gz $$name; \
		fi; \
		echo "packaged $$name"; \
	done; \
	rm -rf $(DIST)/pkg; \
	cd $(DIST) && { command -v sha256sum >/dev/null && sha256sum *.tar.gz *.zip || shasum -a 256 *.tar.gz *.zip; } > SHA256SUMS
	@echo "wrote $(DIST)/SHA256SUMS"

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
