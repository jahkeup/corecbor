SHELL := /bin/bash
.DEFAULT_GOAL := help

GO       := go
GOFUMPT  := $(GO) tool gofumpt

# Default fuzz time per registered target. Override on the command line:
#   make fuzz FUZZTIME=2m
FUZZTIME ?= 30s

.PHONY: help
help: ## show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage: make \033[36m<target>\033[0m\n\nTargets:\n"} \
	      /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: fmt
fmt: ## gofumpt -w across the tree
	$(GOFUMPT) -w .

.PHONY: fmt-check
fmt-check: ## fail if gofumpt would change anything (CI gate)
	@diff_files=$$($(GOFUMPT) -l .); \
	if [ -n "$$diff_files" ]; then \
		echo "ERROR: gofumpt formatting violations in:"; \
		echo "$$diff_files" | sed 's/^/  /'; \
		echo ""; \
		echo "Run 'make fmt' to fix."; \
		exit 1; \
	fi

.PHONY: vet
vet: ## go vet ./...
	$(GO) vet ./...

.PHONY: lint
lint: vet ## go vet always; golangci-lint enforced if on PATH (skipped if absent)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint $$(golangci-lint --version | head -1)"; \
		golangci-lint run --timeout 5m ./...; \
	else \
		echo "golangci-lint not on PATH; skipping (install: brew install golangci-lint)"; \
	fi

.PHONY: test
test: ## go test -race ./...
	$(GO) test -race ./...

.PHONY: bench
bench: ## run all benchmarks (root + sub-modules) with -benchmem
	$(GO) test -run NONE -bench . -benchmem ./...
	@for mod in $$(find . -mindepth 2 -name go.mod -printf '%h\n' | sort); do \
		echo ">>> benchmarks in $$mod"; \
		(cd "$$mod" && $(GO) test -run NONE -bench . -benchmem ./...) || exit 1; \
	done

.PHONY: fuzz
fuzz: ## run every registered Fuzz* target for FUZZTIME (default 30s)
	@targets=$$(grep -rEho 'func Fuzz[A-Z][A-Za-z0-9_]+' --include='*_test.go' . | awk '{print $$2}' | sort -u); \
	if [ -z "$$targets" ]; then \
		echo "no Fuzz* targets registered yet"; \
		exit 0; \
	fi; \
	for t in $$targets; do \
		echo ">>> $$t (fuzztime=$(FUZZTIME))"; \
		pkg=$$(grep -rEl "func $$t" --include='*_test.go' . | head -1 | xargs dirname); \
		$(GO) test -run NONE -fuzz "^$$t$$" -fuzztime $(FUZZTIME) "$$pkg" || exit 1; \
	done

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: check
check: fmt-check vet lint test ## CI-gating set: fmt-check + vet + lint + test

.PHONY: compat
compat: ## run cross-library compatibility tests (including user-provided payloads)
	@echo ">>> cross-library compatibility vectors (built-in)"
	$(GO) test -count=1 -run TestCompat -v ./... 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|PASS|FAIL|ok)" || true
	@echo ""
	@echo ">>> user-provided payload fixtures (testdata/compat/payloads/*.json)"
	@count=$$(find testdata/compat/payloads -name '*.json' 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$$count" -eq 0 ]; then \
		echo "  (no payload fixtures found — add .json files to testdata/compat/payloads/)"; \
	else \
		echo "  found $$count payload fixture(s)"; \
	fi
	$(GO) test -count=1 -run TestCompatPayloads -v . 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL)|PASS|FAIL|ok)" || true
	@echo ""
	@echo ">>> summary"
	$(GO) test -count=1 -run "TestCompat" . -json 2>/dev/null | \
		grep -c '"Test".*"Pass":true' 2>/dev/null || \
		$(GO) test -count=1 -run "TestCompat" . > /dev/null 2>&1 && echo "  all compatibility tests PASS" || echo "  FAILURES detected — run 'go test -run TestCompat -v .' for details"

.PHONY: clean
clean: ## remove build artifacts (does NOT touch testdata/fuzz corpora)
	$(GO) clean -testcache
	rm -f *.out *.prof *.cpu *.mem coverage.txt
