GO       ?= go
BIN      := bin/bkd
PKG      := github.com/mrbuttshooter/securecrt
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X $(PKG)/internal/config.Version=$(VERSION)

.PHONY: all build web test test-race integration lint sec vuln fmt tidy clean run

all: build

## build: compile the static bkd binary, embedding the frontend if it is built
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/bkd

## web: build the frontend and stage it for embedding
##
## The output is copied into internal/web/dist because //go:embed cannot reach
## outside its own package directory.
web:
	cd web && pnpm install --frozen-lockfile && pnpm build
	rm -rf internal/web/dist
	cp -r web/dist internal/web/dist
	@# Restore the tracked placeholder that "rm -rf" above removed. Without
	@# it a clean checkout has no internal/web/dist directory, and //go:embed
	@# is a compile-time directive — the package would not build at all.
	@printf '%s\n' \
		'# Keeps this directory present in a fresh checkout.' \
		'#' \
		'# internal/web/web.go embeds it with //go:embed, which is a compile-time' \
		'# directive: without the directory the package does not build, so' \
		'# "go build ./..." would fail on a clone that had not run "make web".' \
		'#' \
		'# The built frontend is copied here by "make web" and is not committed.' \
		> internal/web/dist/.gitkeep

## release: frontend then binary, which is what a deployable build needs
release: web build

## test: unit tests on both database backends
##
## The two drivers differ in placeholder syntax, type affinity and foreign key
## enforcement, so a suite that only runs one of them misses real bugs.
## BKD_TEST_POSTGRES_DSN selects the backend; unset means SQLite.
test:
	@echo "--- sqlite ---"
	@BKD_TEST_POSTGRES_DSN= $(GO) test ./... -count=1
	@if [ -n "$$BKD_TEST_POSTGRES_DSN" ]; then \
		echo "--- postgres ---"; \
		$(GO) test ./... -count=1; \
	else \
		echo "--- postgres: skipped (set BKD_TEST_POSTGRES_DSN to enable) ---"; \
	fi

## test-race: unit tests under the race detector
test-race:
	$(GO) test ./... -race -count=1

## integration: tests requiring a live Postgres / SSH server
integration:
	$(GO) test ./... -tags=integration -count=1

## e2e: browser tests against a freshly provisioned instance
##
## Requires "make release" first, since it drives the real binary with the
## frontend embedded.
e2e:
	./scripts/e2e.sh

## fmt: format all Go sources
fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

## tidy: sync go.mod/go.sum
tidy:
	$(GO) mod tidy

## sec: static security analysis
sec:
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

## vuln: known-vulnerability scan
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

## run: build and run against ./deploy/config.example.yaml
run: build
	./$(BIN) serve --config deploy/config.example.yaml

clean:
	rm -rf bin dist web/dist coverage.out
