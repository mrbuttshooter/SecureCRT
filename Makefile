GO       ?= go
BIN      := bin/bkd
PKG      := github.com/mrbuttshooter/securecrt
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X $(PKG)/internal/config.Version=$(VERSION)

.PHONY: all build web test test-race integration lint sec vuln fmt tidy clean run

all: build

## build: compile the static bkd binary (embeds web/dist if present)
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/bkd

## web: build the React frontend into web/dist
web:
	cd web && pnpm install --frozen-lockfile && pnpm build

## test: unit tests
test:
	$(GO) test ./... -count=1

## test-race: unit tests under the race detector
test-race:
	$(GO) test ./... -race -count=1

## integration: tests requiring a live Postgres / SSH server
integration:
	$(GO) test ./... -tags=integration -count=1

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
