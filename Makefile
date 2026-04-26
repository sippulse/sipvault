.PHONY: all build build-pcap build-release build-pcap-release test lint clean

GO ?= go

all: build test

# ── Build ────────────────────────────────────────────────────────────
build:
	$(GO) build -o bin/sipvault-agent ./cmd/sipvault-agent

build-pcap:
	$(GO) build -tags pcap -o bin/sipvault-agent-pcap ./cmd/sipvault-agent

build-release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o bin/sipvault-agent-linux-amd64 ./cmd/sipvault-agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o bin/sipvault-agent-linux-arm64 ./cmd/sipvault-agent

# pcap builds require libpcap-dev and CGO
build-pcap-release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 $(GO) build -tags pcap -ldflags="-s -w" -o bin/sipvault-agent-pcap-linux-amd64 ./cmd/sipvault-agent

# ── Test ─────────────────────────────────────────────────────────────
test:
	$(GO) test -race ./...

# ── Lint ─────────────────────────────────────────────────────────────
lint:
	golangci-lint run ./...

# ── Clean ────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
