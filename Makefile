.PHONY: all build build-pcap build-ebpf build-release build-pcap-release build-ebpf-release test test-ebpf lint clean

GO ?= go

all: build test

# ── Build ────────────────────────────────────────────────────────────
build:
	$(GO) build -o bin/sipvault-agent ./cmd/sipvault-agent

build-pcap:
	$(GO) build -tags pcap -o bin/sipvault-agent-pcap ./cmd/sipvault-agent

# eBPF backend: pure-Go cBPF socket filter + AF_PACKET raw socket.
# No CGO, no libpcap, no clang/llvm at build time.
build-ebpf:
	$(GO) build -tags ebpf -o bin/sipvault-agent-ebpf ./cmd/sipvault-agent

build-release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o bin/sipvault-agent-linux-amd64 ./cmd/sipvault-agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags="-s -w" -o bin/sipvault-agent-linux-arm64 ./cmd/sipvault-agent

# pcap builds require libpcap-dev and CGO
build-pcap-release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 $(GO) build -tags pcap -ldflags="-s -w" -o bin/sipvault-agent-pcap-linux-amd64 ./cmd/sipvault-agent

# eBPF release: Linux-only, no CGO needed. Both arches.
build-ebpf-release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -tags ebpf -ldflags="-s -w" -o bin/sipvault-agent-ebpf-linux-amd64 ./cmd/sipvault-agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -tags ebpf -ldflags="-s -w" -o bin/sipvault-agent-ebpf-linux-arm64 ./cmd/sipvault-agent

# ── Test ─────────────────────────────────────────────────────────────
test:
	$(GO) test -race ./...

test-ebpf:
	$(GO) test -tags ebpf ./...

# ── Lint ─────────────────────────────────────────────────────────────
lint:
	golangci-lint run ./...

# ── Clean ────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
