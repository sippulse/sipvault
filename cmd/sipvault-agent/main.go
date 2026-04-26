package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sippulse/sipvault/internal/buffer"
	"github.com/sippulse/sipvault/internal/capture"
	"github.com/sippulse/sipvault/internal/config"
	"github.com/sippulse/sipvault/internal/logfilter"
	"github.com/sippulse/sipvault/internal/logtail"
	"github.com/sippulse/sipvault/internal/mux"
	"github.com/sippulse/sipvault/internal/pcap"
	"github.com/sippulse/sipvault/internal/tracker"
)

var version = "dev"

const defaultConfigPath = "/etc/sipvault/agent.conf"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("sipvault-agent %s\n", version)
		os.Exit(0)
	}

	configPath := defaultConfigPath
	if len(os.Args) > 2 && os.Args[1] == "--config" {
		configPath = os.Args[2]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Determine capture mode
	mode := cfg.CaptureMode
	if mode == "" || mode == "auto" {
		mode = capture.DetectMode()
	}

	log.Printf("sipvault-agent %s starting (capture=%s)", version, mode)

	// Set up disk buffer
	buf, err := buffer.NewDiskBuffer(cfg.BufferPath, cfg.BufferMax)
	if err != nil {
		log.Fatalf("failed to create disk buffer: %v", err)
	}
	defer buf.Close()

	// Set up tracker + filter
	trk := tracker.New(30 * time.Second)
	fltr := logfilter.New(trk)

	// Set up sender and batch wrapper.
	// When TLS is enabled, use HEP over TLS (HEPSender); otherwise use the
	// legacy plaintext binary protocol (Sender) for backward compatibility.
	var (
		batchWriter io.Writer
		connectFn   func(context.Context) error
		closeFn     func() error
	)
	if cfg.TLSEnabled {
		hs, err := mux.NewHEPSenderTLS(
			cfg.ServerAddr, cfg.CustomerID, cfg.Token,
			cfg.TLSServerName, cfg.TLSCACert, buf,
		)
		if err != nil {
			log.Fatalf("failed to create HEP/TLS sender: %v", err)
		}
		batchWriter = hs
		connectFn = hs.Reconnect
		closeFn = hs.Close
	} else {
		s := mux.NewSender(cfg.ServerAddr, cfg.CustomerID, cfg.Token, version, buf)
		batchWriter = s
		connectFn = s.Reconnect
		closeFn = s.Close
	}
	batch := mux.NewBatchSender(batchWriter, 64, 5*time.Millisecond)
	batch.Start()

	// Build capture source based on mode
	var sources []capture.Source

	switch mode {
	case "ebpf":
		// eBPF source would be initialized here (requires root + kernel >= 4.18)
		// For now, placeholder — eBPF loader not yet implemented
		log.Fatal("eBPF capture mode not yet implemented — use pcap mode")

	case "pcap":
		iface := cfg.Interface
		if iface == "" {
			log.Fatal("network interface must be specified for pcap mode (capture.interface in config)")
		}

		pcapSrc, err := pcap.NewSource(iface, cfg.SIPPorts, cfg.RTPPortMin, cfg.RTPPortMax, trk.NeedsRTPCapture)
		if err != nil {
			log.Fatalf("failed to start pcap capture: %v", err)
		}
		sources = append(sources, pcapSrc)

	default:
		log.Fatalf("unknown capture mode: %s", mode)
	}

	// Add log file tailer if configured
	if cfg.LogFile != "" {
		tailer, err := logtail.NewTailer(cfg.LogFile)
		if err != nil {
			log.Fatalf("failed to start log tailer: %v", err)
		}
		sources = append(sources, tailer)
	}

	if len(sources) == 0 {
		log.Fatal("no capture sources configured")
	}

	// Merge sources
	var src capture.Source
	if len(sources) == 1 {
		src = sources[0]
	} else {
		src = capture.NewMultiSource(sources...)
	}

	reader := capture.NewReader(src, trk, fltr, batch)

	// Connect to server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := connectFn(ctx); err != nil {
			log.Printf("server connection failed: %v", err)
		}
	}()

	// Periodic tracker cleanup
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				trk.Cleanup()
			}
		}
	}()

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
	}()

	// Run capture loop
	if err := reader.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("capture error: %v", err)
	}

	batch.Stop()
	_ = closeFn()
	log.Println("stopped")
}
