package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := LoadConfig(os.Getenv)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ledger, err := newFabricLedger(cfg)
	if err != nil {
		log.Fatalf("fabric: %v", err)
	}
	defer ledger.Close()

	srv, source, err := newSPIFFEServer(ctx, cfg, (&API{L: ledger, Role: cfg.Role}).Routes())
	if err != nil {
		log.Fatalf("spiffe: %v", err)
	}
	defer source.Close()

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("bridge role=%s listening on %s (allowed client %s)", cfg.Role, cfg.Listen, cfg.AllowedClientID)
	// Certificates come from the TLS config, so the file arguments are empty.
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}
