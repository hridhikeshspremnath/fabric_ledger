package main

import (
	"context"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// newSPIFFEServer builds an HTTPS server whose TLS config comes from the SPIRE
// Workload API: server cert = this workload's SVID, client CA = trust bundle,
// and only cfg.AllowedClientID is authorised. The X509Source rotates SVIDs.
func newSPIFFEServer(ctx context.Context, cfg Config, handler http.Handler) (*http.Server, *workloadapi.X509Source, error) {
	var opts []workloadapi.X509SourceOption
	if cfg.SpiffeSocket != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.SpiffeSocket)))
	}
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, nil, err
	}
	allowed, err := spiffeid.FromString(cfg.AllowedClientID)
	if err != nil {
		source.Close()
		return nil, nil, err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		TLSConfig:         tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeID(allowed)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv, source, nil
}
