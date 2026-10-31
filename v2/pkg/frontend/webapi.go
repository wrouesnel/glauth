package frontend

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/glauth/glauth/v2/internal/monitoring"
	_tls "github.com/glauth/glauth/v2/internal/tls"
	"github.com/glauth/glauth/v2/pkg/assets"
)

// RunAPI provides a basic REST API
func RunAPI(opts ...Option) {
	options := newOptions(opts...)
	log := options.Logger
	cfg := options.Config

	router := http.DefaultServeMux

	assets.NewAPI(log).RegisterEndpoints(router)
	monitoring.NewAPI(log).RegisterEndpoints(router)

	if cfg.TLS {
		log.Info().Str("address", cfg.Listen).Msg("Starting HTTPS server")

		monitoring.NewCollector(fmt.Sprintf("https://%s/debug/vars", cfg.Listen))
		keypair, err := _tls.LoadKeypair(cfg.Cert, cfg.Key, log)
		if err != nil {
			log.Error().Err(err).Msg("error loading the HTTPS server's certificate")
			return
		}
		srv := &http.Server{Addr: cfg.Listen, TLSConfig: &tls.Config{GetCertificate: keypair.GetCertificate}} //nolint:gosec // as http.ListenAndServeTLS did
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Error().Err(err).Msg("error starting HTTPS server")
		}

		return
	}

	log.Info().Str("address", cfg.Listen).Msg("Starting HTTP server")
	monitoring.NewCollector(fmt.Sprintf("http://%s/debug/vars", cfg.Listen))

	if err := http.ListenAndServe(cfg.Listen, nil); err != nil {
		log.Error().Err(err).Msg("error starting HTTP server")
	}

}
