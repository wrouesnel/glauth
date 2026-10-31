package tls

import (
	tls "crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// keypairCheckInterval is how often a Keypair looks at its files for changes.
const keypairCheckInterval = 10 * time.Second

// Keypair serves a certificate and key read from files, and reads them again when
// they change, so renewed certificates are used without a restart. Until both files
// make a valid pair again, as they may not halfway through a renewal, it keeps
// serving the certificate it has.
type Keypair struct {
	certPath, keyPath string
	log               zerolog.Logger

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   string // the files' sizes and modification times when last read
	checked time.Time
}

// LoadKeypair reads a certificate and key from files.
func LoadKeypair(certPath, keyPath string, log zerolog.Logger) (*Keypair, error) {
	k := &Keypair{certPath: certPath, keyPath: keyPath, log: log}
	stamp, err := k.stamps()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	k.cert, k.stamp, k.checked = &cert, stamp, time.Now()
	return k, nil
}

// GetCertificate serves as tls.Config.GetCertificate.
func (k *Keypair) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if now := time.Now(); now.Sub(k.checked) >= keypairCheckInterval {
		k.checked = now
		k.reload()
	}
	return k.cert, nil
}

func (k *Keypair) reload() {
	stamp, err := k.stamps()
	if err != nil {
		k.log.Warn().Err(err).Str("certificate", k.certPath).Msg("can't check the TLS certificate for changes")
		return
	}
	if stamp == k.stamp {
		return
	}
	// Only try again once the files change again.
	k.stamp = stamp
	cert, err := tls.LoadX509KeyPair(k.certPath, k.keyPath)
	if err != nil {
		k.log.Warn().Err(err).Str("certificate", k.certPath).Msg("TLS certificate changed but can't be loaded: still using the previous one")
		return
	}
	k.cert = &cert
	event := k.log.Info().Str("certificate", k.certPath)
	if cert.Leaf != nil {
		event = event.Time("not_after", cert.Leaf.NotAfter)
	}
	event.Msg("TLS certificate reloaded")
}

func (k *Keypair) stamps() (string, error) {
	var stamp string
	for _, path := range []string{k.certPath, k.keyPath} {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		stamp += fmt.Sprintf("%d:%d;", info.Size(), info.ModTime().UnixNano())
	}
	return stamp, nil
}
