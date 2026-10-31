package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// writeKeypair writes a self-signed certificate for name, with a modification time
// that moves on with every call.
func writeKeypair(t *testing.T, dir, name string, mtime time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{name}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), mtime)
	write(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), mtime)
	return certPath, keyPath
}

func write(t *testing.T, path string, data []byte, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func served(t *testing.T, k *Keypair) string {
	t.Helper()
	k.checked = time.Time{} // don't wait for the next check
	cert, err := k.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestKeypairReloads(t *testing.T) {
	dir := t.TempDir()
	start := time.Now().Add(-time.Hour)
	certPath, keyPath := writeKeypair(t, dir, "first.example.test", start)
	k, err := LoadKeypair(certPath, keyPath, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if name := served(t, k); name != "first.example.test" {
		t.Fatalf("serving %s", name)
	}

	writeKeypair(t, dir, "second.example.test", start.Add(time.Minute))
	if name := served(t, k); name != "second.example.test" {
		t.Fatalf("after renewal, serving %s", name)
	}

	// Halfway through a renewal, the new certificate is written but the key isn't yet.
	writeKeypair(t, dir, "third.example.test", start.Add(2*time.Minute))
	write(t, keyPath, []byte("not a key yet"), start.Add(2*time.Minute))
	if name := served(t, k); name != "second.example.test" {
		t.Fatalf("with a broken key, serving %s", name)
	}

	// Once both files are written, the new pair is served.
	writeKeypair(t, dir, "fourth.example.test", start.Add(4*time.Minute))
	if name := served(t, k); name != "fourth.example.test" {
		t.Fatalf("after the renewal finished, serving %s", name)
	}

	// Between checks, the files aren't looked at.
	writeKeypair(t, dir, "fifth.example.test", start.Add(5*time.Minute))
	if cert, _ := k.GetCertificate(nil); cert == nil {
		t.Fatal("no certificate")
	}
	leaf, _ := x509.ParseCertificate(k.cert.Certificate[0])
	if leaf.Subject.CommonName != "fourth.example.test" {
		t.Fatalf("reloaded before the check interval: %s", leaf.Subject.CommonName)
	}

	if _, err := LoadKeypair(filepath.Join(dir, "missing.pem"), keyPath, zerolog.Nop()); err == nil {
		t.Fatal("loaded a missing certificate")
	}
}
