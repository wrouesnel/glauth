package idp

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	signingKeyFile = "oidc-signing-key.pem"
	secretKeyFile  = "oidc-secret.key"
)

// keys holds the provider's long-lived secrets: the key that signs tokens, and a
// symmetric key for encrypting opaque tokens and deriving client secrets.
type keys struct {
	signing   *rsa.PrivateKey
	signingID string
	secretKey []byte
}

// loadKeys reads the keys from dir, creating any that are missing. With no dir,
// it makes keys that only last as long as the process.
func loadKeys(dir string) (*keys, error) {
	k := &keys{}
	var err error
	if dir == "" {
		if k.signing, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			return nil, err
		}
		k.secretKey = make([]byte, 32)
		if _, err = rand.Read(k.secretKey); err != nil {
			return nil, err
		}
	} else {
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if k.signing, err = loadSigningKey(filepath.Join(dir, signingKeyFile)); err != nil {
			return nil, err
		}
		if k.secretKey, err = loadSecretKey(filepath.Join(dir, secretKeyFile)); err != nil {
			return nil, err
		}
	}
	thumb, err := (&jose.JSONWebKey{Key: &k.signing.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	k.signingID = base64.RawURLEncoding.EncodeToString(thumb)
	return k, nil
}

func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return key, writeNew(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM data", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an RSA key", path)
	}
	return key, nil
}

func loadSecretKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, writeNew(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"))
	}
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(string(trimNewline(data)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s: want 32 base64-encoded bytes", path)
	}
	return key, nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// writeNew writes a private file, failing rather than replacing one that appeared meanwhile.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// subkey derives a key for one purpose from the secret key.
func (k *keys) subkey(purpose string) []byte {
	mac := hmac.New(sha256.New, k.secretKey)
	mac.Write([]byte("glauth-oidc\x00" + purpose))
	return mac.Sum(nil)
}

// cryptoKey encrypts the provider's opaque tokens.
func (k *keys) cryptoKey() [32]byte {
	return [32]byte(k.subkey("token-encryption"))
}

type signingKey struct{ k *keys }

func (s signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (s signingKey) Key() any                                    { return s.k.signing }
func (s signingKey) ID() string                                  { return s.k.signingID }

type publicKey struct{ k *keys }

func (p publicKey) ID() string                         { return p.k.signingID }
func (p publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (p publicKey) Use() string                        { return "sig" }
func (p publicKey) Key() any                           { return &p.k.signing.PublicKey }

var (
	_ op.SigningKey = signingKey{}
	_ op.Key        = publicKey{}
)
