package unix

import (
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/openwall/yescrypt-go"
	"golang.org/x/crypto/bcrypt"
)

var (
	errNoPassword      = errors.New("account has no usable password")
	errUnsupportedHash = errors.New("unsupported password hash scheme")
	errMismatch        = errors.New("password does not match")
)

// verifyPassword checks a password against a crypt(3) hash as found in shadow.
// It supports the schemes Linux distributions use: yescrypt ($y$), SHA-512
// ($6$), SHA-256 ($5$), bcrypt ($2a$, $2b$, $2y$) and MD5 ($1$).
func verifyPassword(hash, password string) error {
	if hash == "" || strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*") {
		return errNoPassword
	}
	if password == "" {
		return errMismatch
	}

	switch {
	case strings.HasPrefix(hash, "$y$"):
		computed, err := yescrypt.Hash([]byte(password), []byte(hash))
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(computed, []byte(hash)) != 1 {
			return errMismatch
		}
		return nil
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
			return errMismatch
		}
		return nil
	case strings.HasPrefix(hash, "$1$"), strings.HasPrefix(hash, "$5$"), strings.HasPrefix(hash, "$6$"):
		if !crypt.IsHashSupported(hash) {
			return errUnsupportedHash
		}
		if err := crypt.NewFromHash(hash).Verify(hash, []byte(password)); err != nil {
			return errMismatch
		}
		return nil
	default:
		// Traditional DES crypt and the rest are too weak to be worth
		// supporting: such accounts can't bind.
		return errUnsupportedHash
	}
}
