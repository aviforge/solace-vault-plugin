package solacevaultplugin

import (
	"crypto/rand"
	"math/big"
)

// Solace password constraints: max 128 chars, excludes :()";'<>,`\*&|
const passwordCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^-_=+.~"

func generatePassword(length int) (string, error) {
	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(passwordCharset)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = passwordCharset[idx.Int64()]
	}

	return string(result), nil
}
