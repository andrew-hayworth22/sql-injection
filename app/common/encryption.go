package common

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os"
)

func Encrypt(plaintext string) (string, error) {
	key := os.Getenv("APP_KEY")

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(block, []byte(key[0:16]))
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, []byte(plaintext))

	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
	return encodedCiphertext, err
}
