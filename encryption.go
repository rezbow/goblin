package main

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/argon2"
)

func encrypt(plaintext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aes, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aes.Seal(nil, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aes, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aes.Open(nil, nonce, ciphertext, nil)

}

func deriveKey(masterKey, salt []byte) []byte {
	const (
		time    = 3         // Number of iterations
		memory  = 64 * 1024 // 64 MB memory
		threads = 4         // Number of threads
		keyLen  = 32        // 32 bytes = 256-bit AES key
	)

	key := argon2.IDKey(masterKey, salt, time, memory, uint8(threads), keyLen)
	return key
}
