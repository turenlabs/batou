// Source: CWE-327/CWE-328 - Weak cryptographic algorithms in Go
// Expected: GTSS-CRY-001 (Weak Hashing - MD5/SHA1), GTSS-CRY-003 (Weak Cipher - DES)
// OWASP: A02:2021 - Cryptographic Failures

package handler

import (
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
)

func HashPassword(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	hash := md5.Sum([]byte(password))
	w.Write([]byte(hex.EncodeToString(hash[:])))
}

func GenerateChecksum(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	hash := sha1.Sum([]byte(data))
	fmt.Fprintf(w, "SHA1: %x", hash)
}

func EncryptData(w http.ResponseWriter, r *http.Request) {
	key := []byte("8byteky")
	block, err := des.NewCipher(key)
	if err != nil {
		http.Error(w, "Cipher error", http.StatusInternalServerError)
		return
	}
	plaintext := []byte(r.FormValue("data"))
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	w.Write(ciphertext)
}

func GenerateToken() string {
	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(token)
}
