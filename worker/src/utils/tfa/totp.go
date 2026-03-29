package tfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

func GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func GenerateCode(secret string, timestamp int64) string {
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ToUpper(secret)

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}

	counter := uint64(timestamp / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	hash := hmacSHA1(key, buf)

	offset := hash[len(hash)-1] & 0x0F

	truncated := binary.BigEndian.Uint32(hash[offset : offset+4])
	truncated = truncated & 0x7FFFFFFF

	code := truncated % uint32(math.Pow10(6))

	return fmt.Sprintf("%06d", code)
}

func VerifyCode(secret, code string) bool {
	currentTime := time.Now().Unix()
	for i := -1; i <= 1; i++ {
		timestamp := currentTime + int64(i*30)

		if GenerateCode(secret, timestamp) == code {
			return true
		}
	}

	return false
}

func GenerateBackupCodes(count int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		hash := sha1.Sum(b)
		codes[i] = fmt.Sprintf("%08x", hash)[:8]
	}

	return codes
}

func GetProvisioningURI(secret, email, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, email, secret, issuer)
}

func hmacSHA1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}
