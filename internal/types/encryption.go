package types

import (
	"fmt"
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
)

const encryptedPrefix = "enc::"

// EncryptField encrypts a plaintext string value using AES-256-GCM and returns
// it with an "enc::" prefix. Empty plaintext or empty key is a no-op (returns
// the input unchanged), so callers can pass an empty key to disable encryption.
func EncryptField(plaintext, key string) (string, error) {
	if key == "" || plaintext == "" {
		return plaintext, nil
	}

	encrypted, err := security.Encrypt([]byte(plaintext), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt field: %w", err)
	}

	return encryptedPrefix + encrypted, nil
}

// DecryptField decrypts a stored value if it has the "enc::" prefix.
// Stored values without the prefix pass through unchanged (backward-compat
// for records written before encryption was enabled). Empty key also passes
// through, so callers can opt out without branching.
func DecryptField(stored, key string) (string, error) {
	if key == "" || stored == "" || !strings.HasPrefix(stored, encryptedPrefix) {
		return stored, nil
	}

	ciphertext := strings.TrimPrefix(stored, encryptedPrefix)
	decrypted, err := security.Decrypt(ciphertext, key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt field: %w", err)
	}

	return string(decrypted), nil
}

// EncryptAndSet encrypts a value and writes it to the named record field.
// With an empty key the plaintext is written directly.
func EncryptAndSet(record *core.Record, field, value, key string) error {
	encrypted, err := EncryptField(value, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", field, err)
	}
	record.Set(field, encrypted)
	return nil
}
