package types

import (
	"strings"
	"testing"
)

const testKey = "0123456789abcdef0123456789abcdef" // 32 chars

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := "-----BEGIN NEBULA ED25519 PRIVATE KEY-----\nsecret\n-----END-----"

	encrypted, err := EncryptField(plaintext, testKey)
	if err != nil {
		t.Fatalf("EncryptField failed: %v", err)
	}
	if !strings.HasPrefix(encrypted, "enc::") {
		t.Errorf("expected enc:: prefix, got %q", encrypted[:10])
	}
	if strings.Contains(encrypted, "secret") {
		t.Error("ciphertext contains plaintext")
	}

	decrypted, err := DecryptField(encrypted, testKey)
	if err != nil {
		t.Fatalf("DecryptField failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("round trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptFieldEmptyKeyIsNoOp(t *testing.T) {
	out, err := EncryptField("plaintext", "")
	if err != nil {
		t.Fatalf("EncryptField failed: %v", err)
	}
	if out != "plaintext" {
		t.Errorf("expected passthrough with empty key, got %q", out)
	}
}

func TestEncryptFieldEmptyValueIsNoOp(t *testing.T) {
	out, err := EncryptField("", testKey)
	if err != nil {
		t.Fatalf("EncryptField failed: %v", err)
	}
	if out != "" {
		t.Errorf("expected empty passthrough, got %q", out)
	}
}

// TestDecryptFieldPlaintextPassthrough guards backward compatibility: records
// written before encryption was enabled have no enc:: prefix and must read
// back unchanged.
func TestDecryptFieldPlaintextPassthrough(t *testing.T) {
	legacy := "legacy plaintext key material"
	out, err := DecryptField(legacy, testKey)
	if err != nil {
		t.Fatalf("DecryptField failed: %v", err)
	}
	if out != legacy {
		t.Errorf("expected plaintext passthrough, got %q", out)
	}
}

func TestDecryptFieldEmptyKeyIsNoOp(t *testing.T) {
	stored := "enc::whatever"
	out, err := DecryptField(stored, "")
	if err != nil {
		t.Fatalf("DecryptField failed: %v", err)
	}
	if out != stored {
		t.Errorf("expected passthrough with empty key, got %q", out)
	}
}

func TestDecryptFieldWrongKeyFails(t *testing.T) {
	encrypted, err := EncryptField("secret", testKey)
	if err != nil {
		t.Fatalf("EncryptField failed: %v", err)
	}

	wrongKey := "ffffffffffffffffffffffffffffffff"
	if _, err := DecryptField(encrypted, wrongKey); err == nil {
		t.Error("expected error decrypting with wrong key, got nil")
	}
}
