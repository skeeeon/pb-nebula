package pbnebula

import (
	"errors"
	"testing"
)

func TestValidateOptionsDefaults(t *testing.T) {
	if err := validateOptions(DefaultOptions()); err != nil {
		t.Errorf("DefaultOptions should validate, got %v", err)
	}
}

func TestValidateOptionsFailures(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Options)
		wantErr error
	}{
		{
			"empty CA collection name",
			func(o *Options) { o.CACollectionName = "" },
			ErrMissingRequiredField,
		},
		{
			"duplicate collection names",
			func(o *Options) { o.NetworkCollectionName = o.CACollectionName },
			ErrInvalidOptions,
		},
		{
			"zero CA validity",
			func(o *Options) { o.DefaultCAValidityYears = 0 },
			ErrInvalidOptions,
		},
		{
			"negative host validity",
			func(o *Options) { o.DefaultHostValidityYears = -1 },
			ErrInvalidOptions,
		},
		{
			"host validity exceeds CA validity",
			func(o *Options) { o.DefaultHostValidityYears = 20 },
			ErrInvalidOptions,
		},
		{
			"encryption key wrong length",
			func(o *Options) { o.EncryptionKey = "too-short" },
			ErrInvalidOptions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := DefaultOptions()
			tt.mutate(&options)
			err := validateOptions(options)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("validateOptions = %v, want errors.Is(%v)", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOptionsAcceptsValidEncryptionKey(t *testing.T) {
	options := DefaultOptions()
	options.EncryptionKey = "0123456789abcdef0123456789abcdef" // 32 chars
	if err := validateOptions(options); err != nil {
		t.Errorf("expected 32-char key to validate, got %v", err)
	}
}

func TestApplyDefaultOptionsFillsZeroValues(t *testing.T) {
	options := applyDefaultOptions(Options{})

	defaults := DefaultOptions()
	if options.CACollectionName != defaults.CACollectionName {
		t.Errorf("expected default CA collection name, got %q", options.CACollectionName)
	}
	if options.DefaultCAValidityYears != defaults.DefaultCAValidityYears {
		t.Errorf("expected default CA validity, got %d", options.DefaultCAValidityYears)
	}
	if options.DefaultHostValidityYears != defaults.DefaultHostValidityYears {
		t.Errorf("expected default host validity, got %d", options.DefaultHostValidityYears)
	}
}

func TestApplyDefaultOptionsPreservesUserValues(t *testing.T) {
	options := applyDefaultOptions(Options{
		CACollectionName:       "custom_ca",
		DefaultCAValidityYears: 5,
	})

	if options.CACollectionName != "custom_ca" {
		t.Errorf("user collection name overwritten: %q", options.CACollectionName)
	}
	if options.DefaultCAValidityYears != 5 {
		t.Errorf("user validity overwritten: %d", options.DefaultCAValidityYears)
	}
	// Unset fields still get defaults
	if options.NetworkCollectionName == "" {
		t.Error("expected default network collection name to be applied")
	}
}
