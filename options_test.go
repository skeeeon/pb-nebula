package pbnebula

import (
	"errors"
	"testing"

	"github.com/skeeeon/pb-nebula/internal/types"
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

// TestDefaultOptionsEnablesRenewal pins the default direction. The option is
// named negatively precisely so the zero value means "renewal on"; if it ever
// flipped, a deployment that never set it would silently stop renewing and
// every host would expire on schedule.
func TestDefaultOptionsEnablesRenewal(t *testing.T) {
	opts := DefaultOptions()

	if opts.DisableHostCertRenewal {
		t.Error("renewal must be enabled by default")
	}
	if opts.HostRenewalThreshold != types.DefaultHostRenewalThreshold {
		t.Errorf("expected default threshold %v, got %v", types.DefaultHostRenewalThreshold, opts.HostRenewalThreshold)
	}
	if opts.HostRenewalCron != types.DefaultHostRenewalCron {
		t.Errorf("expected default cron %q, got %q", types.DefaultHostRenewalCron, opts.HostRenewalCron)
	}

	// An empty Options must pick the same defaults up, since applyDefaultOptions
	// only fills zero values
	applied := applyDefaultOptions(Options{})
	if applied.DisableHostCertRenewal {
		t.Error("an empty Options must still have renewal enabled")
	}
	if applied.HostRenewalThreshold != types.DefaultHostRenewalThreshold {
		t.Errorf("expected threshold filled to %v, got %v", types.DefaultHostRenewalThreshold, applied.HostRenewalThreshold)
	}
	if applied.HostRenewalCron != types.DefaultHostRenewalCron {
		t.Errorf("expected cron filled to %q, got %q", types.DefaultHostRenewalCron, applied.HostRenewalCron)
	}
}

func TestValidateOptionsRejectsBadRenewalThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold float64
		wantErr   bool
	}{
		{"zero would never renew", 0, true},
		{"negative", -0.1, true},
		{"one would renew every sweep", 1, true},
		{"above one", 1.5, true},
		{"the default", 0.20, false},
		{"aggressive but legal", 0.99, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := DefaultOptions()
			opts.HostRenewalThreshold = tt.threshold
			err := validateOptions(opts)
			if tt.wantErr && !errors.Is(err, ErrInvalidOptions) {
				t.Errorf("expected ErrInvalidOptions for threshold %v, got %v", tt.threshold, err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected threshold %v to be accepted, got %v", tt.threshold, err)
			}
		})
	}
}
