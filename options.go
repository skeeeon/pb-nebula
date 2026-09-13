package pbnebula

import (
	"github.com/skeeeon/pb-nebula/internal/types"
)

// Re-export Options type for external use
type Options = types.Options

// DefaultOptions returns sensible defaults for Nebula certificate and config management.
// These defaults follow the grug-brained philosophy: simple, predictable, and safe.
//
// COLLECTION NAMES:
// Uses nebula_ prefix to clearly identify Nebula-related collections in PocketBase admin UI.
//
// VALIDITY PERIODS:
// - CA: 10 years (long-lived root of trust)
// - Hosts: 1 year (shorter validity reduces exposure window)
//
// LOGGING:
// Enabled by default for visibility during development and operations.
//
// RETURNS:
// - Options struct with production-ready defaults
func DefaultOptions() Options {
	return Options{
		CACollectionName:      types.DefaultCACollectionName,
		NetworkCollectionName: types.DefaultNetworkCollectionName,
		HostCollectionName:    types.DefaultHostCollectionName,

		DefaultCAValidityYears:   types.DefaultCAValidityYears,
		DefaultHostValidityYears: types.DefaultHostValidityYears,

		LogToConsole: true,

		// Renewal is ON by default: the failure mode of forgetting it is a
		// host that silently drops off the mesh when its certificate expires.
		DisableHostCertRenewal: false,
		HostRenewalThreshold:   types.DefaultHostRenewalThreshold,
		HostRenewalCron:        types.DefaultHostRenewalCron,

		// Not gated by DisableHostCertRenewal: a CA cannot be renewed, only
		// rotated, and rotation is a manual three-step procedure that needs
		// warning ahead of time no matter how host certificates are handled.
		CAExpiryWarningDays: types.DefaultCAExpiryWarningDays,

		EventFilter: nil, // No filter by default, process all events
	}
}

// applyDefaultOptions fills in default values for any missing options.
// This ensures the system always has valid configuration even if users
// provide partial options.
//
// PARAMETERS:
//   - options: User-provided options (may be partially filled)
//
// RETURNS:
// - Options struct with all fields populated
//
// BEHAVIOR:
// Only replaces empty/zero values, preserves user-specified values.
func applyDefaultOptions(options Options) Options {
	defaults := DefaultOptions()

	// Apply collection names
	if options.CACollectionName == "" {
		options.CACollectionName = defaults.CACollectionName
	}
	if options.NetworkCollectionName == "" {
		options.NetworkCollectionName = defaults.NetworkCollectionName
	}
	if options.HostCollectionName == "" {
		options.HostCollectionName = defaults.HostCollectionName
	}

	// Apply validity defaults
	if options.DefaultCAValidityYears <= 0 {
		options.DefaultCAValidityYears = defaults.DefaultCAValidityYears
	}
	if options.DefaultHostValidityYears <= 0 {
		options.DefaultHostValidityYears = defaults.DefaultHostValidityYears
	}

	// Apply renewal defaults. DisableHostCertRenewal is deliberately absent:
	// its zero value (false, meaning renewal is on) is already the default we
	// want, which is the whole reason the option is named negatively.
	if options.HostRenewalThreshold <= 0 {
		options.HostRenewalThreshold = defaults.HostRenewalThreshold
	}
	if options.HostRenewalCron == "" {
		options.HostRenewalCron = defaults.HostRenewalCron
	}
	if options.CAExpiryWarningDays <= 0 {
		options.CAExpiryWarningDays = defaults.CAExpiryWarningDays
	}

	return options
}
