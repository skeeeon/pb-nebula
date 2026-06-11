package types

import "errors"

// Sentinel errors shared across pb-nebula components.
//
// These live in the types package (rather than the root package) so internal
// packages can wrap them without an import cycle — the root package imports
// internal/sync, which imports this package. The root package re-exports each
// of these so library consumers can match with errors.Is.
//
// ERROR CLASSIFICATION PHILOSOPHY:
// Errors are classified to indicate appropriate handling:
// - Validation errors: Invalid input data that should be corrected
// - Lookup errors: Referenced records that don't exist
// - Operational errors: Runtime generation failures that may be transient
var (
	// Certificate errors - Cryptographic operations
	ErrCertGeneration = errors.New("failed to generate certificate")
	ErrCANotFound     = errors.New("CA not found")

	// Network errors - Network management
	ErrNetworkNotFound  = errors.New("network not found")
	ErrInvalidCIDR      = errors.New("invalid CIDR format")
	ErrIPv6NotSupported = errors.New("IPv6 networks not supported yet")

	// Host errors - Host management
	ErrInvalidIP            = errors.New("invalid IP address")
	ErrIPNotInNetwork       = errors.New("IP address not within network CIDR")
	ErrLighthouseNoPublicIP = errors.New("lighthouse hosts require public_host_port")

	// Config errors - Configuration generation
	ErrConfigGeneration = errors.New("failed to generate config")
	ErrInvalidFirewall  = errors.New("invalid firewall rules")
)
