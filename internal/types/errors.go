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
	ErrCertGeneration  = errors.New("failed to generate certificate")
	ErrCANotFound      = errors.New("CA not found")
	ErrInvalidRotation = errors.New("invalid CA rotation")

	// Network errors - Network management
	ErrNetworkNotFound  = errors.New("network not found")
	ErrInvalidCIDR      = errors.New("invalid CIDR format")
	ErrIPv6NotSupported = errors.New("IPv6 networks not supported yet")

	// Host errors - Host management
	ErrInvalidIP             = errors.New("invalid IP address")
	ErrIPNotInNetwork        = errors.New("IP address not within network CIDR")
	ErrLighthouseNoPublicIP  = errors.New("lighthouse hosts require public_host_port")
	ErrRelayNoPublicIP       = errors.New("relay hosts require public_host_port")
	ErrInvalidPublicHostPort = errors.New("invalid public_host_port")
	ErrInvalidUnsafeNetwork  = errors.New("invalid unsafe network")
	ErrInvalidUnsafeRoute    = errors.New("invalid unsafe route")
	ErrInvalidPreferredRange = errors.New("invalid preferred range")
	ErrInvalidHostPort       = errors.New("invalid host:port address")
	ErrInvalidAllowList      = errors.New("invalid allow list")
	ErrHostInactive          = errors.New("host is inactive")

	// Device-held key errors. A host with device_key = true holds only the
	// public half of its key pair, as `nebula-cert keygen` writes it.
	ErrDeviceKeyFrozen        = errors.New("device_key is set at create and cannot change")
	ErrDeviceKeyEnrolled      = errors.New("a key is already enrolled for this host")
	ErrInvalidDeviceKey       = errors.New("not a NEBULA X25519 PUBLIC KEY in PEM form")
	ErrDeviceKeyHasSecret     = errors.New("a device-held key host cannot carry a private key")
	ErrPublicKeyNotDeviceHeld = errors.New("public_key is set only on a device_key host")

	// Config errors - Configuration generation
	ErrConfigGeneration = errors.New("failed to generate config")
	ErrInvalidFirewall  = errors.New("invalid firewall rules")
)
