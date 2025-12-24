package pbnebula

import (
	"errors"
	"fmt"
	"strings"
)

// Common errors returned by the library organized by operational category.
// This error taxonomy enables consistent error handling across all components.
//
// ERROR CLASSIFICATION PHILOSOPHY:
// Errors are classified to indicate appropriate handling:
// - Configuration errors: System setup problems requiring admin intervention
// - Validation errors: Invalid input data that should be corrected
// - Operational errors: Runtime issues that may be transient
var (
	// Collection errors - Database and schema related issues
	ErrCollectionNotFound = errors.New("collection not found")
	ErrRecordNotFound     = errors.New("record not found")
	ErrInvalidRecord      = errors.New("invalid record data")

	// Certificate errors - Cryptographic operations
	ErrCertGeneration  = errors.New("failed to generate certificate")
	ErrInvalidCert     = errors.New("invalid certificate")
	ErrCertExpired     = errors.New("certificate expired")
	ErrCANotFound      = errors.New("CA not found")
	ErrInvalidCA       = errors.New("invalid CA certificate")
	ErrMultipleCAs     = errors.New("multiple CA records found, only one allowed")

	// Network errors - Network management
	ErrNetworkNotFound  = errors.New("network not found")
	ErrInvalidCIDR      = errors.New("invalid CIDR format")
	ErrIPv6NotSupported = errors.New("IPv6 networks not supported yet")

	// Host errors - Host management
	ErrHostNotFound         = errors.New("host not found")
	ErrInvalidIP            = errors.New("invalid IP address")
	ErrIPNotInNetwork       = errors.New("IP address not within network CIDR")
	ErrLighthouseNoPublicIP = errors.New("lighthouse hosts require public_host_port")

	// Config errors - Configuration generation
	ErrConfigGeneration = errors.New("failed to generate config")
	ErrInvalidFirewall  = errors.New("invalid firewall rules")

	// Validation errors - Input validation
	ErrInvalidOptions       = errors.New("invalid options provided")
	ErrMissingRequiredField = errors.New("missing required field")
)

// WrapError creates a wrapped error with additional context while preserving the original error.
// This provides consistent error context throughout the system.
//
// PARAMETERS:
//   - err: Original error to wrap (nil returns nil)
//   - context: Additional context string to prepend
//
// RETURNS:
// - error: Wrapped error with context, nil if original error nil
//
// ERROR FORMAT: "{context}: {original error message}"
func WrapError(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

// WrapErrorf creates a wrapped error with formatted context string.
// Combines error wrapping with printf-style string formatting.
//
// PARAMETERS:
//   - err: Original error to wrap (nil returns nil)
//   - format: Printf-style format string for context
//   - args: Arguments for format string
//
// RETURNS:
// - error: Wrapped error with formatted context, nil if original error nil
func WrapErrorf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	context := fmt.Sprintf(format, args...)
	return fmt.Errorf("%s: %w", context, err)
}

// ValidateRequired ensures string fields are not empty after trimming whitespace.
// Primary validation function used throughout pb-nebula for required field checking.
//
// PARAMETERS:
//   - value: String value to validate
//   - fieldName: Human-readable field name for error messages
//
// RETURNS:
// - error: nil if valid, descriptive error if empty
func ValidateRequired(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required and cannot be empty", fieldName)
	}
	return nil
}
