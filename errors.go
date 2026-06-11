package pbnebula

import (
	"errors"
	"fmt"
	"strings"

	"github.com/skeeeon/pb-nebula/internal/types"
)

// Common errors returned by the library organized by operational category.
// The component-level sentinels are defined in internal/types (so internal
// packages can wrap them without an import cycle) and re-exported here for
// consumers to match with errors.Is.
//
// ERROR CLASSIFICATION PHILOSOPHY:
// Errors are classified to indicate appropriate handling:
// - Configuration errors: System setup problems requiring admin intervention
// - Validation errors: Invalid input data that should be corrected
// - Operational errors: Runtime issues that may be transient
var (
	// Certificate errors - Cryptographic operations
	ErrCertGeneration = types.ErrCertGeneration
	ErrCANotFound     = types.ErrCANotFound

	// Network errors - Network management
	ErrNetworkNotFound  = types.ErrNetworkNotFound
	ErrInvalidCIDR      = types.ErrInvalidCIDR
	ErrIPv6NotSupported = types.ErrIPv6NotSupported

	// Host errors - Host management
	ErrInvalidIP            = types.ErrInvalidIP
	ErrIPNotInNetwork       = types.ErrIPNotInNetwork
	ErrLighthouseNoPublicIP = types.ErrLighthouseNoPublicIP

	// Config errors - Configuration generation
	ErrConfigGeneration = types.ErrConfigGeneration
	ErrInvalidFirewall  = types.ErrInvalidFirewall

	// Validation errors - Input validation (root-level, used by option validation)
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
// Returned errors match ErrMissingRequiredField via errors.Is.
//
// PARAMETERS:
//   - value: String value to validate
//   - fieldName: Human-readable field name for error messages
//
// RETURNS:
// - error: nil if valid, descriptive error if empty
func ValidateRequired(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required and cannot be empty", ErrMissingRequiredField, fieldName)
	}
	return nil
}
