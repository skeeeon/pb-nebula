package pbnebula

import "errors"

var (
	ErrAuthorityNotFound = errors.New("authority not found")
	ErrIPExhausted       = errors.New("ip address pool exhausted")
	ErrInvalidCIDR       = errors.New("invalid cidr format")
)
