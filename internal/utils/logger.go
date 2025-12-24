// Package utils provides utility functions for the pb-nebula library
package utils

import (
	"fmt"
	"log"
	"time"
)

// Logger provides consistent, categorized logging throughout the pb-nebula library.
// Mirrors the pb-nats logger design with visual prefixes for quick status recognition.
//
// LOGGING PHILOSOPHY:
// - Visual consistency with emoji prefixes
// - Semantic categorization (start, success, info, warning, error, etc.)
// - Timestamp precision for debugging
// - Toggle capability for production vs development
//
// PREFIX SEMANTICS:
// - 🚀 START: System initialization and component startup
// - ✅ SUCCESS: Successful completion of operations
// - ℹ️ INFO: Informational messages and state changes
// - ⚙️ PROCESS: Active processing operations
// - ⚠️ WARNING: Recoverable issues that need attention
// - ❌ ERROR: Failures and error conditions
// - 🛑 STOP: Shutdown and cleanup operations
// - 🔐 CERT: Certificate generation and operations
// - 📝 CONFIG: Configuration generation operations
type Logger struct {
	enabled bool // Controls whether log messages are output
}

// NewLogger creates a new logger instance with configurable output.
//
// PARAMETERS:
//   - enabled: Whether to output log messages
//
// RETURNS:
// - Logger instance ready for categorized logging
func NewLogger(enabled bool) *Logger {
	return &Logger{
		enabled: enabled,
	}
}

// logWithPrefix writes a log message with timestamp and visual prefix if logging enabled.
//
// LOG FORMAT:
//   [HH:MM:SS] PREFIX MESSAGE
//
// PARAMETERS:
//   - prefix: Visual prefix with emoji and category name
//   - format: Printf-style format string
//   - args: Format arguments
func (l *Logger) logWithPrefix(prefix, format string, args ...interface{}) {
	if !l.enabled {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	message := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s %s", timestamp, prefix, message)
}

// Start logs system initialization and component startup messages.
func (l *Logger) Start(format string, args ...interface{}) {
	l.logWithPrefix("🚀 START", format, args...)
}

// Success logs successful completion of operations.
func (l *Logger) Success(format string, args ...interface{}) {
	l.logWithPrefix("✅ SUCCESS", format, args...)
}

// Info logs informational messages and state changes.
func (l *Logger) Info(format string, args ...interface{}) {
	l.logWithPrefix("ℹ️  INFO", format, args...)
}

// Process logs active processing and background operations.
func (l *Logger) Process(format string, args ...interface{}) {
	l.logWithPrefix("⚙️  PROCESS", format, args...)
}

// Warning logs recoverable issues that need attention.
func (l *Logger) Warning(format string, args ...interface{}) {
	l.logWithPrefix("⚠️  WARNING", format, args...)
}

// Error logs failures and error conditions.
func (l *Logger) Error(format string, args ...interface{}) {
	l.logWithPrefix("❌ ERROR", format, args...)
}

// Stop logs shutdown and cleanup operations.
func (l *Logger) Stop(format string, args ...interface{}) {
	l.logWithPrefix("🛑 STOP", format, args...)
}

// Cert logs certificate generation and operations.
func (l *Logger) Cert(format string, args ...interface{}) {
	l.logWithPrefix("🔐 CERT", format, args...)
}

// Config logs configuration generation operations.
func (l *Logger) Config(format string, args ...interface{}) {
	l.logWithPrefix("📝 CONFIG", format, args...)
}
