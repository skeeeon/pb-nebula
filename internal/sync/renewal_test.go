package sync

import (
	"testing"
	"time"
)

// shouldRenew is the whole renewal decision, and it is a pure function of the
// certificate's own window so it can be tested without a PocketBase app. The
// surrounding sweep (which hosts to consider, what to do about the CA clamp)
// needs a live app and is exercised against examples/basic instead.
func TestShouldRenew(t *testing.T) {
	// A one-year certificate, so the 20% threshold falls at roughly 73 days
	// remaining.
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(1, 0, 0)

	const threshold = 0.20

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"brand new", notBefore, false},
		{"half consumed", notBefore.AddDate(0, 6, 0), false},
		{"just inside the threshold", notAfter.AddDate(0, 0, -80), false},
		{"just past the threshold", notAfter.AddDate(0, 0, -70), true},
		{"one day left", notAfter.AddDate(0, 0, -1), true},
		{"exactly at expiry", notAfter, true},
		{"already expired", notAfter.AddDate(0, 0, 1), true},
		// Clock skew can put now before the certificate's own start. The
		// fraction remaining is then above 1, which is not due -- and renewing
		// on a skewed clock would produce a certificate just as wrong.
		{"before it was issued", notBefore.AddDate(0, 0, -1), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRenew(notBefore, notAfter, tt.now, threshold); got != tt.want {
				t.Errorf("shouldRenew(now=%s) = %v, want %v", tt.now.Format(time.RFC3339), got, tt.want)
			}
		})
	}
}

// TestShouldRenewHandlesADegenerateWindow guards the division. A certificate
// whose NotAfter is at or before its NotBefore would otherwise divide by zero
// or produce a nonsense ratio; a hand-edited record or a clock jump can create
// one, and the sweep must not panic or silently skip it forever.
func TestShouldRenewHandlesADegenerateWindow(t *testing.T) {
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	// Zero-length window, evaluated before it closes
	if !shouldRenew(at, at, at.Add(-time.Hour), 0.20) {
		t.Error("a zero-length validity window should be treated as due for renewal")
	}
	// Inverted window
	if !shouldRenew(at, at.Add(-time.Hour), at.Add(-2*time.Hour), 0.20) {
		t.Error("an inverted validity window should be treated as due for renewal")
	}
}

// TestShouldRenewThresholdIsInclusive pins the boundary. The threshold is
// documented as "at or below", and drifting to a strict comparison would leave
// a certificate sitting exactly on the line unrenewed until the next sweep.
func TestShouldRenewThresholdIsInclusive(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(100 * time.Hour)

	// Exactly 20 hours remaining of a 100 hour lifetime is exactly 0.20
	exactly := notAfter.Add(-20 * time.Hour)

	if !shouldRenew(notBefore, notAfter, exactly, 0.20) {
		t.Error("a certificate sitting exactly on the threshold should renew")
	}
	if shouldRenew(notBefore, notAfter, exactly.Add(-time.Minute), 0.20) {
		t.Error("a certificate just above the threshold should not renew")
	}
}
