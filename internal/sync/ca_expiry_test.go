package sync

import (
	"testing"
	"time"
)

// TestClassifyCAExpiry covers the decision behind the CA expiry warning.
//
// The boundary is the part worth pinning. A CA cannot be renewed, only rotated,
// and rotation needs a wait in the middle that nothing can compress -- so the
// warning arriving a day late is not a cosmetic problem, it is the margin the
// whole feature exists to protect.
func TestClassifyCAExpiry(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	const warningDays = 90

	tests := []struct {
		name     string
		notAfter time.Time
		want     caExpiryVerdict
		wantDays int
	}{
		{
			name:     "years out is silent",
			notAfter: now.AddDate(5, 0, 0),
			want:     caExpiryFine,
			wantDays: 1826,
		},
		{
			// One day outside the window. Warning here would mean warning
			// every day for years.
			name:     "just outside the window is silent",
			notAfter: now.Add(91 * 24 * time.Hour),
			want:     caExpiryFine,
			wantDays: 91,
		},
		{
			name:     "exactly at the window warns",
			notAfter: now.Add(90 * 24 * time.Hour),
			want:     caExpiryApproaching,
			wantDays: 90,
		},
		{
			name:     "inside the window warns",
			notAfter: now.Add(7 * 24 * time.Hour),
			want:     caExpiryApproaching,
			wantDays: 7,
		},
		{
			// Truncation, not rounding: 23 hours left must never read as
			// "1 day", which would promise time the operator does not have.
			name:     "hours left truncate to zero days",
			notAfter: now.Add(23 * time.Hour),
			want:     caExpiryApproaching,
			wantDays: 0,
		},
		{
			name:     "already expired",
			notAfter: now.Add(-time.Hour),
			want:     caExpiryPast,
			wantDays: 0,
		},
		{
			// Expiry exactly now is past, matching shouldRenew's !now.Before
			// convention rather than introducing a second reading of "expired".
			name:     "expiring exactly now is past",
			notAfter: now,
			want:     caExpiryPast,
			wantDays: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, days := classifyCAExpiry(tt.notAfter, now, warningDays)
			if got != tt.want {
				t.Errorf("verdict = %v, want %v", got, tt.want)
			}
			if days != tt.wantDays {
				t.Errorf("days = %d, want %d", days, tt.wantDays)
			}
		})
	}
}
