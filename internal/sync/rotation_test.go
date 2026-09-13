package sync

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
)

// caRecord builds a detached CA record for the pure helpers below. No app is
// needed: NewBaseCollection and NewRecord are plain constructors.
func caRecord(t *testing.T, fields map[string]any) *core.Record {
	t.Helper()
	collection := core.NewBaseCollection("nebula_ca")
	collection.Fields.Add(
		&core.TextField{Name: "certificate", Max: 10000},
		&core.TextField{Name: "next_certificate", Max: 10000},
		&core.TextField{Name: "previous_certificate", Max: 10000},
	)
	record := core.NewRecord(collection)
	for k, v := range fields {
		record.Set(k, v)
	}
	return record
}

// TestCARotationStateIsDerived pins the decision to stop storing a status
// column. The phase is a function of which certificate field is populated, so
// there is nothing that can disagree with reality -- the same rule that keeps
// blocklist fingerprints derived from the stored certificate.
func TestCARotationStateIsDerived(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]any
		want   rotationState
	}{
		{"fresh CA", map[string]any{"certificate": "CURRENT"}, rotationIdle},
		{"prepared", map[string]any{"certificate": "CURRENT", "next_certificate": "NEXT"}, rotationPrepared},
		{"rotated", map[string]any{"certificate": "CURRENT", "previous_certificate": "PREV"}, rotationRotated},
		// Should be unreachable (prepare is refused while previous is set), but
		// if it ever happened, treating it as prepared is the safe reading:
		// there is an unfinished mint to deal with before anything else.
		{"both set", map[string]any{"certificate": "C", "next_certificate": "N", "previous_certificate": "P"}, rotationPrepared},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := caRotationState(caRecord(t, tt.fields)); got != tt.want {
				t.Errorf("caRotationState() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCABundleContentIsStableAcrossThePhases is the property the whole
// three-step design depends on.
//
// The bundle must contain the SAME two certificates before and after the
// commit. If it did not, a host that fetched during `prepare` and a host that
// fetched during `commit` would trust different sets, and one of them would be
// unable to verify the other -- which is precisely the split the three steps
// exist to avoid.
func TestCABundleContentIsStableAcrossThePhases(t *testing.T) {
	const old, new_ = "OLD-CA-PEM", "NEW-CA-PEM"

	prepared := caBundle(caRecord(t, map[string]any{
		"certificate":      old,  // issuance still on the old CA
		"next_certificate": new_, // incoming, trusted but not yet signing
	}))
	rotated := caBundle(caRecord(t, map[string]any{
		"certificate":          new_, // issuance switched
		"previous_certificate": old,  // outgoing, still trusted
	}))

	if prepared != rotated {
		t.Errorf("bundle changed across the commit:\n prepared: %q\n rotated:  %q", prepared, rotated)
	}
	// Order is old-then-new in both, which keeps the rendered config stable
	if prepared != old+"\n"+new_ {
		t.Errorf("unexpected bundle layout: %q", prepared)
	}
}

// TestCABundleIsASingleCertificateOutsideARotation is the no-spurious-diff
// guarantee: a CA that has never rotated must render exactly the pki.ca it
// always did, or enabling this feature rewrites every config in every network.
func TestCABundleIsASingleCertificateOutsideARotation(t *testing.T) {
	got := caBundle(caRecord(t, map[string]any{"certificate": "ONLY-CA-PEM"}))

	if got != "ONLY-CA-PEM" {
		t.Errorf("expected the bare certificate, got %q", got)
	}
}
