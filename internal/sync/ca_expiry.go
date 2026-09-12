package sync

import (
	"time"

	"github.com/pocketbase/pocketbase/core"

	nebulacert "github.com/slackhq/nebula/cert"
)

// caExpiryVerdict is how much trouble a CA's remaining lifetime is in.
type caExpiryVerdict int

const (
	caExpiryFine        caExpiryVerdict = iota // outside the warning window
	caExpiryApproaching                        // inside it, still valid
	caExpiryPast                               // already expired
)

// classifyCAExpiry decides whether a CA's expiry is worth saying anything about.
//
// Pure, with now injected, for the reason shouldRenew is: a test can put the
// clock wherever it likes, and one sweep evaluates every CA against a single
// instant rather than drifting across the loop.
//
// The day count is truncated rather than rounded, so "1 day" never means
// "expires in the next few hours". An operator reading a countdown should never
// find they had less time than it said.
//
// PARAMETERS:
//   - notAfter: the CA certificate's own expiry
//   - now: evaluation time
//   - warningDays: how far ahead to start warning
//
// RETURNS:
// - the verdict, and whole days remaining (0 once expired)
//
// SIDE EFFECTS: None (pure).
func classifyCAExpiry(notAfter, now time.Time, warningDays int) (caExpiryVerdict, int) {
	if !now.Before(notAfter) {
		return caExpiryPast, 0
	}

	days := int(notAfter.Sub(now).Hours() / 24)
	if days > warningDays {
		return caExpiryFine, days
	}

	return caExpiryApproaching, days
}

// WarnOnExpiringCAs logs a warning for every CA approaching its NotAfter, and
// changes nothing.
//
// WHY A CA NEEDS ITS OWN WARNING:
// A host certificate is renewable; a CA is not. The only remedy is rotation,
// and rotation is a three-step operator procedure with a deliberate wait in the
// middle -- long enough for every host to pull a config it has not been told to
// pull. Nebula's own guide asks you to begin two to three months out for that
// reason, so the warning has to arrive with room for the wait, not just room
// for the work.
//
// NOTHING ELSE SURFACES THIS IN TIME:
// hostCertNeedsRenewal does warn once host certificates are clamped to the CA's
// NotAfter -- but that is both late and indirect. It fires only for hosts that
// have already passed their own renewal threshold, and it reports a symptom
// ("cannot be renewed past CA X") rather than the deadline. On the default
// 1-year host certificate against a 10-year CA, the first clamp warning lands
// inside the final year.
//
// WHAT IT DELIBERATELY DOES NOT DO:
// It does not warn about a rotation left half-finished. A CA sitting in
// `prepared` for a fortnight is an operator waiting for propagation, which is
// the documented procedure; nothing here can tell that apart from neglect, and
// a warning that cries wolf on correct behavior is worse than no warning.
//
// PARAMETERS: none -- every CA is checked.
//
// SIDE EFFECTS: Logging only. Never writes, never signs.
func (sm *Manager) WarnOnExpiringCAs() {
	cas, err := sm.app.FindAllRecords(sm.options.CACollectionName)
	if err != nil {
		// Advisory, and it runs at bootstrap: never fatal.
		sm.logger.Warning("Could not check CA expiry: %v", err)
		return
	}

	now := time.Now()
	for _, ca := range cas {
		sm.warnIfCAExpiring(ca, now)
	}
}

// warnIfCAExpiring warns about one CA.
//
// The expiry is read from the CERTIFICATE, not the expires_at column, for the
// reason the host cert clamp and the renewal check both read it there:
// certificate timestamps have whole-second precision while a stored date can
// carry more, and the certificate is the thing Nebula enforces.
//
// A CA mid-rotation is judged on its CURRENT certificate -- the one issuance
// uses. An incoming CA in next_certificate is by definition freshly minted, and
// an outgoing one in previous_certificate is on its way out; warning about
// either would be noise during the one procedure that fixes this.
func (sm *Manager) warnIfCAExpiring(ca *core.Record, now time.Time) {
	certPEM := ca.GetString("certificate")
	if certPEM == "" {
		return // mid-creation; the create hook owns filling it in
	}

	parsed, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(certPEM))
	if err != nil {
		sm.logger.Warning("Cannot check expiry of CA %s: certificate does not parse: %v",
			ca.GetString("name"), err)
		return
	}

	notAfter := parsed.NotAfter()
	verdict, days := classifyCAExpiry(notAfter, now, sm.options.CAExpiryWarningDays)

	switch verdict {
	case caExpiryFine:
		return
	case caExpiryPast:
		sm.logger.Error("CA %s EXPIRED on %s. Every host certificate it signed is refused, "+
			"and no rotation can be completed cleanly from here -- hosts must be re-issued by hand.",
			ca.GetString("name"), notAfter.Format(time.RFC3339))
		return
	}

	// A prepared rotation means the operator is already on it. Say so rather
	// than repeating the instruction they have started following.
	switch caRotationState(ca) {
	case rotationPrepared:
		sm.logger.Warning("CA %s expires in %d day(s) (%s). A rotation is prepared -- run commit, "+
			"then finish once every active host has migrated.",
			ca.GetString("name"), days, notAfter.Format(time.RFC3339))
	case rotationRotated:
		sm.logger.Warning("CA %s expires in %d day(s) (%s). A rotation is committed -- run finish "+
			"once every active host has migrated.",
			ca.GetString("name"), days, notAfter.Format(time.RFC3339))
	default:
		sm.logger.Warning("CA %s expires in %d day(s) (%s). A CA cannot be renewed, only rotated: "+
			"set rotate=prepare, let every host fetch its config, then commit, then finish.",
			ca.GetString("name"), days, notAfter.Format(time.RFC3339))
	}
}
