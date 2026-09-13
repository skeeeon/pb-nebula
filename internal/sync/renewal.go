package sync

import (
	"fmt"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	nebulacert "github.com/slackhq/nebula/cert"

	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/types"
)

// SetupCron registers pb-nebula's background jobs.
//
// Registration happens during OnBootstrap, which runs before PocketBase binds
// OnServe -- and OnServe is where app.Cron().Start() lives. So a job added here
// is scheduled in time, and it only ever runs under `serve`, never under a
// one-shot CLI command like `superuser create`. That is the behavior we want:
// no CLI invocation should quietly re-issue certificates.
//
// RETURNS:
// - nil on success (including when every job is disabled)
// - error if a cron expression is rejected
//
// SIDE EFFECTS: Registers scheduled jobs on the PocketBase app.
func (sm *Manager) SetupCron() error {
	// The CA expiry warning is registered FIRST and unconditionally, because it
	// is not part of renewal and must not be switched off with it. A CA cannot
	// be renewed at all -- only rotated, by hand, with a wait in the middle --
	// so an operator who has turned automatic re-issue off wants more warning
	// about an expiring CA, not none.
	if err := sm.app.Cron().Add(types.CAExpiryCronJobID, types.DefaultCAExpiryCron, func() {
		sm.WarnOnExpiringCAs()
	}); err != nil {
		return fmt.Errorf("failed to schedule CA expiry check: %w", err)
	}

	sm.logger.Success("CA expiry check scheduled (%s, warning %d days ahead)",
		types.DefaultCAExpiryCron, sm.options.CAExpiryWarningDays)

	if sm.options.DisableHostCertRenewal {
		sm.logger.Info("Host certificate renewal is disabled")
		return nil
	}

	if err := sm.app.Cron().Add(types.HostRenewalCronJobID, sm.options.HostRenewalCron, func() {
		sm.renewExpiringHostCerts()
	}); err != nil {
		return fmt.Errorf("failed to schedule host certificate renewal: %w", err)
	}

	sm.logger.Success("Host certificate renewal scheduled (%s, threshold %.0f%%)",
		sm.options.HostRenewalCron, sm.options.HostRenewalThreshold*100)

	return nil
}

// shouldRenew reports whether a certificate has consumed enough of its lifetime
// to be re-issued.
//
// now is a parameter rather than a call to time.Now() so a test can advance the
// clock without sleeping, and so the whole sweep evaluates every host against
// one consistent instant.
//
// PARAMETERS:
//   - notBefore, notAfter: the certificate's own validity window
//   - now: evaluation time
//   - threshold: fraction of remaining lifetime at or below which to renew
//
// RETURNS:
// - true if the certificate is expired, degenerate, or past the threshold
//
// SIDE EFFECTS: None (pure).
func shouldRenew(notBefore, notAfter, now time.Time, threshold float64) bool {
	// Already expired: renewing cannot make things worse
	if !now.Before(notAfter) {
		return true
	}

	total := notAfter.Sub(notBefore)
	if total <= 0 {
		// Degenerate window (clock skew, a hand-edited record). Treat as due
		// rather than dividing by zero.
		return true
	}

	return float64(notAfter.Sub(now))/float64(total) <= threshold
}

// renewExpiringHostCerts re-issues every active host certificate that has passed
// the renewal threshold.
//
// ONLY ACTIVE HOSTS:
// An inactive host is revoked -- its fingerprint is in every peer's
// pki.blocklist. Re-issuing it would change that fingerprint, so getBlocklist
// would publish the NEW one while the OLD certificate stays valid and
// unblocklisted. Renewing a revoked host would therefore un-revoke it. Same
// rule, and the same reason, as the CA rotation sweep.
//
// FAILURES ARE PER-HOST:
// One unreadable certificate or one record that fails auth validation must not
// stop the sweep, so failures are logged and skipped -- matching
// regenerateNetworkHostConfigs.
//
// SIDE EFFECTS: Re-issues certificates and writes host records.
func (sm *Manager) renewExpiringHostCerts() {
	if !sm.shouldHandleEvent(sm.options.HostCollectionName, types.EventTypeHostRenew) {
		return
	}

	sm.generation.Lock()
	defer sm.generation.Unlock()

	records, err := sm.app.FindAllRecords(sm.options.HostCollectionName,
		dbx.HashExp{"active": true})
	if err != nil {
		sm.logger.Error("Host certificate renewal sweep failed to list hosts: %v", err)
		return
	}

	// One instant for the whole sweep, so two hosts with identical certificates
	// cannot reach different decisions
	now := time.Now()
	renewed := 0

	for _, record := range records {
		// Re-read immediately before generating. The slice above may be seconds
		// old by the time we reach this host, and an operator edit in between
		// would otherwise be clobbered by the write below.
		fresh, err := sm.app.FindRecordById(sm.options.HostCollectionName, record.Id)
		if err != nil {
			sm.logger.Warning("Skipping renewal for host %s: %v", record.GetString("hostname"), err)
			continue
		}

		due, err := sm.hostCertNeedsRenewal(fresh, now)
		if err != nil {
			sm.logger.Warning("Skipping renewal for host %s: %v", fresh.GetString("hostname"), err)
			continue
		}
		if !due {
			continue
		}

		sm.logger.Cert("Renewing certificate for host %s...", fresh.GetString("hostname"))

		if err := sm.generateHostCertAndConfig(fresh); err != nil {
			sm.logger.Warning("Failed to renew certificate for host %s: %v", fresh.GetString("hostname"), err)
			continue
		}
		if err := sm.saveInternal(fresh); err != nil {
			sm.logger.Warning("Failed to save renewed certificate for host %s: %v", fresh.GetString("hostname"), err)
			continue
		}

		renewed++
	}

	if renewed > 0 {
		sm.logger.Success("Renewed %d host certificate(s)", renewed)
	}
}

// hostCertNeedsRenewal decides whether one host's certificate should be
// re-issued now.
//
// THE CLAMP TRAP THIS GUARDS:
// GenerateHostCert clamps NotAfter to the CA certificate's own NotAfter. Once
// the CA's expiry is the binding constraint, a re-issued certificate carries
// the SAME NotAfter as the one it replaced -- so it is still past the renewal
// threshold, and the host would be re-signed on every sweep until the CA
// expires. That is a nightly fingerprint change and a full config fan-out for
// no benefit, arriving exactly when the CA needs calm attention instead.
//
// So a host whose renewal would gain nothing is skipped with a warning naming
// the real problem. The fix is CA rotation, not another certificate.
//
// PARAMETERS:
//   - record: Host record
//   - now: evaluation time
//
// RETURNS:
// - true if the certificate should be re-issued now
// - error if the certificate or its CA cannot be read
//
// SIDE EFFECTS: Logging only.
func (sm *Manager) hostCertNeedsRenewal(record *core.Record, now time.Time) (bool, error) {
	certPEM := record.GetString("certificate")
	if certPEM == "" {
		// A host mid-creation, before its certificate is generated. The create
		// hook owns that; the sweep should not race it.
		return false, nil
	}

	notBefore, notAfter, err := cert.ValidityFromPEM(certPEM)
	if err != nil {
		return false, fmt.Errorf("certificate does not parse: %w", err)
	}

	if !shouldRenew(notBefore, notAfter, now, sm.options.HostRenewalThreshold) {
		return false, nil
	}

	// Would a new certificate actually last longer than the one we have?
	network, err := sm.app.FindRecordById(sm.options.NetworkCollectionName, record.GetString("network_id"))
	if err != nil {
		return false, fmt.Errorf("%w: %v", types.ErrNetworkNotFound, err)
	}
	ca, err := sm.app.FindRecordById(sm.options.CACollectionName, network.GetString("ca_id"))
	if err != nil {
		return false, fmt.Errorf("%w: %v", types.ErrCANotFound, err)
	}

	caCert, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(ca.GetString("certificate")))
	if err != nil {
		return false, fmt.Errorf("CA certificate does not parse: %w", err)
	}

	// The clamp means a renewed certificate can never expire after the CA, so
	// if the current certificate already ends at (or after) the CA's own expiry
	// there is nothing left to gain.
	if !notAfter.Before(caCert.NotAfter()) {
		sm.logger.Warning("Host %s cannot be renewed past CA %s (expires %s) -- rotate the CA",
			record.GetString("hostname"), ca.GetString("name"), caCert.NotAfter().Format(time.RFC3339))
		return false, nil
	}

	return true, nil
}
