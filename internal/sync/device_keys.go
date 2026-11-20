package sync

import (
	"fmt"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/router"
	"github.com/skeeeon/pb-nebula/internal/cert"
	"github.com/skeeeon/pb-nebula/internal/types"
)

// DEVICE-HELD KEYS
//
// A host with device_key = true holds only the public half of its key pair, as
// `nebula-cert keygen` writes it, in public_key. pb-nebula signs that key and
// never stores a private key; the config's pki.key is a path
// (config.DeviceHostKeyPath). An empty public_key means "waiting for the
// device": no certificate and no config_yaml.
//
// Two choke points, not one:
//   - signing: generateHostCertAndConfig, which create, edits, renew,
//     reactivation, the renewal sweep and CA rotation all call;
//   - rendering: generateHostConfigWith, which the peer fan-out and config-only
//     edits call without going near signing. No certificate, no config.
//
// The invariants live here, because the library breaks without them, whoever
// saved the host and however:
//
//  1. device_key is set at create and never changes.
//  2. public_key changes only from empty, and is set only on a device_key host.
//  3. It is a NEBULA X25519 PUBLIC KEY PEM.
//  4. A device_key host never carries a private key.
//
// There is no in-place key reset. Nebula revokes certificates, by fingerprint,
// never keys, so re-signing a leaked key changes nothing: deactivate the host
// and make a new one.

// waitingForDeviceKey reports whether a host's device has yet to send its key.
func waitingForDeviceKey(record *core.Record) bool {
	return record.GetBool("device_key") && record.GetString("public_key") == ""
}

// refuse turns an invariant error into a 400 that still matches errors.Is:
// router.ApiError.Is delegates to its raw data. badRequest flattens the error
// to its message, which a route enrolling a key could not tell apart.
func refuse(err error) error {
	return router.NewBadRequestError(err.Error(), err)
}

// checkHostCreate enforces the device-key invariants on a new host, before it
// is inserted.
func checkHostCreate(record *core.Record) error {
	pub := record.GetString("public_key")
	if !record.GetBool("device_key") {
		if pub != "" {
			return refuse(types.ErrPublicKeyNotDeviceHeld)
		}
		return nil
	}
	if record.GetString("private_key") != "" {
		return refuse(types.ErrDeviceKeyHasSecret)
	}
	if pub != "" {
		return checkHostPublicKey(pub)
	}
	return nil
}

// checkHostUpdate enforces the device-key invariants on a host save, against
// the stored row.
func (sm *Manager) checkHostUpdate(app core.App, record *core.Record) error {
	// pb-nebula's own saves are trusted, and must be: the create hook saves a
	// record whose Original() is still the blank pre-insert snapshot, where
	// every field looks changed.
	if sm.isInternalSave(record) {
		return nil
	}
	original, err := storedHost(app, record)
	if err != nil {
		return err
	}

	deviceKey := record.GetBool("device_key")
	if deviceKey != original.GetBool("device_key") {
		return refuse(types.ErrDeviceKeyFrozen)
	}
	if deviceKey && record.GetString("private_key") != "" {
		return refuse(types.ErrDeviceKeyHasSecret)
	}

	pub := record.GetString("public_key")
	if pub == original.GetString("public_key") {
		return nil
	}
	if !deviceKey {
		return refuse(types.ErrPublicKeyNotDeviceHeld)
	}
	if original.GetString("public_key") != "" {
		return refuse(types.ErrDeviceKeyEnrolled)
	}
	return checkHostPublicKey(pub)
}

// checkHostPublicKey refuses anything but an X25519 public key PEM.
func checkHostPublicKey(pub string) error {
	if _, err := cert.ParseHostPublicKey(pub); err != nil {
		return refuse(err)
	}
	return nil
}

// storedHost is the host as it stands before this save. Original() is that row
// whenever the record was read from the database, but a record created and
// then saved again from the same object keeps the blank pre-insert snapshot.
// That case is replaced by a read, through the app the save runs in, so a row
// created earlier in the same transaction is found.
func storedHost(app core.App, record *core.Record) (*core.Record, error) {
	original := record.Original()
	if original.Id != "" {
		return original, nil
	}
	stored, err := app.FindRecordById(record.Collection(), record.Id)
	if err != nil {
		return nil, fmt.Errorf("read host %s before checking its key: %w", record.Id, err)
	}
	return stored, nil
}
