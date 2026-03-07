//go:build cgo

package main

import (
	"encoding/base64"
	"errors"
	"fmt"

	libfido2 "github.com/keys-pub/go-libfido2"
)

func fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool) ([]byte, error) {
	// go-libfido2 passes empty string as NULL to fido_dev_get_assert, which
	// bypasses PIN verification and proceeds to touch. When a PIN is required,
	// reject empty input immediately so the retry loop re-prompts the user.
	if pinRequired && pin == "" {
		return nil, libfido2.ErrPinInvalid
	}

	dev, err := libfido2.NewDevice(devPath)
	if err != nil {
		return nil, err
	}

	opts := &libfido2.AssertionOpts{
		Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		HMACSalt:   saltBytes,
	}
	if userPresenceRequired {
		opts.UP = libfido2.True
	}
	if userVerificationRequired {
		opts.UV = libfido2.True
	}

	// clientDataHash: 32 zero bytes — matches fido2-assert's challenge "AAAA...AA=".
	// The HMAC-secret output is not affected by this value.
	var clientDataHash [32]byte

	assertion, err := dev.Assertion(relyingParty, clientDataHash[:], [][]byte{credID}, pin, opts)
	if err != nil {
		return nil, err
	}
	if len(assertion.HMACSecret) == 0 {
		return nil, fmt.Errorf("no HMAC secret in assertion")
	}

	// Encode as base64 to match the format expected by the LUKS token handler.
	return []byte(base64.StdEncoding.EncodeToString(assertion.HMACSecret)), nil
}

func isFido2PinInvalidError(err error) bool {
	return errors.Is(err, libfido2.ErrPinInvalid)
}
