//go:build !cgo

package main

import "fmt"

func fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool) ([]byte, error) {
	return nil, fmt.Errorf("FIDO2 not supported in this build (requires CGO)")
}

func isFido2PinInvalidError(err error) bool {
	return false
}
