package main

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	tpm2new "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

// currentPolicyDigest computes the policy digest the live PCRs produce, the
// value systemd-cryptenroll would have stored as tpm2-policy-hash at enrollment.
// It builds the session the same way policyPCRSession does but without the
// comparison, since the comparison is what the tests below exercise.
func currentPolicyDigest(t *testing.T, pcrs []int, bank tpm2.Algorithm, usePassword bool) []byte {
	t.Helper()
	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()

	sess, _, err := tpm2.StartAuthSession(dev, tpm2.HandleNull, tpm2.HandleNull,
		make([]byte, 32), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	require.NoError(t, err)
	defer tpm2.FlushContext(dev, sess)

	require.NoError(t, tpm2.PolicyPCR(dev, sess, nil, tpm2.PCRSelection{Hash: bank, PCRs: pcrs}))
	if usePassword {
		require.NoError(t, tpm2.PolicyPassword(dev, sess))
	}
	digest, err := tpm2.PolicyGetDigest(dev, sess)
	require.NoError(t, err)
	return digest
}

// TestTPM2PolicySatisfiableDetectsMovedPCR is the regression guard for a moved
// PCR being reported as a bad PIN. A PIN-bound token's policy digest is fixed by
// the PCRs alone — PolicyPassword contributes a constant, not the PIN — so a
// mismatch can be detected before prompting, and no PIN could satisfy it anyway.
// Booster used to discover this only inside the unseal, after the prompt, and
// then relabel it "TPM2 PIN incorrect" and re-prompt twice more.
func TestTPM2PolicySatisfiableDetectsMovedPCR(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	const pcr = 10
	pcrs := []int{pcr}
	bank := tpm2.AlgSHA256

	enrolled := currentPolicyDigest(t, pcrs, bank, true)

	// Nothing has moved yet, so the sealed policy is still satisfiable.
	require.NoError(t, tpm2PolicySatisfiable(pcrs, bank, enrolled, true))

	// Move a bound PCR, as toggling Secure Boot or a firmware update would.
	dev, err := openTPM()
	require.NoError(t, err)
	require.NoError(t, tpm2.PCRExtend(dev, tpmutil.Handle(pcr), bank, make([]byte, 32), ""))
	require.NoError(t, dev.Close())

	err = tpm2PolicySatisfiable(pcrs, bank, enrolled, true)
	require.ErrorIs(t, err, errTPM2TokenMismatch,
		"a moved PCR must be reported as a policy mismatch, not as an authentication failure")
}

// TestTPM2PolicyMismatchSurvivesWrapping pins the %w in policyPCRSession's error.
// The pre-check and the retry loop both branch on errors.Is, so downgrading that
// verb to %v would silently restore the old behaviour: a PIN prompt that cannot
// succeed, reported as incorrect.
func TestTPM2PolicyMismatchSurvivesWrapping(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	pcrs := []int{10}
	bank := tpm2.AlgSHA256

	// A digest that cannot match any live PCR state.
	err := tpm2PolicySatisfiable(pcrs, bank, make([]byte, 32), false)
	require.ErrorIs(t, err, errTPM2TokenMismatch)
	require.Contains(t, err.Error(), "PCRs [10]", "the error should name the bound PCRs")
}


// TestClassifyTPMFailure pins the signed-path classification. The distinction is
// the whole point: a policy the TPM refuses means this token cannot work on this
// machine and the caller should move on, whereas an auth failure means the PIN
// really was wrong and re-prompting is correct. Collapsing the two is what made a
// moved PCR read as a forgotten PIN.
func TestClassifyTPMFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rc       error
		mismatch bool
	}{
		{"policy refused", tpm2new.TPMRCPolicyFail, true},
		{"sealed to another TPM", tpm2new.TPMRCIntegrity, true},
		{"wrong PIN", tpm2new.TPMRCAuthFail, false},
		{"PCRs moved mid-session", tpm2new.TPMRCPCRChanged, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyTPMFailure("unseal", tc.rc)
			require.Error(t, err)
			require.Equal(t, tc.mismatch, errors.Is(err, errTPM2TokenMismatch),
				"token-mismatch classification for %v", tc.rc)
			// The underlying code stays reachable either way, so callers and logs
			// can still see what the TPM actually said.
			require.ErrorIs(t, err, tc.rc)
		})
	}
}
