package main

import (
	"errors"
	"testing"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

// currentPolicyDigest computes the policy digest the live PCRs produce, the
// value systemd-cryptenroll would have stored as tpm2-policy-hash at enrollment.
// It builds the session the same way literalPolicySession does but without the
// comparison, since the comparison is what the tests below exercise.
func currentPolicyDigest(t *testing.T, pcrs []int, bankName string, usePIN bool) []byte {
	t.Helper()
	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()
	th := transport.FromReadWriteCloser(dev)

	sess, cleanup, err := tpm2.PolicySession(th, tpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	defer func() { require.NoError(t, cleanup()) }()

	pcrsU := make([]uint, len(pcrs))
	for i, p := range pcrs {
		pcrsU[i] = uint(p)
	}
	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      pcrBankAlgID(bankName),
		PCRSelect: tpm2.PCClientCompatible.PCRs(pcrsU...),
	}}}
	_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(th)
	require.NoError(t, err)
	if usePIN {
		_, err = (&tpm2.PolicyAuthValue{PolicySession: sess.Handle()}).Execute(th)
		require.NoError(t, err)
	}
	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(th)
	require.NoError(t, err)
	return pgd.PolicyDigest.Buffer
}

// TestTPM2PolicySatisfiableDetectsMovedPCR is the regression guard for a moved
// PCR being reported as a bad PIN. A PIN-bound token's policy digest is fixed by
// the PCRs alone (PolicyAuthValue contributes a constant, not the PIN), so a
// mismatch can be detected before prompting, and no PIN could satisfy it anyway.
// Booster used to discover this only inside the unseal, after the prompt, and
// then relabel it "TPM2 PIN incorrect" and re-prompt twice more.
func TestTPM2PolicySatisfiableDetectsMovedPCR(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	const pcr = 10
	pcrs := []int{pcr}
	const bank = "sha256"

	enrolled := currentPolicyDigest(t, pcrs, bank, true)

	// Nothing has moved yet, so the sealed policy is still satisfiable.
	require.NoError(t, tpm2PolicySatisfiable(pcrs, bank, enrolled, true))

	// Move a bound PCR, as toggling Secure Boot or a firmware update would.
	dev, err := openTPM()
	require.NoError(t, err)
	require.NoError(t, legacytpm2.PCRExtend(dev, tpmutil.Handle(pcr), legacytpm2.AlgSHA256, make([]byte, 32), ""))
	require.NoError(t, dev.Close())

	err = tpm2PolicySatisfiable(pcrs, bank, enrolled, true)
	require.ErrorIs(t, err, errTPM2TokenMismatch,
		"a moved PCR must be reported as a policy mismatch, not as an authentication failure")
}

// TestTPM2PolicyMismatchSurvivesWrapping pins the %w in literalPolicySession's error.
// The pre-check and the retry loop both branch on errors.Is, so downgrading that
// verb to %v would silently restore the old behaviour: a PIN prompt that cannot
// succeed, reported as incorrect.
func TestTPM2PolicyMismatchSurvivesWrapping(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	pcrs := []int{10}

	// A digest that cannot match any live PCR state.
	err := tpm2PolicySatisfiable(pcrs, "sha256", make([]byte, 32), false)
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
		{"policy refused", tpm2.TPMRCPolicyFail, true},
		{"sealed to another TPM", tpm2.TPMRCIntegrity, true},
		{"wrong PIN", tpm2.TPMRCAuthFail, false},
		{"PCRs moved mid-session", tpm2.TPMRCPCRChanged, false},
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

// TestUnsealSRKTemplateMatchesLegacy guards the transient storage primary that
// tokens without a tpm2_srk field (systemd pre-v252) are sealed under. The TPM
// regenerates that key from its seed, so the template must match the one
// booster's legacy go-tpm code used exactly. Any drift changes the key and the
// blob stops loading with an integrity error. go-tpm's own ECCSRKTemplate is a
// different key and is checked here so nobody swaps it in.
func TestUnsealSRKTemplateMatchesLegacy(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()

	// The template booster used before the move to the new go-tpm API.
	legacyHandle, _, err := legacytpm2.CreatePrimary(dev, legacytpm2.HandleOwner, legacytpm2.PCRSelection{}, "", "", legacytpm2.Public{
		Type:       legacytpm2.AlgECC,
		NameAlg:    legacytpm2.AlgSHA256,
		Attributes: legacytpm2.FlagStorageDefault,
		ECCParameters: &legacytpm2.ECCParams{
			Symmetric: &legacytpm2.SymScheme{Alg: legacytpm2.AlgAES, KeyBits: 128, Mode: legacytpm2.AlgCFB},
			CurveID:   legacytpm2.CurveNISTP256,
		},
	})
	require.NoError(t, err)
	_, legacyName, _, err := legacytpm2.ReadPublic(dev, legacyHandle)
	require.NoError(t, err)
	require.NoError(t, legacytpm2.FlushContext(dev, legacyHandle))

	th := transport.FromReadWriteCloser(dev)
	srk, flush, err := loadUnsealSRK(th, 0)
	require.NoError(t, err)
	defer flush()
	require.Equal(t, legacyName, srk.Name.Buffer,
		"unsealSRKTemplate must derive the same primary as the legacy template, or pre-v252 tokens stop unsealing")

	// And the library's standard template must not: if these ever coincide the
	// distinction this template exists for has gone away.
	other, err := (&tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}).Execute(th)
	require.NoError(t, err)
	defer func() { _, _ = (&tpm2.FlushContext{FlushHandle: other.ObjectHandle}).Execute(th) }()
	require.NotEqual(t, legacyName, other.Name.Buffer,
		"ECCSRKTemplate is expected to derive a different primary")
}
