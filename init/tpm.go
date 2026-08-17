package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/pbkdf2"
)

var enableSwEmulator bool

// swEmulatorAddr is where the emulator path dials. swtpm's default port, and a
// variable so tests can run their own instance on a free one instead of racing
// for a fixed port.
var swEmulatorAddr = ":2321"

func openTPM() (transport.TPMCloser, error) {
	var dev transport.TPMCloser

	if enableSwEmulator {
		conn, err := net.Dial("tcp", swEmulatorAddr)
		if err != nil {
			return nil, err
		}
		dev = transport.FromReadWriteCloser(conn)
	} else {
		var err error
		if dev, err = linuxtpm.Open("/dev/tpmrm0"); err != nil {
			return nil, err
		}
	}

	// reading a fixed property doubles as the "is this a TPM 2.0" probe the
	// legacy GetManufacturer call used to serve
	if _, err := (tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}).Execute(dev); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("device is not a TPM 2.0")
	}

	return dev, nil
}

// tpmAvailable reports whether a TPM 2.0 is reachable, by opening and closing it.
func tpmAvailable() bool {
	dev, err := openTPM()
	if err != nil {
		return false
	}
	_ = dev.Close()
	return true
}

// Waits until a tpm device is available for use. Times out and returns false after 3 seconds.
func tpmAwaitReady() bool {
	timedOut := waitTimeout(&tpmReadyWg, time.Second*3)
	if timedOut {
		info("no tpm devices found after 3 seconds.")
	}
	return !timedOut
}

// extractSRKHandle parses the Intel TSS2 IESYS_RESOURCE_SERIALIZE format that
// systemd uses to store the SRK reference in LUKS2 token JSON (tpm2_srk field).
// Layout: magic[4] version[2] handle[4] ... Falls back to 0x81000001, which is
// systemd's standard persistent SRK handle, on any parse failure.
func extractSRKHandle(srk []byte) tpm2.TPMHandle {
	const iesysMagic = 0x69657379
	if len(srk) >= 10 && binary.BigEndian.Uint32(srk[0:4]) == iesysMagic {
		if h := binary.BigEndian.Uint32(srk[6:10]); h != 0 {
			return tpm2.TPMHandle(h)
		}
	}
	return tpm2.TPMHandle(0x81000001)
}

// tpm2PINAuthValue derives the TPM2 authValue from a PIN, matching systemd's convention.
//
// systemd v255+ ("salted PIN"): authValue = SHA256_trimmed(base64(PBKDF2-HMAC-SHA256(pin, salt, 10000, 32)))
// Older tokens (no salt):       authValue = SHA256_trimmed(pin)
//
// Trailing zero bytes are trimmed per TPM2 spec Part 1 "HMAC Computation" authValue Note 2.
func tpm2PINAuthValue(pin, salt []byte) []byte {
	var input []byte
	if len(salt) > 0 {
		dk := pbkdf2.Key(pin, salt, 10000, 32, sha256.New)
		b64 := base64.StdEncoding.EncodeToString(dk)
		input = []byte(b64)
	} else {
		input = pin
	}
	h := sha256.Sum256(input)
	auth := h[:]
	// Trim trailing zero bytes
	for len(auth) > 0 && auth[len(auth)-1] == 0 {
		auth = auth[:len(auth)-1]
	}
	return auth
}

// classifyTPMFailure maps a TPM response code onto errTPM2TokenMismatch, mirroring
// systemd's ERRNO_IS_NEG_TPM2_TOKEN_MISMATCH. TPMRCAuthFail (a wrong PIN, re-prompt)
// stays unclassified on purpose, as does TPMRCPCRChanged, which systemd retries and
// booster does not.
func classifyTPMFailure(stage string, err error) error {
	switch {
	case errors.Is(err, tpm2.TPMRCPolicyFail):
		return fmt.Errorf("%w (%s rejected the current PCR state: %w)", errTPM2TokenMismatch, stage, err)
	case errors.Is(err, tpm2.TPMRCIntegrity):
		return fmt.Errorf("%w (%s: sealed to a different TPM: %w)", errTPM2TokenMismatch, stage, err)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

// errTPM2TokenMismatch reports a token that cannot match this machine: wrong PCRs,
// a signature that does not authorize them, or a blob sealed to another TPM. Never
// an authentication failure, so the caller moves to the next token rather than
// blaming the PIN. Mirrors systemd's ERRNO_IS_NEG_TPM2_TOKEN_MISMATCH.
var errTPM2TokenMismatch = errors.New("TPM2 token does not match current system state: either the system has been tampered with, or the policy is out of date")

// unsealSRKTemplate is the transient storage primary derived for tokens with no
// tpm2_srk field (systemd pre-v252). The TPM regenerates it from its seed, so any
// change stops those tokens loading: NoDA must stay unset and Unique must hold
// zero-length buffers, which is why legacytpm2.ECCSRKTemplate is not used here.
// TestUnsealSRKTemplateMatchesLegacy pins the equivalence.
var unsealSRKTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		Restricted:          true,
		Decrypt:             true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Symmetric: tpm2.TPMTSymDefObject{
			Algorithm: tpm2.TPMAlgAES,
			KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
			Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
		},
		CurveID: tpm2.TPMECCNistP256,
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{},
		Y: tpm2.TPM2BECCParameter{},
	}),
}

// unsealSRK is the storage parent a sealed blob loads under, carried with its
// public area because salting a session needs the key, not just its handle.
type unsealSRK struct {
	tpm2.NamedHandle
	Public tpm2.TPMTPublic
}

// saltedAndEncrypted protects a session on the wire: the session key is derived
// from a seed encrypted to the SRK, and the response parameter is AES-encrypted.
// Without the salt an eavesdropper on a discrete TPM's bus sees the unsealed key,
// and can grind a PIN offline against the session HMAC.
func (srk unsealSRK) saltedAndEncrypted() []tpm2.AuthOption {
	return []tpm2.AuthOption{
		tpm2.Salted(srk.Handle, srk.Public),
		tpm2.AESEncryption(128, tpm2.EncryptOut),
	}
}

// loadUnsealSRK resolves the storage parent of a sealed blob: the persistent SRK
// named by the token (systemd v252+), or the transient primary above. The returned
// cleanup flushes the transient one.
func loadUnsealSRK(t transport.TPM, srkHandle uint32) (unsealSRK, func(), error) {
	noop := func() {}
	if srkHandle != 0 {
		// Persistent handle: never flushed, that would evict it from the TPM.
		rp, err := (&tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(srkHandle)}).Execute(t)
		if err != nil {
			return unsealSRK{}, noop, fmt.Errorf("reading SRK %#x: %w", srkHandle, err)
		}
		pub, err := rp.OutPublic.Contents()
		if err != nil {
			return unsealSRK{}, noop, fmt.Errorf("reading SRK %#x public area: %w", srkHandle, err)
		}
		return unsealSRK{
			NamedHandle: tpm2.NamedHandle{Handle: tpm2.TPMHandle(srkHandle), Name: rp.Name},
			Public:      *pub,
		}, noop, nil
	}
	cp, err := (&tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(unsealSRKTemplate),
	}).Execute(t)
	if err != nil {
		return unsealSRK{}, noop, fmt.Errorf("creating SRK: %w", err)
	}
	pub, err := cp.OutPublic.Contents()
	if err != nil {
		return unsealSRK{}, noop, fmt.Errorf("reading created SRK public area: %w", err)
	}
	return unsealSRK{
			NamedHandle: tpm2.NamedHandle{Handle: cp.ObjectHandle, Name: cp.Name},
			Public:      *pub,
		},
		func() { _, _ = (&tpm2.FlushContext{FlushHandle: cp.ObjectHandle}).Execute(t) }, nil
}

// literalPolicySession rebuilds the policy a literal-PCR token was sealed against
// and checks the digest. systemd seals PolicyPCR then PolicyAuthValue, and the
// digest only matches when that order is reproduced exactly. It never depends on
// the PIN's value, since PolicyAuthValue contributes a fixed constant, which is
// what lets callers test satisfiability before prompting.
// srk is nil when the caller only tests satisfiability: nothing secret crosses
// the bus there, and salting would cost an SRK load before the PIN prompt.
func literalPolicySession(t transport.TPM, srk *unsealSRK, pcrs []int, bank tpm2.TPMAlgID, expectedDigest []byte, pin []byte, usePIN bool) (tpm2.Session, func() error, error) {
	var opts []tpm2.AuthOption
	if len(pin) > 0 {
		opts = append(opts, tpm2.Auth(pin))
	}
	if srk != nil {
		opts = append(opts, srk.saltedAndEncrypted()...)
	}
	sess, cleanup, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("starting policy session: %w", err)
	}

	if len(pcrs) > 0 {
		pcrsU := make([]uint, len(pcrs))
		for i, p := range pcrs {
			pcrsU[i] = uint(p)
		}
		sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      bank,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcrsU...),
		}}}
		if _, err := (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(t); err != nil {
			cleanup()
			return nil, nil, classifyTPMFailure("PolicyPCR", err)
		}
	}

	if usePIN {
		if _, err := (&tpm2.PolicyAuthValue{PolicySession: sess.Handle()}).Execute(t); err != nil {
			cleanup()
			return nil, nil, classifyTPMFailure("PolicyAuthValue", err)
		}
	}

	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(t)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("reading policy digest: %w", err)
	}
	if !bytes.Equal(pgd.PolicyDigest.Buffer, expectedDigest) {
		cleanup()
		return nil, nil, fmt.Errorf("%w (PCR values changed since enrollment, PCRs %v)", errTPM2TokenMismatch, pcrs)
	}
	return sess, cleanup, nil
}

// tpm2PolicySatisfiable reports whether the live PCRs still satisfy the digest
// stored in the token. Needs no PIN and does not unseal, so it can run before
// prompting.
func tpm2PolicySatisfiable(pcrs []int, bankName string, expectedDigest []byte, usePIN bool) error {
	tpmAwaitReady()

	dev, err := openTPM()
	if err != nil {
		return err
	}
	defer dev.Close()

	_, cleanup, err := literalPolicySession(dev, nil, pcrs, pcrBankAlgID(bankName), expectedDigest, nil, usePIN)
	if err != nil {
		return err
	}
	cleanup()
	return nil
}

func tpm2Unseal(public, private []byte, pcrs []int, bankName string, policyHash, pin []byte, srkHandle uint32) ([]byte, error) {
	tpmAwaitReady()

	dev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer dev.Close()
	t := dev

	srk, flush, err := loadUnsealSRK(t, srkHandle)
	if err != nil {
		return nil, err
	}
	defer flush()

	pubArea, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, fmt.Errorf("parsing sealed object public area: %w", err)
	}
	loadRsp, err := (&tpm2.Load{
		ParentHandle: srk,
		InPrivate:    tpm2.TPM2BPrivate{Buffer: private},
		InPublic:     tpm2.New2B(*pubArea),
	}).Execute(t)
	if err != nil {
		return nil, classifyTPMFailure("loading sealed object", err)
	}
	defer func() { _, _ = (&tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}).Execute(t) }()

	sess, cleanup, err := literalPolicySession(t, &srk, pcrs, pcrBankAlgID(bankName), policyHash, pin, len(pin) > 0)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	unseal, err := (&tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: loadRsp.ObjectHandle,
		Name:   loadRsp.Name,
		Auth:   sess,
	}}).Execute(t)
	if err != nil {
		return nil, classifyTPMFailure("unseal", err)
	}
	return unseal.OutData.Buffer, nil
}

// pcrSystemIdentity is the PCR systemd reserves as "system-identity": it is
// populated (not consumed) by FDE so later objects can be bound to the unlocked
// volume. Booster extends it after unseal to close the TPM re-unseal oracle.
const pcrSystemIdentity = 15

// pcrKernelBoot is PCR 11 ("kernel-boot"): systemd-stub measures the UKI's
// sections into it at boot, and systemd-pcrphase extends boot-phase words into
// it as barriers. A signed PCR policy binds the volume key to this PCR, so its
// value at unseal must match systemd's — which, in the initrd, is the UKI
// measurement plus the "enter-initrd" phase word.
const pcrKernelBoot = 11

// Boot-phase words measured into PCR 11. enter-initrd is extended before
// unsealing a PCR11-bound volume so the live PCR matches systemd's signed
// policy; leave-initrd after, at switch_root, as a forward-lock that bars
// re-unsealing the initrd key once the host has taken over.
const (
	phaseEnterInitrd = "enter-initrd"
	phaseLeaveInitrd = "leave-initrd"
)

// xescapeColon mirrors systemd's xescape(s, ":") (src/basic/escape.c): it
// escapes ':' (the delimiter), '\\', control bytes (<0x20) and high/DEL bytes
// (>=0x7f) as lowercase \xNN, copying everything else verbatim. Used to build
// the volume-key measurement message byte-compatibly with systemd-cryptsetup.
func xescapeColon(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '\\' || c == ':' {
			fmt.Fprintf(&b, "\\x%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// cryptoHashForPCRBank maps a TPM PCR bank algorithm to its crypto.Hash.
// ok is false for algorithms booster cannot handle, letting the caller fail
// closed rather than silently leave that bank's PCR un-extended.
func cryptoHashForPCRBank(alg tpm2.TPMAlgID) (h crypto.Hash, ok bool) {
	switch alg {
	case tpm2.TPMAlgSHA1:
		return crypto.SHA1, true
	case tpm2.TPMAlgSHA256:
		return crypto.SHA256, true
	case tpm2.TPMAlgSHA384:
		return crypto.SHA384, true
	case tpm2.TPMAlgSHA512:
		return crypto.SHA512, true
	}
	return 0, false
}

// activePCRBanks returns the hash algorithms of the TPM's allocated PCR banks.
// A bank the TPM reports with an all-zero selection has no PCRs allocated, so it
// is not a bank booster must extend.
func activePCRBanks(t transport.TPM) ([]tpm2.TPMAlgID, error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapPCRs,
		PropertyCount: 64,
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	sel, err := rsp.CapabilityData.Data.AssignedPCR()
	if err != nil {
		return nil, err
	}

	var banks []tpm2.TPMAlgID
	for _, s := range sel.PCRSelections {
		allocated := false
		for _, b := range s.PCRSelect {
			if b != 0 {
				allocated = true
				break
			}
		}
		if allocated {
			banks = append(banks, s.Hash)
		}
	}
	return banks, nil
}

// extendPCR extends one PCR in one bank. The PCR index is its own auth handle
// and takes an empty password, which is how systemd extends them too.
func extendPCR(t transport.TPM, pcr int, bank tpm2.TPMAlgID, digest []byte) error {
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcr),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{{HashAlg: bank, Digest: digest}},
		},
	}.Execute(t)
	return err
}

// volumeKeyHMACer computes HMAC(volume_key, message) with a caller-named hash
// algorithm, without exposing the master key. luks.Volume implements it, so the
// volume key never leaves the LUKS library — only the resulting digest (the
// value measured into the PCR, which is not secret) crosses into booster. The
// hash is a crypto.Hash identifier, not a constructor, so the caller cannot
// supply an implementation that observes the key. This is stricter than
// libcryptsetup's crypt_volume_key_get, which hands the raw key to the caller.
type volumeKeyHMACer interface {
	HMAC(h crypto.Hash, message []byte) ([]byte, error)
}

// measureVolumeKeyToPCR15 extends PCR15 with the systemd-compatible volume-key
// measurement after a volume is unsealed, so a key sealed to an uninitialized
// PCR15 cannot be re-unsealed for the rest of the boot. It matches
// systemd-cryptsetup's tpm2-measure-pcr=yes: for every active PCR bank it
// extends HMAC-<bank>(volume_key, "cryptsetup:" + name + ":" + uuid) using that
// bank's own hash algorithm. Extending ALL active banks is required — a policy
// satisfiable via an un-extended bank would otherwise be bypassable.
func measureVolumeKeyToPCR15(k volumeKeyHMACer, volumeName, luksUUID string) error {
	dev, err := openTPM()
	if err != nil {
		return err
	}
	defer dev.Close()

	banks, err := activePCRBanks(dev)
	if err != nil {
		return fmt.Errorf("reading active PCR banks: %v", err)
	}
	if len(banks) == 0 {
		return fmt.Errorf("no active PCR banks to extend")
	}

	msg := []byte("cryptsetup:" + xescapeColon(volumeName) + ":" + luksUUID)

	for _, bank := range banks {
		h, ok := cryptoHashForPCRBank(bank)
		if !ok {
			return fmt.Errorf("unsupported active PCR bank %v; refusing to leave PCR%d un-extended", bank, pcrSystemIdentity)
		}
		digest, err := k.HMAC(h, msg)
		if err != nil {
			return fmt.Errorf("computing PCR%d measurement for bank %v: %v", pcrSystemIdentity, bank, err)
		}
		if err := extendPCR(dev, pcrSystemIdentity, bank, digest); err != nil {
			return fmt.Errorf("extending PCR%d in bank %v: %v", pcrSystemIdentity, bank, err)
		}
	}
	debug("PCR%d: extended across %d active bank(s) %v for %s", pcrSystemIdentity, len(banks), banks, volumeName)
	return nil
}

// measurePhaseToPCR11 extends PCR11 with a boot-phase word, byte-compatible with
// systemd-pcrextend (src/shared/tpm2-util.c tpm2_pcr_extend_bytes, secret=NULL):
// for every active bank it extends bankHash(word) — the raw ASCII word, no NUL
// terminator and a plain digest rather than the HMAC the PCR15 latch uses. All
// active banks are extended so a policy can't be satisfied via an un-extended
// bank. Fails closed: any extend error aborts the caller.
func measurePhaseToPCR11(word string) error {
	dev, err := openTPM()
	if err != nil {
		return err
	}
	defer dev.Close()

	banks, err := activePCRBanks(dev)
	if err != nil {
		return fmt.Errorf("reading active PCR banks: %v", err)
	}
	if len(banks) == 0 {
		return fmt.Errorf("no active PCR banks to extend")
	}

	for _, bank := range banks {
		h, ok := cryptoHashForPCRBank(bank)
		if !ok {
			return fmt.Errorf("unsupported active PCR bank %v; refusing to leave PCR%d un-extended", bank, pcrKernelBoot)
		}
		hh := h.New()
		hh.Write([]byte(word))
		if err := extendPCR(dev, pcrKernelBoot, bank, hh.Sum(nil)); err != nil {
			return fmt.Errorf("extending PCR%d in bank %v: %v", pcrKernelBoot, bank, err)
		}
	}
	debug("PCR%d: extended phase %q across %d active bank(s) %v", pcrKernelBoot, word, len(banks), banks)
	return nil
}

var (
	enterInitrdOnce    sync.Once
	enterInitrdErr     error
	enterInitrdApplied bool // true once "enter-initrd" was extended, so switch_root can apply the "leave-initrd" forward-lock
)

// ensureEnterInitrdBarrier extends PCR11 with "enter-initrd" exactly once for the
// boot, before the first PCR11-bound unseal, so the live PCR11 equals the value a
// systemd signed policy (signed for the enter-initrd phase) is bound to.
// systemd-pcrphase-initrd.service does this Before=cryptsetup.target; booster
// runs no pcrphase, so it does it here. Idempotent across volumes and PIN
// retries — PCR extension is monotonic, so extending twice would be the wrong
// value. Fails closed: the error propagates so the caller aborts the unseal.
func ensureEnterInitrdBarrier() error {
	enterInitrdOnce.Do(func() {
		if enterInitrdErr = measurePhaseToPCR11(phaseEnterInitrd); enterInitrdErr == nil {
			enterInitrdApplied = true
		}
	})
	return enterInitrdErr
}

// applyBootPhaseForwardLock extends PCR11 with the enter-initrd then leave-initrd
// phase words before switch_root, on every boot regardless of whether anything
// unlocked — matching what systemd-pcrphase-initrd measures. enter-initrd goes
// through ensureEnterInitrdBarrier (sync.Once), so it is extended at most once
// per boot. Best-effort: a failed extend warns rather than aborting handoff.
func applyBootPhaseForwardLock() {
	if err := ensureEnterInitrdBarrier(); err != nil {
		// ensureEnterInitrdBarrier failed (no TPM, or the extend errored); skip the
		// leave-initrd extend.
		debug("PCR%d: enter-initrd barrier unavailable, skipping forward-lock: %v", pcrKernelBoot, err)
		return
	}
	if err := measurePhaseToPCR11(phaseLeaveInitrd); err != nil {
		warning("PCR%d: could not extend leave-initrd forward-lock: %v", pcrKernelBoot, err)
	}
}
