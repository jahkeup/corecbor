// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package edhoc

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"slices"

	"github.com/jahkeup/corecbor/cbor"
)

// EDHOC_KDF info labels (RFC 9528 §4.1.2, §4.2).
const (
	labelKeystream2  = 0
	labelSalt3e2m    = 1
	labelMAC2        = 2
	labelK3          = 3
	labelIV3         = 4
	labelSalt4e3m    = 5
	labelMAC3        = 6
	labelPRKOut      = 7
	labelK4          = 8
	labelIV4         = 9
	labelPRKExporter = 10
	labelKeyUpdate   = 11
)

// OSCORE exporter labels (RFC 9528 Appendix A.1).
const (
	exporterOSCOREMasterSecret = 0
	exporterOSCOREMasterSalt   = 1
)

type sessionState int

const (
	stateInit sessionState = iota
	stateWaitM2
	stateWaitM3
	stateCompleted
	stateFailed
	stateClosed
)

// session is one RFC 9528 EDHOC run, for either role.
type session struct {
	initiator bool
	state     sessionState
	method    Method
	suite     *rfcSuite
	party     credParty
	rand      io.Reader
	accept    func(EADItem) bool

	ownCID, peerCID []byte
	allocCID        func(peer ConnectionID) (ConnectionID, error)
	cidHold         *cidHold          // this session's hold on ownCID (default allocator)
	ownEAD          map[int][]EADItem // by message number
	peerEAD         []EADItem

	eph     *ecdh.PrivateKey
	peerEph *ecdh.PublicKey

	ownCred, peerCred *Credential

	hMsg1                    []byte
	th2, th3, th4            []byte
	prk2e, prk3e2m, prk4e3m  []byte
	prkOut, prkExporter      []byte
	message4Sent, message4OK bool

	// trace, when set (tests), receives intermediate values by their
	// RFC 9529 names.
	trace func(name string, v []byte)
}

func (s *session) t(name string, v []byte) {
	if s.trace != nil {
		s.trace(name, v)
	}
}

// fail records a terminal failure, zeroizes secrets, and returns err.
func (s *session) fail(err error) error {
	if s.state != stateClosed {
		s.state = stateFailed
	}
	s.zeroize()
	s.cidHold.release()
	// Nothing received from an unauthenticated peer stays visible
	// (RFC 9528 §5.3.3, §5.4.3).
	s.peerCred, s.peerEAD = nil, nil
	return err
}

func (s *session) zeroize() {
	for _, b := range [][]byte{s.th2, s.th3, s.th4, s.prk2e, s.prk3e2m, s.prk4e3m, s.prkOut, s.prkExporter, s.hMsg1} {
		clear(b)
	}
	s.th2, s.th3, s.th4 = nil, nil, nil
	s.prk2e, s.prk3e2m, s.prk4e3m, s.prkOut, s.prkExporter, s.hMsg1 = nil, nil, nil, nil, nil, nil
	s.eph = nil
}

func (s *session) close() {
	s.zeroize()
	s.cidHold.release()
	s.state = stateClosed
}

func (s *session) want(st sessionState) error {
	if s.state != st {
		return fmt.Errorf("%w: operation not valid in current state", ErrStateViolation)
	}
	return nil
}

func (s *session) randReader() io.Reader {
	if s.rand != nil {
		return s.rand
	}
	return rand.Reader
}

func (s *session) authPublic(signs bool) (any, error) {
	if signs {
		if s.party.signer == nil {
			return nil, fmt.Errorf("%w: signature authentication needs PrivateKey", ErrStateViolation)
		}
		return s.party.signer.Public(), nil
	}
	dh, err := s.suite.staticPrivate(s.party.dhKey)
	if err != nil {
		return nil, err
	}
	return dh.PublicKey(), nil
}

// ---- message_1 ----

func (s *session) createMessage1(suites []CipherSuite) ([]byte, error) {
	if err := s.want(stateInit); err != nil {
		return nil, err
	}
	if !s.method.valid() {
		return nil, s.fail(fmt.Errorf("%w: unknown method %d", ErrStateViolation, s.method))
	}
	if len(suites) == 0 {
		return nil, s.fail(fmt.Errorf("%w: no suites specified", ErrUnsupportedSuite))
	}
	suite, ok := lookupSuite(suites[len(suites)-1])
	if !ok {
		return nil, s.fail(fmt.Errorf("%w: selected suite %d", ErrUnsupportedSuite, suites[len(suites)-1]))
	}
	s.suite = suite
	eph, err := suite.ephemeralKey(s.rand)
	if err != nil {
		return nil, s.fail(err)
	}
	s.eph = eph
	if s.ownCID, err = s.pickCID(s.ownCID, nil); err != nil {
		return nil, s.fail(err)
	}
	ead, err := encodeEAD(s.ownEAD[1])
	if err != nil {
		return nil, s.fail(err)
	}
	msg1 := encSeq(intItem(int64(s.method)), encodeSuitesItem(suites), bstrItem(suite.encodePublic(eph.PublicKey())), encodeCID(s.ownCID), ead)
	s.hMsg1 = suite.h(msg1)
	s.state = stateWaitM2
	return msg1, nil
}

func (s *session) processMessage1(msg1 []byte, supported []CipherSuite, acceptMethod func(Method) bool) ([]byte, error) {
	if err := s.want(stateInit); err != nil {
		return nil, err
	}
	r := newSeqReader(msg1)
	method, err := r.nextInt("METHOD")
	if err != nil {
		return nil, s.fail(err)
	}
	sv, _, err := r.next()
	if err != nil {
		return nil, s.fail(err)
	}
	suitesI, err := decodeSuitesValue(sv)
	if err != nil {
		return nil, s.fail(err)
	}
	gx, err := r.nextBytes("G_X")
	if err != nil {
		return nil, s.fail(err)
	}
	civ, ciRaw, err := r.next()
	if err != nil {
		return nil, s.fail(err)
	}
	ci, err := decodeCIDValue(civ, ciRaw)
	if err != nil {
		return nil, s.fail(err)
	}
	ead1, err := decodeEAD(r, s.accept)
	if err != nil {
		return nil, s.fail(err)
	}

	if m := Method(method); !m.valid() || !acceptMethod(m) {
		// v0.2 reported an unsupported method as ErrUnsupportedSuite.
		return nil, s.fail(&ErrorMessage{Code: ErrCodeUnspecified, Info: fmt.Sprintf("unsupported method %d", method), compat: ErrUnsupportedSuite})
	}
	s.method = Method(method)

	// RFC 9528 §5.2.3: the selected suite (last) must be supported, and
	// no suite the Initiator prefers over it may be.
	ours := func(c CipherSuite) bool {
		_, known := lookupSuite(c)
		return known && slices.Contains(supported, c)
	}
	selected := suitesI[len(suitesI)-1]
	acceptable := ours(selected)
	for _, c := range suitesI[:len(suitesI)-1] {
		if ours(c) {
			acceptable = false
		}
	}
	if !acceptable {
		var suitesR []CipherSuite
		for _, c := range supported {
			if _, known := lookupSuite(c); known {
				suitesR = append(suitesR, c)
			}
		}
		return nil, s.fail(&ErrorMessage{Code: ErrCodeWrongSelectedSuite, SuitesR: suitesR})
	}
	s.suite, _ = lookupSuite(selected)
	if s.peerEph, err = s.suite.decodePublic(gx); err != nil {
		return nil, s.fail(err)
	}
	s.peerCID, s.peerEAD = ci, ead1
	s.hMsg1 = s.suite.h(msg1)
	return s.createMessage2()
}

// ---- message_2 ----

// th2 = H(G_Y, H(message_1)).
func (s *session) computeTH2(gy []byte) {
	s.th2 = s.suite.h(bstrItem(gy), bstrItem(s.hMsg1))
	s.t("H(message_1)", s.hMsg1)
	s.t("TH_2", s.th2)
}

func (s *session) createMessage2() ([]byte, error) {
	su := s.suite
	eph, err := su.ephemeralKey(s.rand)
	if err != nil {
		return nil, s.fail(err)
	}
	s.eph = eph
	if s.ownCID, err = s.pickCID(s.ownCID, s.peerCID); err != nil {
		return nil, s.fail(err)
	}
	gy := su.encodePublic(eph.PublicKey())
	s.computeTH2(gy)
	gxy, err := su.ecdh(eph, s.peerEph)
	if err != nil {
		return nil, s.fail(err)
	}
	s.t("G_XY", gxy)
	s.prk2e = su.extract(s.th2, gxy)
	s.t("PRK_2e", s.prk2e)
	clear(gxy)

	// PRK_3e2m (§4.1.1.2).
	if s.method.responderSigns() {
		s.prk3e2m = slices.Clone(s.prk2e)
	} else {
		dh, err := su.staticPrivate(s.party.dhKey)
		if err != nil {
			return nil, s.fail(err)
		}
		if s.prk3e2m, err = s.staticPRK(s.prk2e, labelSalt3e2m, s.th2, dh, s.peerEph); err != nil {
			return nil, s.fail(err)
		}
	}

	authPub, err := s.authPublic(s.method.responderSigns())
	if err != nil {
		return nil, s.fail(err)
	}
	if s.ownCred, err = s.party.ownCredential(authPub); err != nil {
		return nil, s.fail(err)
	}
	if err := checkUse(s.ownCred, s.method.responderSigns()); err != nil {
		return nil, s.fail(fmt.Errorf("%w: own credential: %w", ErrStateViolation, err))
	}
	ead2, err := encodeEAD(s.ownEAD[2])
	if err != nil {
		return nil, s.fail(err)
	}
	cR := encodeCID(s.ownCID)
	som, idCompact, err := s.signOrMAC(2, cR, s.th2, ead2, s.method.responderSigns())
	if err != nil {
		return nil, s.fail(err)
	}
	pt2 := encSeq(cR, idCompact, bstrItem(som), ead2)
	s.t("PRK_3e2m", s.prk3e2m)
	s.t("Signature_or_MAC_2", som)
	s.t("PLAINTEXT_2", pt2)
	ks, err := su.kdf(s.prk2e, labelKeystream2, s.th2, len(pt2))
	if err != nil {
		return nil, s.fail(err)
	}
	s.t("KEYSTREAM_2", ks)
	ct2 := make([]byte, len(pt2))
	subtle.XORBytes(ct2, pt2, ks)
	s.t("CIPHERTEXT_2", ct2)
	clear(ks)
	s.th3 = su.h(bstrItem(s.th2), pt2, s.ownCred.Raw)
	s.t("TH_3", s.th3)
	s.state = stateWaitM3
	return bstrItem(append(gy, ct2...)), nil
}

func (s *session) processMessage2(ctx context.Context, msg2 []byte) ([]byte, error) {
	if err := s.want(stateWaitM2); err != nil {
		return nil, err
	}
	su := s.suite
	if len(msg2) > 0 && msg2[0]>>5 <= 1 { // error message: starts with an integer
		e, err := parseErrorMessage(msg2)
		if err != nil {
			return nil, s.fail(err)
		}
		return nil, s.fail(e)
	}
	r := newSeqReader(msg2)
	body, err := r.nextBytes("G_Y_CIPHERTEXT_2")
	if err != nil {
		return nil, s.fail(err)
	}
	if r.more() {
		return nil, s.fail(fmt.Errorf("%w: trailing bytes after message_2", ErrMessageFormat))
	}
	n := su.publicLen()
	if len(body) <= n {
		return nil, s.fail(fmt.Errorf("%w: message_2 too short", ErrMessageFormat))
	}
	gy, ct2 := body[:n], body[n:]
	if s.peerEph, err = su.decodePublic(gy); err != nil {
		return nil, s.fail(err)
	}
	s.computeTH2(gy)
	gxy, err := su.ecdh(s.eph, s.peerEph)
	if err != nil {
		return nil, s.fail(err)
	}
	s.prk2e = su.extract(s.th2, gxy)
	clear(gxy)
	ks, err := su.kdf(s.prk2e, labelKeystream2, s.th2, len(ct2))
	if err != nil {
		return nil, s.fail(err)
	}
	pt2 := make([]byte, len(ct2))
	subtle.XORBytes(pt2, ct2, ks)
	clear(ks)

	pr := newSeqReader(pt2)
	crv, crRaw, err := pr.next()
	if err != nil {
		return nil, s.fail(err)
	}
	if s.peerCID, err = decodeCIDValue(crv, crRaw); err != nil {
		return nil, s.fail(err)
	}
	if bytes.Equal(s.peerCID, s.ownCID) {
		return nil, s.fail(fmt.Errorf("%w: %w: C_R equals C_I", ErrMessageFormat, ErrConnectionIDCollision))
	}
	idv, idRaw, err := pr.next()
	if err != nil {
		return nil, s.fail(err)
	}
	peerID, err := parseIDCred(idv, idRaw)
	if err != nil {
		return nil, s.fail(err)
	}
	som, err := pr.nextBytes("Signature_or_MAC_2")
	if err != nil {
		return nil, s.fail(err)
	}
	ead2Raw := pr.rest
	ead2, err := decodeEAD(pr, s.accept)
	if err != nil {
		return nil, s.fail(err)
	}
	peerCred, err := s.party.resolvePeer(ctx, peerID)
	if err != nil {
		return nil, s.fail(err)
	}
	if err := checkUse(peerCred, s.method.responderSigns()); err != nil {
		return nil, s.fail(fmt.Errorf("%w: peer credential: %w", ErrAuthentication, err))
	}

	if s.method.responderSigns() {
		s.prk3e2m = slices.Clone(s.prk2e)
	} else {
		peerDH, err := su.staticPublic(peerCred.PublicKey)
		if err != nil {
			return nil, s.fail(err)
		}
		if s.prk3e2m, err = s.staticPRK(s.prk2e, labelSalt3e2m, s.th2, s.eph, peerDH); err != nil {
			return nil, s.fail(err)
		}
	}
	if err := s.verifySignOrMAC(2, encodeCID(s.peerCID), peerID, peerCred, s.th2, ead2Raw, som, s.method.responderSigns()); err != nil {
		return nil, s.fail(err)
	}
	// The Responder is authenticated: only now are its credential and
	// EAD_2 visible.
	s.peerCred, s.peerEAD = peerCred, ead2
	s.th3 = su.h(bstrItem(s.th2), pt2, peerCred.Raw)
	s.t("TH_3", s.th3)

	// PRK_4e3m (§4.1.1.3).
	if s.method.initiatorSigns() {
		s.prk4e3m = slices.Clone(s.prk3e2m)
	} else {
		dh, err := su.staticPrivate(s.party.dhKey)
		if err != nil {
			return nil, s.fail(err)
		}
		if s.prk4e3m, err = s.staticPRK(s.prk3e2m, labelSalt4e3m, s.th3, dh, s.peerEph); err != nil {
			return nil, s.fail(err)
		}
	}
	return s.createMessage3()
}

// staticPRK computes Extract(EDHOC_KDF(prk, label, th, hash_length),
// ECDH(priv, pub)) for static DH authentication.
func (s *session) staticPRK(prk []byte, label int64, th []byte, priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	salt, err := s.suite.kdf(prk, label, th, s.suite.hashSize)
	if err != nil {
		return nil, err
	}
	z, err := s.suite.ecdh(priv, pub)
	if err != nil {
		return nil, err
	}
	out := s.suite.extract(salt, z)
	clear(salt)
	clear(z)
	return out, nil
}

// signOrMAC computes Signature_or_MAC_n for this party (n = 2 or 3)
// and returns it with the compact ID_CRED. cR is C_R's encoding for
// n = 2 (context_2 starts with it) and nil for n = 3.
func (s *session) signOrMAC(n int, cR, th, ead []byte, signs bool) ([]byte, []byte, error) {
	idFull, err := s.ownCred.IDCred.full()
	if err != nil {
		return nil, nil, err
	}
	idCompact, err := s.ownCred.IDCred.compact()
	if err != nil {
		return nil, nil, err
	}
	mac, err := s.mac(n, cR, idFull, th, s.ownCred.Raw, ead, signs)
	if err != nil {
		return nil, nil, err
	}
	if !signs {
		return mac, idCompact, nil
	}
	sig, err := s.suite.sign(s.party.signer, sigStructure(idFull, th, s.ownCred.Raw, ead, mac))
	if err != nil {
		return nil, nil, err
	}
	return sig, idCompact, nil
}

func (s *session) verifySignOrMAC(n int, cR []byte, peerID IDCred, cred *Credential, th, ead, som []byte, signs bool) error {
	idFull, err := peerID.full()
	if err != nil {
		return err
	}
	mac, err := s.mac(n, cR, idFull, th, cred.Raw, ead, signs)
	if err != nil {
		return err
	}
	if signs {
		return s.suite.verify(cred.PublicKey, sigStructure(idFull, th, cred.Raw, ead, mac), som)
	}
	if subtle.ConstantTimeCompare(mac, som) != 1 {
		return fmt.Errorf("%w: MAC_%d", ErrAuthentication, n)
	}
	return nil
}

// mac computes MAC_2 / MAC_3 (§5.3.2, §5.4.2). context_2 is
// << C_R, ID_CRED_R, TH_2, CRED_R, ? EAD_2 >>, context_3 the same
// without C_R. With signature authentication the length is the hash
// length, otherwise the suite's MAC length.
func (s *session) mac(n int, cR, idFull, th, cred, ead []byte, signs bool) ([]byte, error) {
	label, prk := int64(labelMAC2), s.prk3e2m
	if n == 3 {
		label, prk = labelMAC3, s.prk4e3m
	}
	length := s.suite.macLen
	if signs {
		length = s.suite.hashSize
	}
	ctx := encSeq(cR, idFull, bstrItem(th), cred, ead)
	s.t(fmt.Sprintf("context_%d", n), ctx)
	m, err := s.suite.kdf(prk, label, ctx, length)
	s.t(fmt.Sprintf("MAC_%d", n), m)
	return m, err
}

// sigStructure is the COSE Sig_structure EDHOC signs:
// ["Signature1", << ID_CRED >>, << TH, CRED, ? EAD >>, MAC].
func sigStructure(idFull, th, cred, ead, mac []byte) []byte {
	return encSeq([]byte{0x84}, item(cbor.Text("Signature1")), bstrItem(idFull), bstrItem(encSeq(bstrItem(th), cred, ead)), bstrItem(mac))
}

// encStructure is the COSE Enc_structure used as AEAD associated data:
// ["Encrypt0", h”, TH].
func encStructure(th []byte) []byte {
	return encSeq([]byte{0x83}, item(cbor.Text("Encrypt0")), bstrItem(nil), bstrItem(th))
}

// ---- message_3 ----

func (s *session) createMessage3() ([]byte, error) {
	su := s.suite
	authPub, err := s.authPublic(s.method.initiatorSigns())
	if err != nil {
		return nil, s.fail(err)
	}
	if s.ownCred, err = s.party.ownCredential(authPub); err != nil {
		return nil, s.fail(err)
	}
	if err := checkUse(s.ownCred, s.method.initiatorSigns()); err != nil {
		return nil, s.fail(fmt.Errorf("%w: own credential: %w", ErrStateViolation, err))
	}
	ead3, err := encodeEAD(s.ownEAD[3])
	if err != nil {
		return nil, s.fail(err)
	}
	som, idCompact, err := s.signOrMAC(3, nil, s.th3, ead3, s.method.initiatorSigns())
	if err != nil {
		return nil, s.fail(err)
	}
	pt3 := encSeq(idCompact, bstrItem(som), ead3)
	s.t("PRK_4e3m", s.prk4e3m)
	s.t("Signature_or_MAC_3", som)
	s.t("PLAINTEXT_3", pt3)
	ct3, err := s.seal(s.prk3e2m, labelK3, labelIV3, s.th3, pt3)
	if err != nil {
		return nil, s.fail(err)
	}
	s.t("CIPHERTEXT_3", ct3)
	s.th4 = su.h(bstrItem(s.th3), pt3, s.ownCred.Raw)
	s.t("TH_4", s.th4)
	if err := s.deriveOut(); err != nil {
		return nil, s.fail(err)
	}
	s.state = stateCompleted
	return bstrItem(ct3), nil
}

func (s *session) processMessage3(ctx context.Context, msg3 []byte) error {
	if err := s.want(stateWaitM3); err != nil {
		return err
	}
	su := s.suite
	r := newSeqReader(msg3)
	ct3, err := r.nextBytes("CIPHERTEXT_3")
	if err != nil {
		return s.fail(err)
	}
	if r.more() {
		return s.fail(fmt.Errorf("%w: trailing bytes after message_3", ErrMessageFormat))
	}
	pt3, err := s.open(s.prk3e2m, labelK3, labelIV3, s.th3, ct3)
	if err != nil {
		return s.fail(err)
	}
	pr := newSeqReader(pt3)
	idv, idRaw, err := pr.next()
	if err != nil {
		return s.fail(err)
	}
	peerID, err := parseIDCred(idv, idRaw)
	if err != nil {
		return s.fail(err)
	}
	som, err := pr.nextBytes("Signature_or_MAC_3")
	if err != nil {
		return s.fail(err)
	}
	ead3Raw := pr.rest
	ead3, err := decodeEAD(pr, s.accept)
	if err != nil {
		return s.fail(err)
	}
	peerCred, err := s.party.resolvePeer(ctx, peerID)
	if err != nil {
		return s.fail(err)
	}
	if err := checkUse(peerCred, s.method.initiatorSigns()); err != nil {
		return s.fail(fmt.Errorf("%w: peer credential: %w", ErrAuthentication, err))
	}
	if s.method.initiatorSigns() {
		s.prk4e3m = slices.Clone(s.prk3e2m)
	} else {
		peerDH, err := su.staticPublic(peerCred.PublicKey)
		if err != nil {
			return s.fail(err)
		}
		if s.prk4e3m, err = s.staticPRK(s.prk3e2m, labelSalt4e3m, s.th3, s.eph, peerDH); err != nil {
			return s.fail(err)
		}
	}
	if err := s.verifySignOrMAC(3, nil, peerID, peerCred, s.th3, ead3Raw, som, s.method.initiatorSigns()); err != nil {
		return s.fail(err)
	}
	// The Initiator is authenticated: only now are its credential and
	// EAD_3 visible.
	s.peerCred, s.peerEAD = peerCred, ead3
	s.th4 = su.h(bstrItem(s.th3), pt3, peerCred.Raw)
	s.t("TH_4", s.th4)
	if err := s.deriveOut(); err != nil {
		return s.fail(err)
	}
	s.state = stateCompleted
	return nil
}

// deriveOut computes PRK_out and PRK_exporter (§4.1.3, §4.2.1) and
// drops values no longer needed.
func (s *session) deriveOut() error {
	var err error
	if s.prkOut, err = s.suite.kdf(s.prk4e3m, labelPRKOut, s.th4, s.suite.hashSize); err != nil {
		return err
	}
	if s.prkExporter, err = s.suite.kdf(s.prkOut, labelPRKExporter, nil, s.suite.hashSize); err != nil {
		return err
	}
	s.t("PRK_out", s.prkOut)
	s.t("PRK_exporter", s.prkExporter)
	clear(s.prk2e)
	s.prk2e, s.eph = nil, nil
	return nil
}

func (s *session) aead(prk []byte, kl, ivl int64, th []byte) (key, iv []byte, err error) {
	if key, err = s.suite.kdf(prk, kl, th, s.suite.keyLen); err != nil {
		return nil, nil, err
	}
	if iv, err = s.suite.kdf(prk, ivl, th, s.suite.ivLen); err != nil {
		return nil, nil, err
	}
	n := "3"
	if kl == labelK4 {
		n = "4"
	}
	s.t("K_"+n, key)
	s.t("IV_"+n, iv)
	s.t("A_"+n, encStructure(th))
	return key, iv, nil
}

func (s *session) seal(prk []byte, kl, ivl int64, th, pt []byte) ([]byte, error) {
	key, iv, err := s.aead(prk, kl, ivl, th)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	a, err := newAEAD(s.suite.aead, key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, iv, pt, encStructure(th)), nil
}

func (s *session) open(prk []byte, kl, ivl int64, th, ct []byte) ([]byte, error) {
	key, iv, err := s.aead(prk, kl, ivl, th)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	a, err := newAEAD(s.suite.aead, key)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, iv, ct, encStructure(th))
	if err != nil {
		return nil, fmt.Errorf("%w: decryption failed", ErrAuthentication)
	}
	return pt, nil
}

// ---- message_4 ----

func (s *session) createMessage4() ([]byte, error) {
	if err := s.want(stateCompleted); err != nil {
		return nil, err
	}
	if s.message4Sent {
		return nil, fmt.Errorf("%w: message_4 already sent", ErrStateViolation)
	}
	ead4, err := encodeEAD(s.ownEAD[4])
	if err != nil {
		return nil, s.fail(err)
	}
	ct4, err := s.seal(s.prk4e3m, labelK4, labelIV4, s.th4, ead4)
	if err != nil {
		return nil, s.fail(err)
	}
	s.message4Sent = true
	return bstrItem(ct4), nil
}

func (s *session) processMessage4(msg4 []byte) error {
	if err := s.want(stateCompleted); err != nil {
		return err
	}
	if s.message4OK {
		return fmt.Errorf("%w: message_4 already processed", ErrStateViolation)
	}
	r := newSeqReader(msg4)
	ct4, err := r.nextBytes("CIPHERTEXT_4")
	if err != nil {
		return s.fail(err)
	}
	if r.more() {
		return s.fail(fmt.Errorf("%w: trailing bytes after message_4", ErrMessageFormat))
	}
	pt4, err := s.open(s.prk4e3m, labelK4, labelIV4, s.th4, ct4)
	if err != nil {
		return s.fail(err)
	}
	ead4, err := decodeEAD(newSeqReader(pt4), s.accept)
	if err != nil {
		return s.fail(err)
	}
	s.peerEAD = ead4 // authenticated by the AEAD
	s.message4OK = true
	return nil
}

// ---- outputs ----

func (s *session) export(label int, ctx []byte, length int) ([]byte, error) {
	if err := s.want(stateCompleted); err != nil {
		return nil, err
	}
	if label < 0 || length < 0 {
		return nil, fmt.Errorf("%w: exporter label and length must not be negative", ErrStateViolation)
	}
	return s.suite.kdf(s.prkExporter, int64(label), ctx, length)
}

func (s *session) oscore(p OSCOREParams) (*OSCOREContext, error) {
	if err := s.want(stateCompleted); err != nil {
		return nil, err
	}
	if p.MasterSecretLen == 0 {
		p.MasterSecretLen = s.suite.appKey
	}
	if p.MasterSaltLen == 0 {
		p.MasterSaltLen = 8
	}
	secret, err := s.export(exporterOSCOREMasterSecret, nil, p.MasterSecretLen)
	if err != nil {
		return nil, err
	}
	salt, err := s.export(exporterOSCOREMasterSalt, nil, p.MasterSaltLen)
	if err != nil {
		return nil, err
	}
	o := &OSCOREContext{
		MasterSecret: secret,
		MasterSalt:   salt,
		SenderID:     slices.Clone(s.peerCID),
		RecipientID:  slices.Clone(s.ownCID),
		AEAD:         cosePublic(s.suite.appAEAD),
	}
	if s.suite.appHash.Size() == 32 {
		o.HKDF = coseHKDFSHA256
	}
	return o, nil
}

func (s *session) prkOutCopy() ([]byte, error) {
	if err := s.want(stateCompleted); err != nil {
		return nil, err
	}
	return slices.Clone(s.prkOut), nil
}

// keyUpdate replaces PRK_out with EDHOC_KDF(PRK_out, 11, context,
// hash_length) and re-derives PRK_exporter (RFC 9528 Appendix H).
func (s *session) keyUpdate(ctx []byte) error {
	if err := s.want(stateCompleted); err != nil {
		return err
	}
	next, err := s.suite.kdf(s.prkOut, labelKeyUpdate, ctx, s.suite.hashSize)
	if err != nil {
		return err
	}
	exp, err := s.suite.kdf(next, labelPRKExporter, nil, s.suite.hashSize)
	if err != nil {
		return err
	}
	clear(s.prkOut)
	clear(s.prkExporter)
	s.prkOut, s.prkExporter = next, exp
	return nil
}
