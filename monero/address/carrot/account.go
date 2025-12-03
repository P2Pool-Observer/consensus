package carrot

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

// MakeProveSpendKey make_carrot_provespend_key
func MakeProveSpendKey(hasher *blake2b.Digest, proveSpendOut *curve25519.Scalar, masterSecret types.Hash) {
	// k_ps = H_n(s_m)
	ScalarTranscript(
		proveSpendOut, hasher, masterSecret[:],
		[]byte(DomainSeparatorProveSpendKey),
	)
}

// MakePartialSpendPub make_carrot_partial_spend_pubkey
func MakePartialSpendPub[T curve25519.PointOperations](partialSpendPubOut *curve25519.PublicKey[T], proveSpend *curve25519.Scalar) {
	// K_ps = k_ps T
	partialSpendPubOut.ScalarMultPrecomputed(proveSpend, crypto.GeneratorT)
}

// MakeViewBalanceSecret make_carrot_viewbalance_secret
func MakeViewBalanceSecret(hasher *blake2b.Digest, masterSecret types.Hash) (viewBalanceSecret types.Hash) {
	// s_vb = H_32(s_m)
	HashedTranscript(
		viewBalanceSecret[:], hasher, masterSecret[:],
		[]byte(DomainSeparatorViewBalanceSecret),
	)
	return viewBalanceSecret
}

// MakeGenerateImagePreimageSecret make_carrot_generateimage_preimage_secret
func MakeGenerateImagePreimageSecret(hasher *blake2b.Digest, viewBalanceSecret types.Hash) (generateImagePreimageSecret types.Hash) {
	// s_gp = H_n(s_vb)
	HashedTranscript(
		generateImagePreimageSecret[:], hasher, viewBalanceSecret[:],
		[]byte(DomainSeparatorGenerateImagePreimageSecret),
	)
	return generateImagePreimageSecret
}

// MakeGenerateImageKey make_carrot_generateimage_key
func MakeGenerateImageKey(hasher *blake2b.Digest, generateImageKeyOut *curve25519.Scalar, partialSpendPubKey curve25519.PublicKeyBytes, generateImagePreimageSecret types.Hash) {
	// k_gi = H_n(s_gp, K_ps)
	ScalarTranscript(
		generateImageKeyOut, hasher, generateImagePreimageSecret[:],
		[]byte(DomainSeparatorGenerateImageKey), partialSpendPubKey[:],
	)
}

// MakeViewIncomingKey make_carrot_viewincoming_key
func MakeViewIncomingKey(hasher *blake2b.Digest, viewIncomingKeyOut *curve25519.Scalar, viewBalanceSecret types.Hash) {
	// k_v = H_n(s_vb)
	ScalarTranscript(
		viewIncomingKeyOut, hasher, viewBalanceSecret[:],
		[]byte(DomainSeparatorIncomingViewKey),
	)
}

// MakeGenerateAddressSecret make_carrot_generateaddress_secret
func MakeGenerateAddressSecret(hasher *blake2b.Digest, viewBalanceSecret types.Hash) (generateAddressSecret types.Hash) {
	// s_ga = H_32(s_vb)
	HashedTranscript(
		generateAddressSecret[:], hasher, viewBalanceSecret[:],
		[]byte(DomainSeparatorGenerateAddressSecret),
	)
	return generateAddressSecret
}

// MakeSpendPub make_carrot_spend_pubkey / derive_carrot_account_spend_pubkey
func MakeSpendPub[T curve25519.PointOperations](addressSpendPubOut *curve25519.PublicKey[T], generateImage, proveSpend *curve25519.Scalar) {
	// K_s = k_gi G + k_ps T
	addressSpendPubOut.DoubleScalarBaseMultPrecomputed(proveSpend, crypto.GeneratorT, generateImage)
}

// MakeSpendPubFromPartialSpendPub Alternate version of MakeSpendPub without proveSpend key
func MakeSpendPubFromPartialSpendPub[T curve25519.PointOperations](addressSpendPubOut *curve25519.PublicKey[T], generateImage *curve25519.Scalar, proveSpendPub *curve25519.PublicKey[T]) {
	// K_s = k_gi G + k_ps T
	addressSpendPubOut.ScalarBaseMult(generateImage)
	addressSpendPubOut.Add(addressSpendPubOut, proveSpendPub)
}

// MakeAccountViewPub make_carrot_account_view_pubkey / derive_carrot_account_view_pubkey
func MakeAccountViewPub[T curve25519.PointOperations](addressViewPubOut *curve25519.PublicKey[T], view *curve25519.Scalar, spendPub *curve25519.PublicKey[T]) {
	// K^v = k_v K_s
	addressViewPubOut.ScalarMult(view, spendPub)
}

// MakePrimaryAddressViewPub make_carrot_primary_address_view_pubkey
func MakePrimaryAddressViewPub[T curve25519.PointOperations](addressViewPubOut *curve25519.PublicKey[T], view *curve25519.Scalar) {
	// K^0_v = k_v G
	addressViewPubOut.ScalarBaseMult(view)
}

// MakeAddressIndexPreimage1 make_carrot_address_index_preimage_1
func MakeAddressIndexPreimage1(hasher *blake2b.Digest, generateAddressSecret types.Hash, i address.SubaddressIndex) (addressIndexPreimage1 types.Hash) {
	// s^j_ap1 = H_32[s_ga](j_major, j_minor)
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[:], i.Account)
	binary.LittleEndian.PutUint32(buf[4:], i.Offset)
	HashedTranscript(
		addressIndexPreimage1[:], hasher, generateAddressSecret[:],
		[]byte(DomainSeparatorAddressIndexPreimage1), buf[:],
	)
	return addressIndexPreimage1
}

// MakeAddressIndexPreimage2 make_carrot_address_index_preimage_2
func MakeAddressIndexPreimage2(hasher *blake2b.Digest, addressIndexPreimage1 types.Hash, accountSpendPub, accountViewPub curve25519.PublicKeyBytes, i address.SubaddressIndex) (addressIndexPreimage2 types.Hash) {
	// s^j_ap2 = H_32[s^j_ap1](j_major, j_minor, K_s, K_v)
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[:], i.Account)
	binary.LittleEndian.PutUint32(buf[4:], i.Offset)
	HashedTranscript(
		addressIndexPreimage2[:], hasher, addressIndexPreimage1[:],
		[]byte(DomainSeparatorAddressIndexPreimage2), buf[:], accountSpendPub[:], accountViewPub[:],
	)
	return addressIndexPreimage2
}

// MakeSubaddressScalar make_carrot_subaddress_scalar
func MakeSubaddressScalar(hasher *blake2b.Digest, subaddressScalarOut *curve25519.Scalar, addressIndexPreimage2 types.Hash, accountSpendPub curve25519.PublicKeyBytes) {
	// k^j_subscal = H_n[s^j_ap2](K_s)
	ScalarTranscript(
		subaddressScalarOut, hasher, addressIndexPreimage2[:],
		[]byte(DomainSeparatorSubaddressScalar), accountSpendPub[:],
	)
}
