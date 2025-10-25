package carrot

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

// MakeProveSpendKey make_carrot_provespend_key
func MakeProveSpendKey(hasher *blake2b.Digest, proveSpendOut *crypto.PrivateKeyScalar, masterSecret types.Hash) {
	// k_ps = H_n(s_m)
	ScalarTranscript(
		proveSpendOut.Scalar(), hasher, masterSecret[:],
		[]byte(DomainSeparatorProveSpendKey),
	)
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

// MakeGenerateImageKey make_carrot_generateimage_key
func MakeGenerateImageKey(hasher *blake2b.Digest, viewIncomingKeyOut *crypto.PrivateKeyScalar, viewBalanceSecret types.Hash) {
	// k_gi = H_n(s_vb)
	ScalarTranscript(
		viewIncomingKeyOut.Scalar(), hasher, viewBalanceSecret[:],
		[]byte(DomainSeparatorGenerateImageKey),
	)
}

// MakeViewIncomingKey make_carrot_viewincoming_key
func MakeViewIncomingKey(hasher *blake2b.Digest, viewIncomingKeyOut *crypto.PrivateKeyScalar, viewBalanceSecret types.Hash) {
	// k_v = H_n(s_vb)
	ScalarTranscript(
		viewIncomingKeyOut.Scalar(), hasher, viewBalanceSecret[:],
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

// MakeSpendPub make_carrot_spend_pubkey
func MakeSpendPub(addressSpendPubOut *crypto.PublicKeyPoint, generateImage, proveSpend *crypto.PrivateKeyScalar) {
	// K_s = k_gi G + k_ps T
	addressSpendPubOut.Point().UnsafeVarTimeDoubleScalarBaseMultPrecomputed(proveSpend.Scalar(), crypto.GeneratorT.Table, generateImage.Scalar())
}

func MakeSpendPubFromSpendPub(addressSpendPubOut *crypto.PublicKeyPoint, generateImage *crypto.PrivateKeyScalar, proveSpendPub *crypto.PublicKeyPoint) {
	// K_s = k_gi G + k_ps T
	addressSpendPubOut.Point().UnsafeVarTimeScalarBaseMult(generateImage.Scalar())
	addressSpendPubOut.Point().Add(addressSpendPubOut.Point(), proveSpendPub.Point())
}

// MakeAccountViewPub make_carrot_account_view_pubkey
func MakeAccountViewPub(addressViewPubOut *crypto.PublicKeyPoint, view *crypto.PrivateKeyScalar, spendPub *crypto.PublicKeyPoint) {
	addressViewPubOut.Point().UnsafeVarTimeScalarMult(view.Scalar(), spendPub.Point())
}

// MakePrimaryAddressViewPub make_carrot_primary_address_view_pubkey
func MakePrimaryAddressViewPub(addressViewPubOut *crypto.PublicKeyPoint, view *crypto.PrivateKeyScalar) {
	// K^0_v = k_v G
	addressViewPubOut.Point().UnsafeVarTimeScalarBaseMult(view.Scalar())
}

// makeIndexExtensionGenerator make_carrot_index_extension_generator
func makeIndexExtensionGenerator(hasher *blake2b.Digest, generateAddressSecret types.Hash, i address.SubaddressIndex) (addressIndexGeneratorSecret types.Hash) {
	// s^j_gen = H_32[s_ga](j_major, j_minor)
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[:], i.Account)
	binary.LittleEndian.PutUint32(buf[4:], i.Offset)
	HashedTranscript(
		addressIndexGeneratorSecret[:], hasher, generateAddressSecret[:],
		[]byte(DomainSeparatorAddressIndexGenerator), buf[:],
	)
	return addressIndexGeneratorSecret
}

// makeSubaddressScalar make_carrot_subaddress_scalar
func makeSubaddressScalar(hasher *blake2b.Digest, addressIndexGeneratorSecretOut *crypto.PrivateKeyScalar, spendPub crypto.PublicKeyBytes, addressIndexGeneratorSecret types.Hash, i address.SubaddressIndex) {
	// k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[:], i.Account)
	binary.LittleEndian.PutUint32(buf[4:], i.Offset)
	ScalarTranscript(
		addressIndexGeneratorSecretOut.Scalar(), hasher, addressIndexGeneratorSecret[:],
		[]byte(DomainSeparatorSubaddressScalar), spendPub[:], buf[:],
	)
}
