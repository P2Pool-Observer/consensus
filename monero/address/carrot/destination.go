package carrot

import (
	"errors"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type DestinationV1 struct {
	Address address.PackedAddressWithSubaddress `json:"address"`

	PaymentId [monero.PaymentIdSize]byte `json:"payment_id,omitempty"`
}

// MakeDestinationMainAddress make_main_address
func MakeDestinationMainAddress(accountSpendPub, primaryAddressViewPub curve25519.PublicKeyBytes) DestinationV1 {
	return DestinationV1{
		Address: address.NewPackedAddressWithSubaddressFromBytes(accountSpendPub, primaryAddressViewPub, false),
	}
}

// MakeDestinationSubaddress make_subaddress
func MakeDestinationSubaddress[T curve25519.PointOperations](hasher *blake2b.Digest, accountSpendPub, accountViewPub *curve25519.PublicKey[T], generateAddressSecret types.Hash, i address.SubaddressIndex) (DestinationV1, error) {
	if i.IsZero() {
		return DestinationV1{}, errors.New("invalid subaddress index")
	}

	// s^j_gen = H_32[s_ga](j_major, j_minor)
	addressIndexGenerator := MakeIndexExtensionGenerator(hasher, generateAddressSecret, i)

	// k^j_subscal = H_n[s^j_gen](K_s, K_v, j_major, j_minor)
	var addressIndexGeneratorSecret curve25519.Scalar
	MakeSubaddressScalar(hasher, &addressIndexGeneratorSecret, accountSpendPub.AsBytes(), accountViewPub.AsBytes(), addressIndexGenerator, i)

	var addressSpendPub, addressViewPub curve25519.PublicKey[T]
	// K^j_s = k^j_subscal * K_s
	addressSpendPub.ScalarMult(&addressIndexGeneratorSecret, accountSpendPub)

	// K^j_v = k^j_subscal * K_v
	addressViewPub.ScalarMult(&addressIndexGeneratorSecret, accountViewPub)

	return DestinationV1{
		Address: address.NewPackedAddressWithSubaddressFromBytes(addressSpendPub.AsBytes(), addressViewPub.AsBytes(), true),
	}, nil
}

// MakeDestinationSubaddressSpendPub used to create subaddress map
func MakeDestinationSubaddressSpendPub[T curve25519.PointOperations](hasher *blake2b.Digest, accountSpendPub, accountViewPub *curve25519.PublicKey[T], generateAddressSecret types.Hash, i address.SubaddressIndex) curve25519.PublicKeyBytes {

	// s^j_gen = H_32[s_ga](j_major, j_minor)
	addressIndexGenerator := MakeIndexExtensionGenerator(hasher, generateAddressSecret, i)

	// k^j_subscal = H_n[s^j_gen](K_s, K_v, j_major, j_minor)
	var addressIndexGeneratorSecret curve25519.Scalar
	MakeSubaddressScalar(hasher, &addressIndexGeneratorSecret, accountSpendPub.AsBytes(), accountViewPub.AsBytes(), addressIndexGenerator, i)

	var addressSpendPub curve25519.PublicKey[T]
	// K^j_s = k^j_subscal * K_s
	addressSpendPub.ScalarMult(&addressIndexGeneratorSecret, accountSpendPub)

	return addressSpendPub.AsBytes()
}
