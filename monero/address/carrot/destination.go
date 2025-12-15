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

	PaymentId [monero.PaymentIdSize]byte `json:"payment_id,omitzero"`
}

// MakeDestinationMainAddress make_carrot_main_address_v1
func MakeDestinationMainAddress(accountSpendPub, primaryAddressViewPub curve25519.PublicKeyBytes) DestinationV1 {
	return DestinationV1{
		Address: address.NewPackedAddressWithSubaddressFromBytes(accountSpendPub, primaryAddressViewPub, false),
	}
}

// MakeDestinationSubaddress make_carrot_subaddress_v1
func MakeDestinationSubaddress[T curve25519.PointOperations](hasher *blake2b.Digest, accountSpendPub, accountViewPub *curve25519.PublicKey[T], generateAddressSecret types.Hash, i address.SubaddressIndex) (DestinationV1, error) {
	if i.IsZero() {
		return DestinationV1{}, errors.New("invalid subaddress index")
	}

	// s^j_ap1 = H_32[s_ga](j_major, j_minor)
	addressIndexPreimage1 := MakeAddressIndexPreimage1(hasher, generateAddressSecret, i)

	spendPubBytes := accountSpendPub.AsBytes()

	// s^j_ap2 = H_32[s^j_ap1](j_major, j_minor, K_s, K_v)
	addressIndexPreimage2 := MakeAddressIndexPreimage2(hasher, addressIndexPreimage1, spendPubBytes, accountViewPub.AsBytes(), i)

	// k^j_subscal = H_n[s^j_ap2](K_s)
	var subaddressScalar curve25519.Scalar
	MakeSubaddressScalar(hasher, &subaddressScalar, addressIndexPreimage2, spendPubBytes)

	var addressSpendPub, addressViewPub curve25519.PublicKey[T]
	// K^j_s = k^j_subscal * K_s
	addressSpendPub.ScalarMult(&subaddressScalar, accountSpendPub)

	// K^j_v = k^j_subscal * K_v
	addressViewPub.ScalarMult(&subaddressScalar, accountViewPub)

	return DestinationV1{
		Address: address.NewPackedAddressWithSubaddressFromBytes(addressSpendPub.AsBytes(), addressViewPub.AsBytes(), true),
	}, nil
}

// MakeDestinationSubaddressSpendPub used to create subaddress map
func MakeDestinationSubaddressSpendPub[T curve25519.PointOperations](hasher *blake2b.Digest, accountSpendPub, accountViewPub *curve25519.PublicKey[T], generateAddressSecret types.Hash, i address.SubaddressIndex) curve25519.PublicKeyBytes {

	// s^j_ap1 = H_32[s_ga](j_major, j_minor)
	addressIndexPreimage1 := MakeAddressIndexPreimage1(hasher, generateAddressSecret, i)

	spendPubBytes := accountSpendPub.AsBytes()

	// s^j_ap2 = H_32[s^j_ap1](j_major, j_minor, K_s, K_v)
	addressIndexPreimage2 := MakeAddressIndexPreimage2(hasher, addressIndexPreimage1, spendPubBytes, accountViewPub.AsBytes(), i)

	// k^j_subscal = H_n[s^j_ap2](K_s)
	var subaddressScalar curve25519.Scalar
	MakeSubaddressScalar(hasher, &subaddressScalar, addressIndexPreimage2, spendPubBytes)

	var addressSpendPub curve25519.PublicKey[T]
	// K^j_s = k^j_subscal * K_s
	addressSpendPub.ScalarMult(&subaddressScalar, accountSpendPub)

	return addressSpendPub.AsBytes()
}
