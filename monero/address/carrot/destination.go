package carrot

import (
	"errors"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type DestinationV1 struct {
	Address address.PackedAddressWithSubaddress `json:"address"`

	PaymentId [monero.PaymentIdSize]byte `json:"payment_id,omitempty"`
}

// MakeDestinationMainAddress make_main_address
func MakeDestinationMainAddress(accountSpendPub, primaryAddressViewPub crypto.PublicKeyBytes) DestinationV1 {
	return DestinationV1{
		Address: address.NewPackedAddressWithSubaddressFromBytes(accountSpendPub, primaryAddressViewPub, false),
	}
}

// MakeDestinationSubaddress make_subaddress
func MakeDestinationSubaddress(hasher *blake2b.Digest, accountSpendPub, accountViewPub *crypto.PublicKeyPoint, generateAddressSecret types.Hash, i address.SubaddressIndex) (DestinationV1, error) {
	if i.IsZero() {
		return DestinationV1{}, errors.New("invalid subaddress index")
	}

	// s^j_gen = H_32[s_ga](j_major, j_minor)
	addressIndexGenerator := makeIndexExtensionGenerator(hasher, generateAddressSecret, i)

	// k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
	var addressIndexGeneratorSecret crypto.PrivateKeyScalar
	makeSubaddressScalar(hasher, &addressIndexGeneratorSecret, accountSpendPub.AsBytes(), addressIndexGenerator, i)

	var addressSpendPub, addressViewPub crypto.PublicKeyPoint
	// K^j_s = k^j_subscal * K_s
	addressSpendPub.Point().ScalarMult(addressIndexGeneratorSecret.Scalar(), accountSpendPub.Point())

	// K^j_v = k^j_subscal * K_v
	addressViewPub.Point().ScalarMult(addressIndexGeneratorSecret.Scalar(), accountViewPub.Point())

	return DestinationV1{
		Address: address.NewPackedAddressWithSubaddressFromBytes(addressSpendPub.AsBytes(), addressViewPub.AsBytes(), true),
	}, nil
}

// MakeDestinationSubaddressSpendPub used to create subaddress map
func MakeDestinationSubaddressSpendPub(hasher *blake2b.Digest, accountSpendPub *crypto.PublicKeyPoint, generateAddressSecret types.Hash, i address.SubaddressIndex) crypto.PublicKeyBytes {

	// s^j_gen = H_32[s_ga](j_major, j_minor)
	addressIndexGenerator := makeIndexExtensionGenerator(hasher, generateAddressSecret, i)

	// k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
	var addressIndexGeneratorSecret crypto.PrivateKeyScalar
	makeSubaddressScalar(hasher, &addressIndexGeneratorSecret, accountSpendPub.AsBytes(), addressIndexGenerator, i)

	var addressSpendPub crypto.PublicKeyPoint
	// K^j_s = k^j_subscal * K_s
	addressSpendPub.Point().ScalarMult(addressIndexGeneratorSecret.Scalar(), accountSpendPub.Point())

	return addressSpendPub.AsBytes()
}
