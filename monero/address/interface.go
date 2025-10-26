package address

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

type Interface interface {
	Compare(b Interface) int

	SpendPublicKey() *curve25519.PublicKeyBytes
	ViewPublicKey() *curve25519.PublicKeyBytes

	ToAddress(network uint8, err ...error) *Address
	ToPackedAddress() PackedAddress
}

type InterfaceSubaddress interface {
	Interface
	IsSubaddress() bool
}
