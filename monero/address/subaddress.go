package address

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
)

var ZeroSubaddressIndex = SubaddressIndex{
	Account: 0,
	Offset:  0,
}

type SubaddressIndex struct {
	Account uint32
	Offset  uint32
}

var hashKeySubaddress = []byte("SubAddr\x00") // HASH_KEY_SUBADDRESS

// SecretKey Hs(a || index_major || index_minor)
func (index SubaddressIndex) SecretKey(viewKey crypto.PrivateKey) crypto.PrivateKey {
	var major, minor [4]byte
	binary.LittleEndian.PutUint32(major[:], index.Account)
	binary.LittleEndian.PutUint32(minor[:], index.Offset)
	return crypto.PrivateKeyFromScalar(crypto.HashToScalar(
		hashKeySubaddress,
		viewKey.AsSlice(),
		major[:],
		minor[:],
	))
}

func GetSubaddress(a *Address, viewKey crypto.PrivateKey, index SubaddressIndex) *Address {
	if a == nil || a.IsSubaddress() {
		// cannot derive
		return nil
	}
	m := index.SecretKey(viewKey)

	// spend pub
	// M = m*G
	M := m.PublicKey()

	// D = B + M
	D := a.SpendPublicKey().AsPoint().Add(M.AsPoint())

	// view pub
	C := viewKey.GetDerivation(D)

	switch a.BaseNetwork() {
	case monero.MainNetwork:
		return FromRawAddress(monero.SubAddressMainNetwork, D, C)
	case monero.TestNetwork:
		return FromRawAddress(monero.SubAddressTestNetwork, D, C)
	case monero.StageNetwork:
		return FromRawAddress(monero.SubAddressStageNetwork, D, C)
	default:
		return nil
	}
}

func GetSubaddressFakeAddress(sa InterfaceSubaddress, viewKey crypto.PrivateKey) Interface {
	if !sa.IsSubaddress() {
		return sa
	}

	// mismatched view key
	if viewKey.GetDerivation(sa.SpendPublicKey()).AsBytes() != sa.ViewPublicKey().AsBytes() {
		return nil
	}

	switch t := sa.(type) {
	case *Address:
		switch t.TypeNetwork {
		case monero.SubAddressMainNetwork:
			return FromRawAddress(monero.MainNetwork, sa.SpendPublicKey(), viewKey.PublicKey())
		case monero.SubAddressTestNetwork:
			return FromRawAddress(monero.TestNetwork, sa.SpendPublicKey(), viewKey.PublicKey())
		case monero.SubAddressStageNetwork:
			return FromRawAddress(monero.StageNetwork, sa.SpendPublicKey(), viewKey.PublicKey())
		default:
			return nil
		}
	default:
		return &PackedAddress{sa.SpendPublicKey().AsBytes(), viewKey.PublicKey().AsBytes()}
	}
}
