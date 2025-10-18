package address

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
)

var ZeroSubaddressIndex = SubaddressIndex{
	Account: 0,
	Offset:  0,
}

type SubaddressIndex struct {
	// Account index, also called major_index
	Account uint32
	// Offset within the Account, also called minor_index
	Offset uint32
}

func (index SubaddressIndex) IsZero() bool {
	return index == ZeroSubaddressIndex
}

var hashKeySubaddress = []byte("SubAddr\x00") // HASH_KEY_SUBADDRESS

// SecretKey Hs(a || index_major || index_minor)
func (index SubaddressIndex) SecretKey(viewKey crypto.PrivateKeyBytes) crypto.PrivateKey {
	var major, minor [4]byte
	binary.LittleEndian.PutUint32(major[:], index.Account)
	binary.LittleEndian.PutUint32(minor[:], index.Offset)
	return crypto.PrivateKeyFromScalar(crypto.ScalarDeriveLegacy(
		hashKeySubaddress,
		viewKey[:],
		major[:],
		minor[:],
	))
}

func GetSubaddressSpendPub(a *Address, viewKeyBytes crypto.PrivateKeyBytes, index SubaddressIndex) crypto.PublicKeyBytes {
	m := index.SecretKey(viewKeyBytes)

	// spend pub
	// M = m*G
	M := m.PublicKey()

	// D = B + M
	D := a.SpendPublicKey().AsPoint().Add(M.AsPoint())

	return D.AsBytes()
}

func GetSubaddressNoAllocate(a *Address, viewKeyScalar *crypto.PrivateKeyScalar, viewKeyBytes crypto.PrivateKeyBytes, index SubaddressIndex) *Address {
	if a == nil || a.IsSubaddress() {
		// cannot derive
		return nil
	}

	// special case
	if index == ZeroSubaddressIndex {
		return a
	}

	m := index.SecretKey(viewKeyBytes)

	// spend pub
	// M = m*G
	M := m.PublicKey()

	// D = B + M
	D := a.SpendPublicKey().AsPoint().Add(M.AsPoint())

	// view pub
	C := viewKeyScalar.GetDerivation(D)

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

func GetSubaddress(a *Address, viewKey crypto.PrivateKey, index SubaddressIndex) *Address {
	return GetSubaddressNoAllocate(a, viewKey.AsScalar(), viewKey.AsBytes(), index)
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
