package address

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
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
func (index SubaddressIndex) SecretKey(out *curve25519.Scalar, viewKey curve25519.PrivateKeyBytes) *curve25519.Scalar {
	var major, minor [4]byte
	binary.LittleEndian.PutUint32(major[:], index.Account)
	binary.LittleEndian.PutUint32(minor[:], index.Offset)
	return crypto.ScalarDeriveLegacyNoAllocate(
		out,
		hashKeySubaddress,
		viewKey[:],
		major[:],
		minor[:],
	)
}

func GetSubaddressSpendPub[T curve25519.PointOperations](spendPub *curve25519.PublicKey[T], viewKeyBytes curve25519.PrivateKeyBytes, index SubaddressIndex) curve25519.PublicKeyBytes {
	var m curve25519.Scalar
	index.SecretKey(&m, viewKeyBytes)

	var M, D curve25519.PublicKey[T]

	// spend pub
	// M = m*G
	M.ScalarBaseMult(&m)

	// D = B + M
	D.Add(spendPub, &M)

	return D.Bytes()
}

func GetSubaddressNoAllocate[T curve25519.PointOperations](baseNetwork uint8, spendPub *curve25519.PublicKey[T], viewKeyScalar *curve25519.Scalar, viewKeyBytes curve25519.PrivateKeyBytes, index SubaddressIndex) *Address {
	// special case
	if index == ZeroSubaddressIndex {
		panic("unreachable")
	}

	var m curve25519.Scalar
	index.SecretKey(&m, viewKeyBytes)

	var M, D, C curve25519.PublicKey[T]

	// spend pub
	// M = m*G
	M.ScalarBaseMult(&m)

	// D = B + M
	D.Add(spendPub, &M)

	// view pub
	C.ScalarMult(viewKeyScalar, &D)

	switch baseNetwork {
	case monero.MainNetwork:
		return FromRawAddress(monero.SubAddressMainNetwork, D.Bytes(), C.Bytes())
	case monero.TestNetwork:
		return FromRawAddress(monero.SubAddressTestNetwork, D.Bytes(), C.Bytes())
	case monero.StageNetwork:
		return FromRawAddress(monero.SubAddressStageNetwork, D.Bytes(), C.Bytes())
	default:
		return nil
	}
}

func GetSubaddress(a *Address, viewKey *curve25519.Scalar, index SubaddressIndex) *Address {
	if index == ZeroSubaddressIndex {
		return a
	}
	var spendPub curve25519.VarTimePublicKey
	curve25519.DecodeCompressedPoint(&spendPub, *a.SpendPublicKey())

	return GetSubaddressNoAllocate(a.BaseNetwork(), &spendPub, viewKey, curve25519.PrivateKeyBytes(viewKey.Bytes()), index)
}

func GetSubaddressFakeAddress(sa InterfaceSubaddress, viewKey *curve25519.Scalar) Interface {
	if !sa.IsSubaddress() {
		return sa
	}

	var spendPub, viewPub curve25519.VarTimePublicKey
	curve25519.DecodeCompressedPoint(&spendPub, *sa.SpendPublicKey())

	// mismatched view key
	if new(curve25519.VarTimePublicKey).ScalarMult(viewKey, &spendPub).Bytes() != *sa.ViewPublicKey() {
		return nil
	}

	viewPub.ScalarBaseMult(viewKey)

	switch t := sa.(type) {
	case *Address:
		switch t.TypeNetwork {
		case monero.SubAddressMainNetwork:
			return FromRawAddress(monero.MainNetwork, *sa.SpendPublicKey(), viewPub.Bytes())
		case monero.SubAddressTestNetwork:
			return FromRawAddress(monero.TestNetwork, *sa.SpendPublicKey(), viewPub.Bytes())
		case monero.SubAddressStageNetwork:
			return FromRawAddress(monero.StageNetwork, *sa.SpendPublicKey(), viewPub.Bytes())
		default:
			return nil
		}
	default:
		return &PackedAddress{*sa.SpendPublicKey(), viewPub.Bytes()}
	}
}
