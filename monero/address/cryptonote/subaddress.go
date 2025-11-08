package cryptonote

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

var hashKeySubaddress = []byte("SubAddr\x00") // HASH_KEY_SUBADDRESS

// SubaddressExtension Hs(a || index_major || index_minor) make_legacy_subaddress_extension
func SubaddressExtension(out *curve25519.Scalar, index address.SubaddressIndex, viewKey curve25519.PrivateKeyBytes) *curve25519.Scalar {
	if index == address.ZeroSubaddressIndex {
		// set to zero
		return out.Set(&curve25519.Scalar{})
	}
	var major, minor [4]byte
	binary.LittleEndian.PutUint32(major[:], index.Account)
	binary.LittleEndian.PutUint32(minor[:], index.Offset)
	return crypto.ScalarDeriveLegacy(
		out,
		hashKeySubaddress,
		viewKey[:],
		major[:],
		minor[:],
	)
}

func GetSubaddressSpendPub[T curve25519.PointOperations](spendPub *curve25519.PublicKey[T], viewKeyBytes curve25519.PrivateKeyBytes, index address.SubaddressIndex) curve25519.PublicKeyBytes {
	var m curve25519.Scalar
	SubaddressExtension(&m, index, viewKeyBytes)

	var M, D curve25519.PublicKey[T]

	// spend pub
	// M = m*G
	M.ScalarBaseMult(&m)

	// D = B + M
	D.Add(spendPub, &M)

	return D.Bytes()
}

func GetSubaddressNoAllocate[T curve25519.PointOperations](baseNetwork uint8, spendPub *curve25519.PublicKey[T], viewKeyScalar *curve25519.Scalar, viewKeyBytes curve25519.PrivateKeyBytes, index address.SubaddressIndex) *address.Address {
	// special case
	if index == address.ZeroSubaddressIndex {
		panic("unreachable")
	}

	var extensionScalar curve25519.Scalar
	SubaddressExtension(&extensionScalar, index, viewKeyBytes)

	var extension, D, C curve25519.PublicKey[T]

	// spend pub
	// M = m*G
	extension.ScalarBaseMult(&extensionScalar)

	// D = B + M
	D.Add(spendPub, &extension)

	// view pub
	C.ScalarMult(viewKeyScalar, &D)

	switch baseNetwork {
	case monero.MainNetwork:
		return address.FromRawAddress(monero.SubAddressMainNetwork, D.Bytes(), C.Bytes())
	case monero.TestNetwork:
		return address.FromRawAddress(monero.SubAddressTestNetwork, D.Bytes(), C.Bytes())
	case monero.StageNetwork:
		return address.FromRawAddress(monero.SubAddressStageNetwork, D.Bytes(), C.Bytes())
	default:
		return nil
	}
}

func GetSubaddress(a *address.Address, viewKey *curve25519.Scalar, index address.SubaddressIndex) *address.Address {
	if index == address.ZeroSubaddressIndex {
		return a
	}
	var spendPub curve25519.VarTimePublicKey
	curve25519.DecodeCompressedPoint(&spendPub, *a.SpendPublicKey())

	return GetSubaddressNoAllocate(a.BaseNetwork(), &spendPub, viewKey, curve25519.PrivateKeyBytes(viewKey.Bytes()), index)
}

func GetSubaddressFakeAddress(sa address.InterfaceSubaddress, viewKey *curve25519.Scalar) address.Interface {
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
	case *address.Address:
		switch t.TypeNetwork {
		case monero.SubAddressMainNetwork:
			return address.FromRawAddress(monero.MainNetwork, *sa.SpendPublicKey(), viewPub.Bytes())
		case monero.SubAddressTestNetwork:
			return address.FromRawAddress(monero.TestNetwork, *sa.SpendPublicKey(), viewPub.Bytes())
		case monero.SubAddressStageNetwork:
			return address.FromRawAddress(monero.StageNetwork, *sa.SpendPublicKey(), viewPub.Bytes())
		default:
			return nil
		}
	default:
		return &address.PackedAddress{*sa.SpendPublicKey(), viewPub.Bytes()}
	}
}
