package address

import (
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	base58 "git.gammaspectra.live/P2Pool/monero-base58"
)

var PackedAddressGlobalNetwork uint8 = monero.MainNetwork

const PackedAddressSpend = 0
const PackedAddressView = 1

// PackedAddress 0 = spend, 1 = view
type PackedAddress [2]crypto.PublicKeyBytes

func NewPackedAddressFromBytes(spend, view crypto.PublicKeyBytes) (result PackedAddress) {
	copy(result[PackedAddressSpend][:], spend[:])
	copy(result[PackedAddressView][:], view[:])
	return
}

func NewPackedAddress(spend, view crypto.PublicKey) (result PackedAddress) {
	return NewPackedAddressFromBytes(spend.AsBytes(), view.AsBytes())
}

func (p *PackedAddress) PublicKeys() (spend, view crypto.PublicKey) {
	return &(*p)[PackedAddressSpend], &(*p)[PackedAddressView]
}

func (p *PackedAddress) SpendPublicKey() *crypto.PublicKeyBytes {
	return &(*p)[PackedAddressSpend]
}

func (p *PackedAddress) ViewPublicKey() *crypto.PublicKeyBytes {
	return &(*p)[PackedAddressView]
}

func (p *PackedAddress) ToPackedAddress() PackedAddress {
	return *p
}

// Compare special consensus comparison
func (p *PackedAddress) Compare(b Interface) int {
	//compare spend key

	resultSpendKey := crypto.CompareConsensusPublicKeyBytes(&p[PackedAddressSpend], b.SpendPublicKey())
	if resultSpendKey != 0 {
		return resultSpendKey
	}

	// compare view key
	return crypto.CompareConsensusPublicKeyBytes(&p[PackedAddressView], b.ViewPublicKey())
}

func (p *PackedAddress) ComparePacked(other *PackedAddress) int {
	//compare spend key

	resultSpendKey := crypto.CompareConsensusPublicKeyBytes(&p[PackedAddressSpend], &other[PackedAddressSpend])
	if resultSpendKey != 0 {
		return resultSpendKey
	}

	// compare view key
	return crypto.CompareConsensusPublicKeyBytes(&p[PackedAddressView], &other[PackedAddressView])
}

func (p *PackedAddress) ToAddress(typeNetwork uint8, err ...error) *Address {
	if len(err) > 0 && err[0] != nil {
		return nil
	}
	return FromRawAddress(typeNetwork, p.SpendPublicKey(), p.ViewPublicKey())
}

func (p PackedAddress) ToBase58(typeNetwork uint8, err ...error) []byte {
	var nice [69]byte
	nice[0] = typeNetwork
	copy(nice[1:], p[PackedAddressSpend][:])
	copy(nice[1+crypto.PublicKeySize:], p[PackedAddressView][:])
	sum := checksumHash(nice[:65])

	buf := make([]byte, 0, 95)
	return base58.EncodeMoneroBase58PreAllocated(buf, []byte{typeNetwork}, p[PackedAddressSpend][:], p[PackedAddressView][:], sum[:])
}

// Valid check that points can be decoded and that they are not torsioned
func (p PackedAddress) Valid() bool {
	if spend := p.SpendPublicKey().AsPoint(); spend == nil || !spend.IsTorsionFreeVarTime() {
		return false
	}
	if view := p.ViewPublicKey().AsPoint(); view == nil || !view.IsTorsionFreeVarTime() {
		return false
	}
	return true
}

func (p PackedAddress) Reference() *PackedAddress {
	return &p
}

func (p PackedAddress) Bytes() []byte {
	return (*[crypto.PublicKeySize * 2]byte)(unsafe.Pointer(&p))[:]
}

type PackedAddressWithSubaddress [crypto.PublicKeySize*2 + 1]byte

func NewPackedAddressWithSubaddressFromBytes(spendPub, viewPub crypto.PublicKeyBytes, isSubaddress bool) (out PackedAddressWithSubaddress) {
	copy(out[:], spendPub[:])
	copy(out[crypto.PublicKeySize:], viewPub[:])
	if isSubaddress {
		out[crypto.PublicKeySize*2] = 1
	}
	return out
}

func NewPackedAddressWithSubaddress(a *PackedAddress, isSubaddress bool) (out PackedAddressWithSubaddress) {
	return NewPackedAddressWithSubaddressFromBytes(*a.SpendPublicKey(), *a.ViewPublicKey(), isSubaddress)
}

func (p *PackedAddressWithSubaddress) SpendPublicKey() *crypto.PublicKeyBytes {
	return (*crypto.PublicKeyBytes)(unsafe.Pointer(p))
}

func (p *PackedAddressWithSubaddress) ViewPublicKey() *crypto.PublicKeyBytes {
	return (*crypto.PublicKeyBytes)(unsafe.Pointer(&p[crypto.PublicKeySize]))
}

func (p *PackedAddressWithSubaddress) IsSubaddress() bool {
	return p[crypto.PublicKeySize*2] == 1
}

func (p *PackedAddressWithSubaddress) PackedAddress() *PackedAddress {
	return (*PackedAddress)(unsafe.Pointer(p))
}

// Valid check that points can be decoded and that they are not torsioned
func (p *PackedAddressWithSubaddress) Valid() bool {
	if spend := p.SpendPublicKey().AsPoint(); spend == nil || !spend.IsTorsionFreeVarTime() {
		return false
	}
	if view := p.ViewPublicKey().AsPoint(); view == nil || !view.IsTorsionFreeVarTime() {
		return false
	}
	return true
}

func (p *PackedAddressWithSubaddress) ComparePacked(other *PackedAddressWithSubaddress) int {
	//compare spend key

	resultSpendKey := crypto.CompareConsensusPublicKeyBytes(p.SpendPublicKey(), other.SpendPublicKey())
	if resultSpendKey != 0 {
		return resultSpendKey
	}

	// compare view key
	resultViewKey := crypto.CompareConsensusPublicKeyBytes(p.ViewPublicKey(), other.ViewPublicKey())
	if resultViewKey != 0 {
		return resultViewKey
	}

	// compare subaddress
	return int(p[crypto.PublicKeySize*2]) - int(other[crypto.PublicKeySize*2])
}
