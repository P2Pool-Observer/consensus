//go:build packedaddress_base58

package address

import (
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	base58 "git.gammaspectra.live/P2Pool/monero-base58"
)

func (p PackedAddress) String() string {
	return string(p.ToBase58(PackedAddressGlobalNetwork))
}

func (p PackedAddress) MarshalJSON() ([]byte, error) {
	var nice [69]byte
	nice[0] = PackedAddressGlobalNetwork
	copy(nice[1:], p[PackedAddressSpend][:])
	copy(nice[1+crypto.PublicKeySize:], p[PackedAddressView][:])
	sum := crypto.PooledKeccak256(nice[:65])

	buf := make([]byte, 0, 97)
	buf2 := base58.EncodeMoneroBase58PreAllocated(buf[1:], []byte{PackedAddressGlobalNetwork}, p[PackedAddressSpend][:], p[PackedAddressView][:], sum[:4])
	buf = buf[:len(buf2)+1]
	buf[0] = '"'
	buf[len(buf)-1] = '"'
	return buf, nil
}

func (p *PackedAddress) UnmarshalJSON(b []byte) error {
	var a Address
	err := a.UnmarshalJSON(b)
	if err != nil {
		return err
	}
	*p = a.ToPackedAddress()
	return nil
}
