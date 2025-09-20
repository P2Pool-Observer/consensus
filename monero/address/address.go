package address

import (
	"bytes"
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	base58 "git.gammaspectra.live/P2Pool/monero-base58"
)

type Address struct {
	SpendPub    crypto.PublicKeyBytes
	ViewPub     crypto.PublicKeyBytes
	TypeNetwork uint8
	hasChecksum bool
	checksum    Checksum
}

const ChecksumLength = 4

type Checksum [ChecksumLength]byte

func (a *Address) Compare(b Interface) int {
	//compare spend key

	resultSpendKey := crypto.CompareConsensusPublicKeyBytes(&a.SpendPub, b.SpendPublicKey())
	if resultSpendKey != 0 {
		return resultSpendKey
	}

	// compare view key
	return crypto.CompareConsensusPublicKeyBytes(&a.ViewPub, b.ViewPublicKey())
}

func (a *Address) PublicKeys() (spend, view crypto.PublicKey) {
	return &a.SpendPub, &a.ViewPub
}

func (a *Address) SpendPublicKey() *crypto.PublicKeyBytes {
	return &a.SpendPub
}

func (a *Address) ViewPublicKey() *crypto.PublicKeyBytes {
	return &a.ViewPub
}

func (a *Address) ToAddress(network uint8, err ...error) *Address {
	if a.TypeNetwork != network || (len(err) > 0 && err[0] != nil) {
		return nil
	}
	return a
}

func (a *Address) BaseNetwork() uint8 {
	switch a.TypeNetwork {
	case monero.MainNetwork, monero.IntegratedMainNetwork, monero.SubAddressMainNetwork:
		return monero.MainNetwork
	case monero.TestNetwork, monero.IntegratedTestNetwork, monero.SubAddressTestNetwork:
		return monero.TestNetwork
	case monero.StageNetwork, monero.IntegratedStageNetwork, monero.SubAddressStageNetwork:
		return monero.StageNetwork
	default:
		return 0
	}
}

func (a *Address) IsSubaddress() bool {
	return a.TypeNetwork == monero.SubAddressMainNetwork || a.TypeNetwork == monero.SubAddressTestNetwork || a.TypeNetwork == monero.SubAddressStageNetwork
}

func (a *Address) ToPackedAddress() PackedAddress {
	return NewPackedAddressFromBytes(a.SpendPub, a.ViewPub)
}

func FromBase58(address string) *Address {
	preAllocatedBuf := make([]byte, 0, 69)
	raw := base58.DecodeMoneroBase58PreAllocated(preAllocatedBuf, []byte(address))

	if len(raw) != 69 {
		return nil
	}

	switch raw[0] {
	case monero.MainNetwork, monero.TestNetwork, monero.StageNetwork:
		break
	case monero.IntegratedMainNetwork, monero.IntegratedTestNetwork, monero.IntegratedStageNetwork:
		return nil
	case monero.SubAddressMainNetwork, monero.SubAddressTestNetwork, monero.SubAddressStageNetwork:
		// allow
		break
	default:
		return nil
	}

	a := &Address{
		TypeNetwork: raw[0],
		checksum:    checksumHash(raw[:65]),
		hasChecksum: true,
	}

	if bytes.Compare(a.checksum[:], raw[65:]) != 0 {
		return nil
	}

	copy(a.SpendPub[:], raw[1:33])
	copy(a.ViewPub[:], raw[33:65])

	return a
}

func FromBase58NoChecksumCheck(address []byte) *Address {
	preAllocatedBuf := make([]byte, 0, 69)
	raw := base58.DecodeMoneroBase58PreAllocated(preAllocatedBuf, address)

	if len(raw) != 69 {
		return nil
	}

	switch raw[0] {
	case monero.MainNetwork, monero.TestNetwork, monero.StageNetwork:
		break
	case monero.IntegratedMainNetwork, monero.IntegratedTestNetwork, monero.IntegratedStageNetwork:
		return nil
	case monero.SubAddressMainNetwork, monero.SubAddressTestNetwork, monero.SubAddressStageNetwork:
		// allow
		break
	default:
		return nil
	}

	a := &Address{
		TypeNetwork: raw[0],
	}
	copy(a.checksum[:], raw[65:])
	a.hasChecksum = true

	copy(a.SpendPub[:], raw[1:33])
	copy(a.ViewPub[:], raw[33:65])

	return a
}

func checksumHash(data []byte) (sum [ChecksumLength]byte) {
	h := crypto.GetKeccak256Hasher()
	defer crypto.PutKeccak256Hasher(h)
	_, _ = h.Write(data)
	_, _ = h.Read(sum[:])
	return sum
}

func FromRawAddress(typeNetwork uint8, spend, view crypto.PublicKey) *Address {
	var nice [69]byte
	nice[0] = typeNetwork
	copy(nice[1:], spend.AsSlice())
	copy(nice[33:], view.AsSlice())

	return &Address{
		TypeNetwork: nice[0],
		checksum:    checksumHash(nice[:65]),
		hasChecksum: true,
		SpendPub:    spend.AsBytes(),
		ViewPub:     view.AsBytes(),
	}
}

func (a *Address) verifyChecksum() {
	if !a.hasChecksum {
		var nice [69]byte
		nice[0] = a.TypeNetwork
		copy(nice[1:], a.SpendPub.AsSlice())
		copy(nice[1+crypto.PublicKeySize:], a.ViewPub.AsSlice())
		//this race is ok
		a.checksum = checksumHash(nice[:65])
		a.hasChecksum = true
	}
}

func (a *Address) ToBase58() []byte {
	a.verifyChecksum()
	buf := make([]byte, 0, 95)
	return base58.EncodeMoneroBase58PreAllocated(buf, []byte{a.TypeNetwork}, a.SpendPub.AsSlice(), a.ViewPub.AsSlice(), a.checksum[:])
}

func (a *Address) MarshalJSON() ([]byte, error) {
	a.verifyChecksum()
	buf := make([]byte, 95+2)
	buf[0] = '"'
	base58.EncodeMoneroBase58PreAllocated(buf[1:1], []byte{a.TypeNetwork}, a.SpendPub.AsSlice(), a.ViewPub.AsSlice(), a.checksum[:])
	buf[len(buf)-1] = '"'
	return buf, nil
}

func (a *Address) UnmarshalJSON(b []byte) error {
	if len(b) < 2 {
		return errors.New("unsupported length")
	}

	if addr := FromBase58NoChecksumCheck(b[1 : len(b)-1]); addr != nil {
		a.TypeNetwork = addr.TypeNetwork
		a.SpendPub = addr.SpendPub
		a.ViewPub = addr.ViewPub
		a.checksum = addr.checksum
		a.hasChecksum = addr.hasChecksum
		return nil
	} else {
		return errors.New("invalid address")
	}
}
