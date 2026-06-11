package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
)

var i2pB32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

const I2PPort = 28723

//nolint:recvcheck
type I2PAddressB32 [sha256.Size]byte

func MustI2PAddressB32FromString(s string) (addr I2PAddressB32) {
	err := addr.UnmarshalText([]byte(s))
	if err != nil {
		panic(err)
	}
	return addr
}

const i2pB32DomainSuffix = ".b32.i2p"

var ErrInvalidI2PAddress = errors.New("invalid I2P address")

func (pub *I2PAddressB32) UnmarshalText(buf []byte) error {
	if !bytes.HasSuffix(buf, []byte(i2pB32DomainSuffix)) {
		return ErrInvalidI2PAddress
	}

	if len(pub) != i2pB32Encoding.DecodedLen(len(buf)-len(i2pB32DomainSuffix)) {
		return ErrInvalidI2PAddress
	}
	if _, err := i2pB32Encoding.Decode(pub[:], buf[:len(buf)-len(i2pB32DomainSuffix)]); err != nil {
		return err
	}

	return nil
}

func (pub *I2PAddressB32) MarshalText() ([]byte, error) {

	encodedLen := i2pB32Encoding.EncodedLen(len(pub))
	buf := make([]byte, encodedLen+len(i2pB32DomainSuffix))
	i2pB32Encoding.Encode(buf, pub[:])
	copy(buf[encodedLen:], i2pB32DomainSuffix)

	return buf, nil
}

func (pub I2PAddressB32) String() string {
	txt, _ := pub.MarshalText()
	return string(txt)
}
