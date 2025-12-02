package types

import (
	"bytes"
	"crypto/sha3"
	"encoding/base32"
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
)

var onionBase32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

const OnionPort = 28722

//nolint:recvcheck
type OnionAddressV3 curve25519.PublicKeyBytes

func MustOnionAddressV3FromString(s string) (addr OnionAddressV3) {
	err := addr.UnmarshalText([]byte(s))
	if err != nil {
		panic(err)
	}
	return addr
}

const onionVersion = 3
const onionChecksumSize = 2
const onionDomainSuffix = ".onion"
const onionChecksumDomain = ".onion checksum"

var ErrInvalidOnionAddress = errors.New("invalid onion address")

func (pub *OnionAddressV3) UnmarshalText(buf []byte) error {
	if !bytes.HasSuffix(buf, []byte(onionDomainSuffix)) {
		return ErrInvalidOnionAddress
	}

	var addr [curve25519.PublicKeySize + onionChecksumSize + 1]byte
	if len(addr) != onionBase32Encoding.DecodedLen(len(buf)-len(onionDomainSuffix)) {
		return ErrInvalidOnionAddress
	}
	if _, err := onionBase32Encoding.Decode(addr[:], buf[:len(buf)-len(onionDomainSuffix)]); err != nil {
		return err
	}

	if addr[curve25519.PublicKeySize+onionChecksumSize] != onionVersion {
		return ErrInvalidOnionAddress
	}

	copy(pub[:], addr[:])

	hasher := sha3.New256()
	_, _ = hasher.Write([]byte(onionChecksumDomain))
	_, _ = hasher.Write(pub[:])
	_, _ = hasher.Write([]byte{onionVersion})

	var checkSum [32]byte
	hasher.Sum(checkSum[:0])

	if !bytes.Equal(addr[curve25519.PublicKeySize:curve25519.PublicKeySize+onionChecksumSize], checkSum[:onionChecksumSize]) {
		return ErrInvalidOnionAddress
	}

	return nil
}

func (pub *OnionAddressV3) MarshalText() ([]byte, error) {

	hasher := sha3.New256()
	_, _ = hasher.Write([]byte(onionChecksumDomain))
	_, _ = hasher.Write(pub[:])
	_, _ = hasher.Write([]byte{onionVersion})

	var checkSum [32]byte
	hasher.Sum(checkSum[:0])

	var addr [curve25519.PublicKeySize + onionChecksumSize + 1]byte
	copy(addr[:], pub[:])
	copy(addr[curve25519.PublicKeySize:], checkSum[:onionChecksumSize])
	addr[curve25519.PublicKeySize+onionChecksumSize] = onionVersion

	encodedLen := onionBase32Encoding.EncodedLen(len(addr))
	buf := make([]byte, encodedLen+len(onionDomainSuffix))
	onionBase32Encoding.Encode(buf, addr[:])
	copy(buf[encodedLen:], onionDomainSuffix)

	return buf, nil
}

func (pub *OnionAddressV3) Valid() bool {
	// check pubkey encoding
	return (*curve25519.PublicKeyBytes)(pub).PointVarTime() != nil && curve25519.PublicKeyBytes(*pub) != curve25519.ZeroPublicKeyBytes
}

func (pub OnionAddressV3) String() string {
	txt, _ := pub.MarshalText()
	return string(txt)
}
