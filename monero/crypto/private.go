package crypto

import (
	"bytes"
	"database/sql/driver"
	"errors"

	"git.gammaspectra.live/P2Pool/consensus/v4/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
	fasthex "github.com/tmthrgd/go-hex"
)

type PrivateKey interface {
	AsSlice() PrivateKeySlice
	AsBytes() PrivateKeyBytes
	AsScalar() *PrivateKeyScalar

	PublicKey() PublicKey

	// GetDerivation derives a secret via a peer PublicKey, ECDH
	GetDerivation(public PublicKey) PublicKey

	// GetDerivationCofactor derives a secret via a peer PublicKey, ECDH, making sure it is in the proper range (*8)
	GetDerivationCofactor(public PublicKey) PublicKey

	String() string
	UnmarshalJSON(b []byte) error
	MarshalJSON() ([]byte, error)
}

const PrivateKeySize = 32

var ZeroPrivateKeyBytes PrivateKeyBytes

type PrivateKeyScalar edwards25519.Scalar

func (p *PrivateKeyScalar) AsSlice() PrivateKeySlice {
	return p.Scalar().Bytes()
}

func (p *PrivateKeyScalar) AsBytes() (buf PrivateKeyBytes) {
	copy(buf[:], p.AsSlice())
	return
}

func (p *PrivateKeyScalar) AsScalar() *PrivateKeyScalar {
	return p
}

func PrivateKeyFromScalar(scalar *edwards25519.Scalar) *PrivateKeyScalar {
	return (*PrivateKeyScalar)(scalar)
}

func (p *PrivateKeyScalar) Scalar() *edwards25519.Scalar {
	return (*edwards25519.Scalar)(p)
}

func (p *PrivateKeyScalar) PublicKey() PublicKey {
	return PublicKeyFromPoint(GetEdwards25519Point().ScalarBaseMult(p.Scalar()))
}

func (p *PrivateKeyScalar) Add(private PrivateKey) PrivateKey {
	return PrivateKeyFromScalar(GetEdwards25519Scalar().Add(p.Scalar(), private.AsScalar().Scalar()))
}

func (p *PrivateKeyScalar) Subtract(private PrivateKey) PrivateKey {
	return PrivateKeyFromScalar(GetEdwards25519Scalar().Subtract(p.Scalar(), private.AsScalar().Scalar()))
}

func (p *PrivateKeyScalar) GetDerivation(public PublicKey) PublicKey {
	return deriveKeyExchangeSecret(p, public.AsPoint())
}

func (p *PrivateKeyScalar) GetDerivationCofactor(public PublicKey) PublicKey {
	return deriveKeyExchangeSecretCofactor(p, public.AsPoint())
}

func (p *PrivateKeyScalar) String() string {
	return fasthex.EncodeToString(p.Scalar().Bytes())
}

func (p *PrivateKeyScalar) UnmarshalJSON(b []byte) error {
	var s string
	if err := utils.UnmarshalJSON(b, &s); err != nil {
		return err
	}

	if buf, err := fasthex.DecodeString(s); err != nil {
		return err
	} else {
		if len(buf) != PrivateKeySize {
			return errors.New("wrong key size")
		}

		if _, err = p.Scalar().SetCanonicalBytes(buf); err != nil {
			return err
		}

		return nil
	}
}

func (p *PrivateKeyScalar) MarshalJSON() ([]byte, error) {
	return []byte("\"" + p.String() + "\""), nil
}

type PrivateKeyBytes [PrivateKeySize]byte

func (k *PrivateKeyBytes) AsSlice() PrivateKeySlice {
	return (*k)[:]
}

func (k *PrivateKeyBytes) AsBytes() PrivateKeyBytes {
	return *k
}

func (k *PrivateKeyBytes) AsScalar() *PrivateKeyScalar {
	secret, _ := GetEdwards25519Scalar().SetCanonicalBytes((*k)[:])
	return PrivateKeyFromScalar(secret)
}

func (k *PrivateKeyBytes) PublicKey() PublicKey {
	return PublicKeyFromPoint(GetEdwards25519Point().ScalarBaseMult(k.AsScalar().Scalar()))
}

func (k *PrivateKeyBytes) GetDerivation(public PublicKey) PublicKey {
	return k.AsScalar().GetDerivation(public)
}

func (k *PrivateKeyBytes) GetDerivationCofactor(public PublicKey) PublicKey {
	return k.AsScalar().GetDerivationCofactor(public)
}

func (k *PrivateKeyBytes) String() string {
	return fasthex.EncodeToString(k.AsSlice())
}

func (k *PrivateKeyBytes) Scan(src any) error {
	if src == nil {
		return nil
	} else if buf, ok := src.([]byte); ok {
		if len(buf) == 0 {
			return nil
		}
		if len(buf) != PrivateKeySize {
			return errors.New("invalid key size")
		}
		copy((*k)[:], buf)

		return nil
	}
	return errors.New("invalid type")
}

func (k *PrivateKeyBytes) Value() (driver.Value, error) {
	var zeroPrivKey PrivateKeyBytes
	if *k == zeroPrivKey {
		return nil, nil
	}
	return []byte((*k)[:]), nil
}

func (k *PrivateKeyBytes) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || len(b) == 2 {
		return nil
	}

	if len(b) != PrivateKeySize*2+2 {
		return errors.New("wrong key size")
	}

	if _, err := fasthex.Decode(k[:], b[1:len(b)-1]); err != nil {
		return err
	} else {
		return nil
	}
}

func (k *PrivateKeyBytes) MarshalJSON() ([]byte, error) {
	var buf [PrivateKeySize*2 + 2]byte
	buf[0] = '"'
	buf[PrivateKeySize*2+1] = '"'
	fasthex.Encode(buf[1:], k[:])
	return buf[:], nil
}

type PrivateKeySlice []byte

func (k *PrivateKeySlice) AsSlice() PrivateKeySlice {
	return *k
}

func (k *PrivateKeySlice) AsBytes() (buf PrivateKeyBytes) {
	copy(buf[:], *k)
	return
}

func (k *PrivateKeySlice) AsScalar() *PrivateKeyScalar {
	secret, _ := GetEdwards25519Scalar().SetCanonicalBytes(*k)
	return PrivateKeyFromScalar(secret)
}

func (k *PrivateKeySlice) PublicKey() PublicKey {
	return PublicKeyFromPoint(GetEdwards25519Point().ScalarBaseMult(k.AsScalar().Scalar()))
}

func (k *PrivateKeySlice) GetDerivation(public PublicKey) PublicKey {
	return k.AsScalar().GetDerivation(public)
}

func (k *PrivateKeySlice) GetDerivationCofactor(public PublicKey) PublicKey {
	return k.AsScalar().GetDerivationCofactor(public)
}

func (k *PrivateKeySlice) String() string {
	return fasthex.EncodeToString(*k)
}

func (k *PrivateKeySlice) Scan(src any) error {
	if src == nil {
		return nil
	} else if buf, ok := src.([]byte); ok {
		if len(buf) == 0 {
			return nil
		}
		if len(buf) != PrivateKeySize {
			return errors.New("invalid key size")
		}
		copy(*k, buf)

		return nil
	}
	return errors.New("invalid type")
}

func (k *PrivateKeySlice) Value() (driver.Value, error) {
	var zeroPrivKey PublicKeyBytes
	if bytes.Compare(*k, zeroPrivKey[:]) == 0 {
		return nil, nil
	}
	return []byte(*k), nil
}

func (k *PrivateKeySlice) UnmarshalJSON(b []byte) error {
	var s string
	if err := utils.UnmarshalJSON(b, &s); err != nil {
		return err
	}

	if buf, err := fasthex.DecodeString(s); err != nil {
		return err
	} else {
		if len(buf) != PrivateKeySize {
			return errors.New("wrong key size")
		}

		*k = buf
		return nil
	}
}

func (k *PrivateKeySlice) MarshalJSON() ([]byte, error) {
	var buf [PrivateKeySize*2 + 2]byte
	buf[0] = '"'
	buf[PrivateKeySize*2+1] = '"'
	fasthex.Encode(buf[1:], (*k)[:])
	return buf[:], nil
}

func deriveKeyExchangeSecretCofactor(private *PrivateKeyScalar, public *PublicKeyPoint) *PublicKeyPoint {
	return public.Multiply(private).Cofactor()
}

func deriveKeyExchangeSecret(private *PrivateKeyScalar, public *PublicKeyPoint) *PublicKeyPoint {
	return public.Multiply(private)
}
