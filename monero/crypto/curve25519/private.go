package curve25519

import (
	"database/sql/driver"
	"errors"

	fasthex "github.com/tmthrgd/go-hex"
)

const PrivateKeySize = 32

var ZeroPrivateKeyBytes = PrivateKeyBytes{}

type PrivateKeyBytes [PrivateKeySize]byte

func (k *PrivateKeyBytes) Slice() []byte {
	return (*k)[:]
}

func (k *PrivateKeyBytes) Scalar() *Scalar {
	secret, _ := new(Scalar).SetCanonicalBytes((*k)[:])
	return secret
}

func (k *PrivateKeyBytes) String() string {
	return fasthex.EncodeToString(k.Slice())
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
