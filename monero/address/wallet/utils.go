package wallet

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

func Encrypt(data []byte, key *curve25519.Scalar, kdfRounds int, authenticated bool) []byte {
	size := len(data) + crypto.ChaChaNonceSize
	if authenticated {
		size += curve25519.PrivateKeySize * 2
	}
	dst := make([]byte, len(data)+crypto.ChaChaNonceSize, size)
	crypto.ChaChaEncrypt(dst, data, key.Bytes(), kdfRounds)
	if authenticated {
		sig := crypto.CreateMessageSignature[curve25519.ConstantTimeOperations](crypto.Keccak256(dst), key, rand.Reader)
		dst = append(dst, sig.Bytes()...)
	}
	return dst
}

func Decrypt[T curve25519.PointOperations](data []byte, key *curve25519.Scalar, kdfRounds int, authenticated bool) ([]byte, error) {
	size := len(data)
	if authenticated {
		size -= curve25519.PrivateKeySize * 2
		sig := crypto.NewSignatureFromBytes[T](data[size:])
		if sig == nil {
			return nil, errors.New("invalid signature data")
		}
		if !crypto.VerifyMessageSignature(crypto.Keccak256(data[:size]), new(curve25519.PublicKey[T]).ScalarBaseMult(key), *sig) {
			return nil, errors.New("failed to authenticate signature")
		}
	}

	dst := make([]byte, size-crypto.ChaChaNonceSize)
	crypto.ChaChaDecrypt(dst, data[:size], key.Bytes(), kdfRounds)
	return dst, nil
}

const KeyImageExportFileMagic = "Monero key image export\003"

type SignedKeyImage[T curve25519.PointOperations] struct {
	KI        curve25519.PublicKey[T]
	Signature crypto.Signature[T]
}
type KeyImageExport[T curve25519.PointOperations] struct {
	Offset uint32

	SpendPub curve25519.PublicKey[T]
	ViewPub  curve25519.PublicKey[T]

	Images  []SignedKeyImage[T]
	Spent   uint64
	Unspent uint64
}

func DecryptKeyImages[T curve25519.PointOperations](data []byte, key *curve25519.Scalar, kdfRounds int) (*KeyImageExport[T], error) {
	if !bytes.HasPrefix(data, []byte(KeyImageExportFileMagic)) {
		return nil, errors.New("invalid key image export file")
	}
	data = data[len(KeyImageExportFileMagic):]
	plain, err := Decrypt[T](data, key, kdfRounds, true)
	if err != nil {
		return nil, err
	}

	export := new(KeyImageExport[T])

	r := bytes.NewReader(plain)

	if err = utils.ReadLittleEndianInteger(r, &export.Offset); err != nil {
		return nil, err
	}
	if err = export.SpendPub.FromReader(r); err != nil {
		return nil, err
	}
	if err = export.ViewPub.FromReader(r); err != nil {
		return nil, err
	}

	if new(curve25519.PublicKey[T]).ScalarBaseMult(key).Equal(&export.ViewPub) == 0 {
		return nil, errors.New("export is for a different account")
	}

	var ki curve25519.PublicKey[T]
	var sigBuf [curve25519.PrivateKeySize * 2]byte
	for {
		if err = ki.FromReader(r); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if _, err = utils.ReadFullNoEscape(r, sigBuf[:]); err != nil {
			return nil, err
		}
		sig := crypto.NewSignatureFromBytes[T](sigBuf[:])
		if sig == nil {
			return nil, errors.New("invalid signature data")
		}

		export.Images = append(export.Images, SignedKeyImage[T]{
			KI:        ki,
			Signature: *sig,
		})
	}

	return export, nil
}
