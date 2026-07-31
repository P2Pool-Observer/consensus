package transaction

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

const TxExtraTagPadding = 0x00
const TxExtraTagPubKey = 0x01
const TxExtraTagNonce = 0x02
const TxExtraTagMergeMining = 0x03
const TxExtraTagAdditionalPubKeys = 0x04
const TxExtraTagOrdinalsRegister = 0x10
const TxExtraTagOrdinalsUpdate = 0x11

// todo: mordinal v2

const TxExtraTagOrdinalsRegisterMultiBody = 0x12
const TxExtraTagOrdinalsMultiBodyPart = 0x13
const TxExtraTagMysteriousMinergate = 0xde

const TxExtraPaddingMaxCount = 255
const TxExtraNonceMaxCount = 255

const TxExtraNoncePaymentId = 0x00
const TxExtraNonceEncryptedPaymentId = 0x01

const TxExtraTagMergeMiningMaxCount = types.HashSize + 9

const TxExtraTemplateNonceSize = 4

type ExtraTags []ExtraTag

type ExtraTag struct {
	// VarInt has different meanings. In TxExtraTagMergeMining it is depth, while in others it is length
	VarInt    uint64      `json:"var_int"`
	Tag       uint8       `json:"tag"`
	HasVarInt bool        `json:"has_var_int"`
	Data      types.Bytes `json:"data"`
}

func (t *ExtraTags) UnmarshalBinary(data []byte) (err error) {
	reader := bytes.NewReader(data)
	err = t.FromReader(reader)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}

func (t *ExtraTags) BufferLength() (length int) {
	for _, tag := range *t {
		length += tag.BufferLength()
	}
	return length
}

func (t *ExtraTags) MarshalBinary() ([]byte, error) {

	return t.AppendBinary(make([]byte, 0, t.BufferLength()))
}

func (t *ExtraTags) AppendBinary(preAllocatedBuf []byte) (buf []byte, err error) {
	if t == nil {
		return nil, nil
	}
	buf = preAllocatedBuf
	for _, tag := range *t {
		if buf, err = tag.AppendBinary(buf); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

func (t *ExtraTags) SideChainHashingBlob(preAllocatedBuf []byte, majorVersion uint8, zeroTemplateId bool) (buf []byte, err error) {
	if t == nil {
		return nil, nil
	}
	buf = preAllocatedBuf
	for _, tag := range *t {
		if buf, err = tag.SideChainHashingBlob(buf, majorVersion, zeroTemplateId); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

func (t *ExtraTags) FromReader(reader utils.ReaderAndByteReader) (err error) {
	for {
		var tag ExtraTag
		if err = tag.FromReader(reader); err != nil {
			if errors.Is(err, ErrExtraTagNoMoreTags) {
				return nil
			}
			return err
		}
		*t = append(*t, tag)
	}
}

func (t *ExtraTags) GetTag(tag uint8) *ExtraTag {
	for i := range *t {
		if (*t)[i].Tag == tag {
			return &(*t)[i]
		}
	}

	return nil
}

func (t *ExtraTag) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	err := t.FromReader(reader)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}

func (t *ExtraTag) BufferLength() int {
	if t.HasVarInt {
		return 1 + utils.UVarInt64Size(t.VarInt) + len(t.Data)
	}
	return 1 + len(t.Data)
}

func (t *ExtraTag) MarshalBinary() ([]byte, error) {
	return t.AppendBinary(make([]byte, 0, t.BufferLength()))
}

func (t *ExtraTag) AppendBinary(preAllocatedBuf []byte) ([]byte, error) {
	buf := preAllocatedBuf
	buf = append(buf, t.Tag)
	if t.HasVarInt {
		buf = binary.AppendUvarint(buf, t.VarInt)
	}
	buf = append(buf, t.Data...)
	return buf, nil
}

func (t *ExtraTag) SideChainHashingBlob(preAllocatedBuf []byte, majorVersion uint8, zeroTemplateId bool) ([]byte, error) {
	buf := preAllocatedBuf
	buf = append(buf, t.Tag)
	if t.HasVarInt {
		buf = binary.AppendUvarint(buf, t.VarInt)
	}
	if zeroTemplateId && t.Tag == TxExtraTagMergeMining {
		// TODO: this is to comply with non-standard p2pool serialization, see https://github.com/SChernykh/p2pool/issues/249
		// v3 has some extra data included before hash
		// serialize everything but the last hash size bytes
		dataLen := max(0, len(t.Data)-types.HashSize)
		buf = append(buf, t.Data[:dataLen]...)

		// serialize zero hash or remaining data only
		buf = append(buf, make([]byte, len(t.Data)-dataLen)...)
		// TODO: do the same as extra nonce
	} else if t.Tag == TxExtraTagNonce {
		if majorVersion < monero.HardForkCarrotVersion {
			//Replace only the first four bytes
			buf = append(buf,
				[]byte{0, 0, 0, 0}[:min(TxExtraTemplateNonceSize, len(t.Data))]...,
			)
			if len(t.Data) > TxExtraTemplateNonceSize {
				buf = append(buf, t.Data[TxExtraTemplateNonceSize:]...)
			}
		} else {
			// entire tag is zero'd except length
			buf = append(buf, make([]byte, len(t.Data))...)
		}
	} else {
		buf = append(buf, t.Data...)
	}
	return buf, nil
}

var ErrExtraTagNoMoreTags = errors.New("no more tags")

func (t *ExtraTag) FromReader(reader utils.ReaderAndByteReader) (err error) {

	if t.Tag, err = utils.ReadByteNoEscape(reader); err != nil {
		if err == io.EOF { //nolint:errorlint
			return ErrExtraTagNoMoreTags
		}
		return err
	}

	switch t.Tag {
	default:
		return utils.ErrorfNoEscape("unknown extra tag %d", t.Tag)
	case TxExtraTagPadding:
		var size uint64
		var zero byte
		for size = 1; size <= TxExtraPaddingMaxCount; size++ {
			if zero, err = utils.ReadByteNoEscape(reader); err != nil {
				if err == io.EOF { //nolint:errorlint
					break
				} else {
					return err
				}
			}

			if zero != 0 {
				return errors.New("padding is not zero")
			}
		}

		if size > TxExtraPaddingMaxCount {
			return errors.New("padding is too big")
		}

		t.Data = make([]byte, size-1)
	case TxExtraTagPubKey:
		t.Data = make([]byte, curve25519.PublicKeySize)
		if _, err = utils.ReadFullNoEscape(reader, t.Data); err != nil {
			return err
		}
	case TxExtraTagNonce:
		t.HasVarInt = true
		if t.VarInt, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		} else {
			if t.VarInt > TxExtraNonceMaxCount {
				return errors.New("nonce is too big")
			}

			t.Data = make([]byte, t.VarInt)
			if _, err = utils.ReadFullNoEscape(reader, t.Data); err != nil {
				return err
			}
		}
	case TxExtraTagAdditionalPubKeys:
		t.HasVarInt = true
		if t.VarInt, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		} else {
			_, err = utils.ReadFullProgressive(utils.LimitByteReader(reader, int64(types.HashSize*t.VarInt)), &t.Data, int(types.HashSize*t.VarInt))
			if err != nil {
				return err
			}
		}
	case TxExtraTagMergeMining, TxExtraTagOrdinalsRegister, TxExtraTagOrdinalsUpdate, TxExtraTagMysteriousMinergate:
		t.HasVarInt = true
		if t.VarInt, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		} else {
			_, err = utils.ReadFullProgressive(utils.LimitByteReader(reader, int64(t.VarInt)), &t.Data, int(t.VarInt))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type PublicKeys struct {
	PublicKey            curve25519.PublicKeyBytes
	AdditionalPublicKeys []curve25519.PublicKeyBytes
}

func (pubs PublicKeys) Main() curve25519.PublicKeyBytes {
	return pubs.PublicKey
}

func (pubs PublicKeys) Additional(i uint64) (curve25519.PublicKeyBytes, error) {
	if len(pubs.AdditionalPublicKeys) > int(i) {
		return pubs.AdditionalPublicKeys[i], nil
	} else {
		return curve25519.ZeroPublicKeyBytes, io.ErrUnexpectedEOF
	}
}

func (pubs PublicKeys) Slice() (out []curve25519.PublicKeyBytes) {
	if pubs.PublicKey != curve25519.ZeroPublicKeyBytes {
		out = append(out, pubs.PublicKey)
		out = append(out, pubs.AdditionalPublicKeys...)
		return out
	} else {
		return pubs.AdditionalPublicKeys
	}
}

func (pubs PublicKeys) Scan(i uint64) iter.Seq[*curve25519.PublicKeyBytes] {
	return func(yield func(*curve25519.PublicKeyBytes) bool) {
		if pubs.PublicKey != curve25519.ZeroPublicKeyBytes {
			if !yield(&pubs.PublicKey) {
				return
			}
		}

		if len(pubs.AdditionalPublicKeys) > int(i) {
			yield(&pubs.AdditionalPublicKeys[i])
		}
	}
}

func ExtraPublicKeys(extra ExtraTags) (pubs PublicKeys, ok bool) {
	if txPubExtra := extra.GetTag(TxExtraTagPubKey); txPubExtra != nil && len(txPubExtra.Data) == curve25519.PublicKeySize {
		pubs.PublicKey = curve25519.PublicKeyBytes(txPubExtra.Data)
		//TODO: fail if this is not set?
		ok = true
	}

	if txPubsExtra := extra.GetTag(TxExtraTagAdditionalPubKeys); txPubsExtra != nil && len(txPubsExtra.Data) > 0 && len(txPubsExtra.Data)%curve25519.PublicKeySize == 0 {
		// #nosec G103 -- verified public key size for data, and that it's modulo the data, and it's longer than 0
		additionalPubs := unsafe.Slice((*curve25519.PublicKeyBytes)(unsafe.Pointer(unsafe.SliceData(txPubsExtra.Data))), len(txPubsExtra.Data)/curve25519.PublicKeySize)
		pubs.AdditionalPublicKeys = additionalPubs
		ok = true
	}

	return pubs, ok
}

func ExtraPaymentId(extra ExtraTags) (legacyPaymentId *[monero.LegacyPaymentIdSize]byte, encryptedPaymentId *[monero.PaymentIdSize]byte) {
	nonce := extra.GetTag(TxExtraTagNonce)
	if nonce == nil {
		return nil, nil
	}

	if len(nonce.Data) == monero.LegacyPaymentIdSize+1 && nonce.Data[0] == TxExtraNoncePaymentId {
		return (*[monero.LegacyPaymentIdSize]byte)(nonce.Data[1:]), nil
	} else if len(nonce.Data) == monero.PaymentIdSize+1 && nonce.Data[0] == TxExtraNonceEncryptedPaymentId {
		return nil, (*[monero.PaymentIdSize]byte)(nonce.Data[1:])
	}
	return nil, nil
}
