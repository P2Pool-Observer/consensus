package transaction

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"git.gammaspectra.live/P2Pool/consensus/v4/monero"
	"git.gammaspectra.live/P2Pool/consensus/v4/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v4/utils"
)

type Outputs []Output

func (s *Outputs) FromReader(reader utils.ReaderAndByteReader) (err error) {
	var outputCount uint64

	if outputCount, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if outputCount > 0 {
		if outputCount < 8192 {
			*s = make(Outputs, 0, outputCount)
		}

		var o Output
		for index := 0; index < int(outputCount); index++ {
			o.Index = uint64(index)

			if o.Reward, err = utils.ReadCanonicalUvarint(reader); err != nil {
				return err
			}

			if o.Type, err = reader.ReadByte(); err != nil {
				return err
			}

			switch o.Type {
			case TxOutToTaggedKey, TxOutToKey:
				if _, err = io.ReadFull(reader, o.EphemeralPublicKey[:]); err != nil {
					return err
				}

				if o.Type == TxOutToTaggedKey || o.Type == TxOutToCarrotV1 {
					if o.ViewTag, err = reader.ReadByte(); err != nil {
						return err
					}
				} else {
					o.ViewTag = 0
				}
			case TxOutToCarrotV1:
				if _, err = io.ReadFull(reader, o.EphemeralPublicKey[:]); err != nil {
					return err
				}
				if _, err = io.ReadFull(reader, o.CarrotViewTag[:]); err != nil {
					return err
				}
				if _, err = io.ReadFull(reader, o.EncryptedJanusAnchor[:]); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown %d TXOUT key", o.Type)
			}

			*s = append(*s, o)
		}
	}
	return nil
}

func (s *Outputs) BufferLength() (n int) {
	n = utils.UVarInt64Size(len(*s))
	for _, o := range *s {
		n += utils.UVarInt64Size(o.Reward) +
			1 +
			crypto.PublicKeySize
		if o.Type == TxOutToTaggedKey {
			n++
		} else if o.Type == TxOutToCarrotV1 {
			n += monero.CarrotViewTagSize + monero.JanusAnchorSize
		}
	}
	return n
}

func (s *Outputs) MarshalBinary() (data []byte, err error) {
	return s.AppendBinary(make([]byte, 0, s.BufferLength()))
}

func (s *Outputs) AppendBinary(preAllocatedBuf []byte) (data []byte, err error) {
	data = preAllocatedBuf

	data = binary.AppendUvarint(data, uint64(len(*s)))

	for _, o := range *s {
		data = binary.AppendUvarint(data, o.Reward)
		data = append(data, o.Type)

		switch o.Type {
		case TxOutToTaggedKey, TxOutToKey:
			data = append(data, o.EphemeralPublicKey[:]...)

			if o.Type == TxOutToTaggedKey {
				data = append(data, o.ViewTag)
			}
		case TxOutToCarrotV1:
			data = append(data, o.EphemeralPublicKey[:]...)
			data = append(data, o.CarrotViewTag[:]...)
			data = append(data, o.EncryptedJanusAnchor[:]...)
		default:
			return nil, errors.New("unknown output type")
		}
	}
	return data, nil
}

type Output struct {
	Index uint64 `json:"index"`
	// Reward amount of Monero rewarded on this output.
	// Consensus: p2pool limits this field to 56 bits max
	// https://github.com/SChernykh/p2pool/blob/10d583adb67d0566af6c36a6c97fed69545421a2/src/pool_block.h#L104-L106
	Reward uint64 `json:"reward"`
	// Type would be here
	EphemeralPublicKey   crypto.PublicKeyBytes         `json:"ephemeral_public_key"`
	EncryptedJanusAnchor [monero.JanusAnchorSize]uint8 `json:"encrypted_janus_anchor,omitempty"`

	// Type re-arranged here to improve memory layout space
	Type          uint8                          `json:"type"`
	ViewTag       uint8                          `json:"view_tag"`
	CarrotViewTag [monero.CarrotViewTagSize]byte `json:"carrot_view_tag"`
}
