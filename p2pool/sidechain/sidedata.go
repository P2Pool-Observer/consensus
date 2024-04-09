package sidechain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v3/monero/crypto"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v3/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"git.gammaspectra.live/P2Pool/consensus/v3/utils"
	"io"
)

const MaxMerkleProofSize = 7

type SideData struct {
	PublicKey              address.PackedAddress `json:"public_key"`
	CoinbasePrivateKeySeed types.Hash            `json:"coinbase_private_key_seed,omitempty"`
	// CoinbasePrivateKey filled or calculated on decoding
	CoinbasePrivateKey   crypto.PrivateKeyBytes `json:"coinbase_private_key"`
	Parent               types.Hash             `json:"parent"`
	Uncles               []types.Hash           `json:"uncles,omitempty"`
	Height               uint64                 `json:"height"`
	Difficulty           types.Difficulty       `json:"difficulty"`
	CumulativeDifficulty types.Difficulty       `json:"cumulative_difficulty"`

	// MerkleProof Merkle proof for merge mining, available in ShareVersion ShareVersion_V3 and above
	MerkleProof crypto.MerkleProof `json:"merkle_proof,omitempty"`

	// ExtraBuffer Arbitrary extra data, available in ShareVersion ShareVersion_V2 and above
	ExtraBuffer SideDataExtraBuffer `json:"extra_buffer,omitempty"`
}

type SideDataExtraBuffer struct {
	SoftwareId          p2pooltypes.SoftwareId      `json:"software_id"`
	SoftwareVersion     p2pooltypes.SoftwareVersion `json:"software_version"`
	RandomNumber        uint32                      `json:"random_number"`
	SideChainExtraNonce uint32                      `json:"side_chain_extra_nonce"`
}

func (b *SideData) BufferLength(version ShareVersion) (size int) {
	size = crypto.PublicKeySize +
		crypto.PublicKeySize +
		types.HashSize +
		crypto.PrivateKeySize +
		utils.UVarInt64Size(len(b.Uncles)) + len(b.Uncles)*types.HashSize +
		utils.UVarInt64Size(b.Height) +
		utils.UVarInt64Size(b.Difficulty.Lo) + utils.UVarInt64Size(b.Difficulty.Hi) +
		utils.UVarInt64Size(b.CumulativeDifficulty.Lo) + utils.UVarInt64Size(b.CumulativeDifficulty.Hi)

	if version > ShareVersion_V1 {
		// ExtraBuffer
		size += 4 * 4
	}
	if version > ShareVersion_V2 {
		// MerkleProof
		size += utils.UVarInt64Size(len(b.MerkleProof)) + len(b.MerkleProof)*types.HashSize
	}

	return size
}

func (b *SideData) MarshalBinary(version ShareVersion) (buf []byte, err error) {
	return b.AppendBinary(make([]byte, 0, b.BufferLength(version)), version)
}

func (b *SideData) AppendBinary(preAllocatedBuf []byte, version ShareVersion) (buf []byte, err error) {
	buf = preAllocatedBuf
	buf = append(buf, b.PublicKey[address.PackedAddressSpend][:]...)
	buf = append(buf, b.PublicKey[address.PackedAddressView][:]...)
	if version > ShareVersion_V1 {
		buf = append(buf, b.CoinbasePrivateKeySeed[:]...)
	} else {
		buf = append(buf, b.CoinbasePrivateKey[:]...)
	}
	buf = append(buf, b.Parent[:]...)
	buf = binary.AppendUvarint(buf, uint64(len(b.Uncles)))
	for _, uId := range b.Uncles {
		buf = append(buf, uId[:]...)
	}
	buf = binary.AppendUvarint(buf, b.Height)
	buf = binary.AppendUvarint(buf, b.Difficulty.Lo)
	buf = binary.AppendUvarint(buf, b.Difficulty.Hi)
	buf = binary.AppendUvarint(buf, b.CumulativeDifficulty.Lo)
	buf = binary.AppendUvarint(buf, b.CumulativeDifficulty.Hi)

	if version > ShareVersion_V2 {
		if len(b.MerkleProof) > MaxMerkleProofSize {
			return nil, fmt.Errorf("merkle proof too large: %d > %d", len(b.MerkleProof), MaxMerkleProofSize)
		}
		buf = append(buf, uint8(len(b.MerkleProof)))
		for _, h := range b.MerkleProof {
			buf = append(buf, h[:]...)
		}
	}

	if version > ShareVersion_V1 {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(b.ExtraBuffer.SoftwareId))
		buf = binary.LittleEndian.AppendUint32(buf, uint32(b.ExtraBuffer.SoftwareVersion))
		buf = binary.LittleEndian.AppendUint32(buf, b.ExtraBuffer.RandomNumber)
		buf = binary.LittleEndian.AppendUint32(buf, b.ExtraBuffer.SideChainExtraNonce)
	}

	return buf, nil
}

func (b *SideData) FromReader(reader utils.ReaderAndByteReader, version ShareVersion) (err error) {
	var (
		uncleCount uint64
		uncleHash  types.Hash

		merkleProofSize uint8
		merkleProofHash types.Hash
	)
	if _, err = io.ReadFull(reader, b.PublicKey[address.PackedAddressSpend][:]); err != nil {
		return err
	}
	if _, err = io.ReadFull(reader, b.PublicKey[address.PackedAddressView][:]); err != nil {
		return err
	}

	if version > ShareVersion_V1 {
		//needs preprocessing
		if _, err = io.ReadFull(reader, b.CoinbasePrivateKeySeed[:]); err != nil {
			return err
		}
	} else {
		if _, err = io.ReadFull(reader, b.CoinbasePrivateKey[:]); err != nil {
			return err
		}
	}
	if _, err = io.ReadFull(reader, b.Parent[:]); err != nil {
		return err
	}
	if uncleCount, err = binary.ReadUvarint(reader); err != nil {
		return err
	}

	for i := 0; i < int(uncleCount); i++ {
		if _, err = io.ReadFull(reader, uncleHash[:]); err != nil {
			return err
		}
		//TODO: check if copy is needed
		b.Uncles = append(b.Uncles, uncleHash)
	}

	if b.Height, err = binary.ReadUvarint(reader); err != nil {
		return err
	}

	{
		if b.Difficulty.Lo, err = binary.ReadUvarint(reader); err != nil {
			return err
		}

		if b.Difficulty.Hi, err = binary.ReadUvarint(reader); err != nil {
			return err
		}
	}

	{
		if b.CumulativeDifficulty.Lo, err = binary.ReadUvarint(reader); err != nil {
			return err
		}

		if b.CumulativeDifficulty.Hi, err = binary.ReadUvarint(reader); err != nil {
			return err
		}
	}

	if version > ShareVersion_V2 {
		if merkleProofSize, err = reader.ReadByte(); err != nil {
			return err
		}
		if merkleProofSize > MaxMerkleProofSize {
			return fmt.Errorf("merkle proof too large: %d > %d", len(b.MerkleProof), MaxMerkleProofSize)
		}
		b.MerkleProof = make(crypto.MerkleProof, 0, merkleProofSize)

		for i := 0; i < int(merkleProofSize); i++ {
			if _, err = io.ReadFull(reader, merkleProofHash[:]); err != nil {
				return err
			}
			b.MerkleProof = append(b.MerkleProof, merkleProofHash)
		}
	}

	if version > ShareVersion_V1 {
		if err = binary.Read(reader, binary.LittleEndian, &b.ExtraBuffer.SoftwareId); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
		if err = binary.Read(reader, binary.LittleEndian, &b.ExtraBuffer.SoftwareVersion); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
		if err = binary.Read(reader, binary.LittleEndian, &b.ExtraBuffer.RandomNumber); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
		if err = binary.Read(reader, binary.LittleEndian, &b.ExtraBuffer.SideChainExtraNonce); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
	}

	return nil
}

func (b *SideData) UnmarshalBinary(data []byte, version ShareVersion) error {
	reader := bytes.NewReader(data)
	return b.FromReader(reader, version)
}
