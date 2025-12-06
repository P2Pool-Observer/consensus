package sidechain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"git.gammaspectra.live/P2Pool/consensus/v5/merge_mining"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v5/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

const MaxUncleCount = uint64(math.MaxUint64) / types.HashSize

type SideData struct {
	PublicKey    address.PackedAddress `json:"public_key"`
	IsSubaddress bool                  `json:"is_subaddress,omitempty"`

	CoinbasePrivateKeySeed types.Hash `json:"coinbase_private_key_seed,omitempty"`
	// CoinbasePrivateKey filled or calculated on decoding,
	CoinbasePrivateKey curve25519.PrivateKeyBytes `json:"coinbase_private_key"`
	// Parent Template Id of the parent of this share, or zero if genesis
	Parent types.Hash `json:"parent"`
	// Uncles List of Template Ids of the uncles this share contains
	Uncles               []types.Hash     `json:"uncles,omitempty"`
	Height               uint64           `json:"height"`
	Difficulty           types.Difficulty `json:"difficulty"`
	CumulativeDifficulty types.Difficulty `json:"cumulative_difficulty"`

	// MerkleProof Merkle proof for merge mining, available in ShareVersion ShareVersion_V3 and above
	MerkleProof crypto.MerkleProof `json:"merkle_proof,omitempty"`

	// MergeMiningExtra vector of (chain ID, chain data) pairs
	// Chain data format is arbitrary and depends on the merge mined chain's requirements
	MergeMiningExtra MergeMiningExtra `json:"merge_mining_extra,omitempty"`

	// ExtraBuffer Arbitrary extra data, available in ShareVersion ShareVersion_V2 and above
	ExtraBuffer SideDataExtraBuffer `json:"extra_buffer"`
}
type SideDataExtraBuffer struct {
	SoftwareId          p2pooltypes.SoftwareId      `json:"software_id"`
	SoftwareVersion     p2pooltypes.SoftwareVersion `json:"software_version"`
	RandomNumber        uint32                      `json:"random_number"`
	SideChainExtraNonce uint32                      `json:"side_chain_extra_nonce"`
}

func (b *SideData) BufferLength(majorVersion uint8, version ShareVersion) (size int) {
	size = curve25519.PublicKeySize*2 +
		types.HashSize +
		curve25519.PrivateKeySize +
		utils.UVarInt64Size(len(b.Uncles)) + len(b.Uncles)*types.HashSize +
		utils.UVarInt64Size(b.Height) +
		utils.UVarInt64Size(b.Difficulty.Lo) + utils.UVarInt64Size(b.Difficulty.Hi) +
		utils.UVarInt64Size(b.CumulativeDifficulty.Lo) + utils.UVarInt64Size(b.CumulativeDifficulty.Hi)

	if majorVersion >= monero.HardForkCarrotVersion {
		// PublicKey IsSubaddress
		size++
	}

	if version >= ShareVersion_V2 {
		// ExtraBuffer
		size += 4 * 4
	}
	if version >= ShareVersion_V3 {
		// MerkleProof + MergeMiningExtra
		size += utils.UVarInt64Size(len(b.MerkleProof)) + len(b.MerkleProof)*types.HashSize + b.MergeMiningExtra.BufferLength()
	}

	return size
}

func (b *SideData) MarshalBinary(majorVersion uint8, version ShareVersion) (buf []byte, err error) {
	return b.AppendBinary(make([]byte, 0, b.BufferLength(majorVersion, version)), majorVersion, version)
}

func (b *SideData) AppendBinary(preAllocatedBuf []byte, majorVersion uint8, version ShareVersion) (buf []byte, err error) {
	buf = preAllocatedBuf
	buf = append(buf, b.PublicKey[address.PackedAddressSpend][:]...)
	buf = append(buf, b.PublicKey[address.PackedAddressView][:]...)
	if majorVersion >= monero.HardForkCarrotVersion {
		if b.IsSubaddress {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
	}

	if version >= ShareVersion_V2 {
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

	if version >= ShareVersion_V3 {
		// merkle proof
		if len(b.MerkleProof) > merge_mining.MaxChainsLog2 {
			return nil, utils.ErrorfNoEscape("merkle proof too large: %d > %d", len(b.MerkleProof), merge_mining.MaxChainsLog2)
		}
		buf = append(buf, uint8(len(b.MerkleProof)))
		for _, h := range b.MerkleProof {
			buf = append(buf, h[:]...)
		}

		// merge mining extra
		if len(b.MergeMiningExtra) > merge_mining.MaxChains {
			return nil, utils.ErrorfNoEscape("merge mining extra size too big: %d > %d", len(b.MergeMiningExtra), merge_mining.MaxChains)
		}
		buf = binary.AppendUvarint(buf, uint64(len(b.MergeMiningExtra)))
		for i := range b.MergeMiningExtra {
			buf = append(buf, b.MergeMiningExtra[i].ChainId[:]...)
			buf = binary.AppendUvarint(buf, uint64(len(b.MergeMiningExtra[i].Data)))
			buf = append(buf, b.MergeMiningExtra[i].Data...)
		}
	}

	if version >= ShareVersion_V2 {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(b.ExtraBuffer.SoftwareId))
		buf = binary.LittleEndian.AppendUint32(buf, uint32(b.ExtraBuffer.SoftwareVersion))
		buf = binary.LittleEndian.AppendUint32(buf, b.ExtraBuffer.RandomNumber)
		buf = binary.LittleEndian.AppendUint32(buf, b.ExtraBuffer.SideChainExtraNonce)
	}

	return buf, nil
}

func (b *SideData) FromReader(reader utils.ReaderAndByteReader, majorVersion uint8, version ShareVersion) (err error) {
	var (
		uncleCount uint64
		uncleHash  types.Hash

		merkleProofSize          uint8
		mergeMiningExtraSize     uint64
		mergeMiningExtraDataSize uint64
	)

	if _, err = utils.ReadFullNoEscape(reader, b.PublicKey[address.PackedAddressSpend][:]); err != nil {
		return err
	}
	if _, err = utils.ReadFullNoEscape(reader, b.PublicKey[address.PackedAddressView][:]); err != nil {
		return err
	}
	// read subaddress data
	if majorVersion >= monero.HardForkCarrotVersion {
		var isSubaddress uint8
		if isSubaddress, err = utils.ReadByteNoEscape(reader); err != nil {
			return err
		}
		// ensure value can only be 0 or 1
		if isSubaddress > 1 {
			return utils.ErrorfNoEscape("invalid isSubaddress: %d > 1", isSubaddress)
		}
		b.IsSubaddress = isSubaddress == 1
	}

	if version >= ShareVersion_V2 {
		// Read private key seed instead of private key. Only on ShareVersion_V2 and above
		// needs preprocessing
		if _, err = utils.ReadFullNoEscape(reader, b.CoinbasePrivateKeySeed[:]); err != nil {
			return err
		}
	} else {
		if _, err = utils.ReadFullNoEscape(reader, b.CoinbasePrivateKey[:]); err != nil {
			return err
		}
	}

	if _, err = utils.ReadFullNoEscape(reader, b.Parent[:]); err != nil {
		return err
	}

	if uncleCount, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	} else if uncleCount > MaxUncleCount {
		return utils.ErrorfNoEscape("uncle count too large: %d > %d", uncleCount, MaxUncleCount)
	} else if uncleCount > 0 {
		// preallocate for append, with 64 as soft limit
		b.Uncles = make([]types.Hash, 0, min(64, uncleCount))

		for range uncleCount {
			if _, err = utils.ReadFullNoEscape(reader, uncleHash[:]); err != nil {
				return err
			}
			b.Uncles = append(b.Uncles, uncleHash)
		}
	}

	if b.Height, err = utils.ReadCanonicalUvarint(reader); err != nil {
		return err
	}

	if b.Height > PoolBlockMaxSideChainHeight {
		return utils.ErrorfNoEscape("side block height too high (%d > %d)", b.Height, PoolBlockMaxSideChainHeight)
	}

	{
		if b.Difficulty.Lo, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		if b.Difficulty.Hi, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}
	}

	{
		if b.CumulativeDifficulty.Lo, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}

		if b.CumulativeDifficulty.Hi, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		}
	}

	if b.CumulativeDifficulty.Cmp(PoolBlockMaxCumulativeDifficulty) > 0 {
		return utils.ErrorfNoEscape("side block cumulative difficulty too large (%s > %s)", b.CumulativeDifficulty.StringNumeric(), PoolBlockMaxCumulativeDifficulty.StringNumeric())
	}

	// Read merkle proof list of hashes. Only on ShareVersion_V3 and above
	if version >= ShareVersion_V3 {
		if merkleProofSize, err = utils.ReadByteNoEscape(reader); err != nil {
			return err
		} else if merkleProofSize > merge_mining.MaxChainsLog2 {
			return utils.ErrorfNoEscape("merkle proof too large: %d > %d", merkleProofSize, merge_mining.MaxChainsLog2)
		} else if merkleProofSize > 0 {
			// preallocate
			b.MerkleProof = make(crypto.MerkleProof, merkleProofSize)

			for i := range merkleProofSize {
				if _, err = utils.ReadFullNoEscape(reader, b.MerkleProof[i][:]); err != nil {
					return err
				}
			}
		}

		if mergeMiningExtraSize, err = utils.ReadCanonicalUvarint(reader); err != nil {
			return err
		} else if mergeMiningExtraSize > merge_mining.MaxChains {
			return utils.ErrorfNoEscape("merge mining data too big: %d > %d", mergeMiningExtraSize, merge_mining.MaxChains)
		} else if mergeMiningExtraSize > 0 {
			// preallocate
			b.MergeMiningExtra = make(MergeMiningExtra, mergeMiningExtraSize)

			for i := range mergeMiningExtraSize {
				if _, err = utils.ReadFullNoEscape(reader, b.MergeMiningExtra[i].ChainId[:]); err != nil {
					return err
				} else if i > 0 && b.MergeMiningExtra[i-1].ChainId.Compare(b.MergeMiningExtra[i].ChainId) >= 0 {
					// IDs must be ordered to avoid duplicates
					return utils.ErrorfNoEscape("duplicate or not ordered merge mining data chain id: %s > %s", b.MergeMiningExtra[i-1].ChainId, b.MergeMiningExtra[i].ChainId)
				} else if mergeMiningExtraDataSize, err = utils.ReadCanonicalUvarint(reader); err != nil {
					return err
				} else if mergeMiningExtraDataSize > PoolBlockMaxTemplateSize {
					return utils.ErrorfNoEscape("merge mining data size too big: %d > %d", mergeMiningExtraDataSize, PoolBlockMaxTemplateSize)
				} else if mergeMiningExtraDataSize > 0 {
					b.MergeMiningExtra[i].Data = make(types.Bytes, mergeMiningExtraDataSize)
					if _, err = utils.ReadFullNoEscape(reader, b.MergeMiningExtra[i].Data); err != nil {
						return err
					}
				}

				// field no longer allowed (use subaddress bool)
				// TODO: maybe just ignore field but allow it?
				if majorVersion >= monero.HardForkCarrotVersion && b.MergeMiningExtra[i].ChainId == ExtraChainKeySubaddressViewPub {
					return utils.ErrorfNoEscape("subaddress_viewpub is not allowed")
				}
			}
		}
	}

	// Read share extra buffer. Only on ShareVersion_V2 and above
	if version >= ShareVersion_V2 {
		if err = utils.BinaryReadNoEscape(reader, binary.LittleEndian, &b.ExtraBuffer.SoftwareId); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
		if err = utils.BinaryReadNoEscape(reader, binary.LittleEndian, &b.ExtraBuffer.SoftwareVersion); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
		if err = utils.BinaryReadNoEscape(reader, binary.LittleEndian, &b.ExtraBuffer.RandomNumber); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
		if err = utils.BinaryReadNoEscape(reader, binary.LittleEndian, &b.ExtraBuffer.SideChainExtraNonce); err != nil {
			return fmt.Errorf("within extra buffer: %w", err)
		}
	}

	return nil
}

func (b *SideData) UnmarshalBinary(data []byte, majorVersion uint8, version ShareVersion) error {
	reader := bytes.NewReader(data)
	err := b.FromReader(reader, majorVersion, version)
	if err != nil {
		return err
	}
	if reader.Len() > 0 {
		return errors.New("leftover bytes in reader")
	}
	return nil
}
