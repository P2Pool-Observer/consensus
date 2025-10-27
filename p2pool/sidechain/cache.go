package sidechain

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type carrotEnoteCacheKey [curve25519.PublicKeySize*2 + 1 + types.HashSize + 8]byte
type deterministicTransactionCacheKey [curve25519.PublicKeySize + types.HashSize]byte
type ephemeralPublicKeyCacheKey [curve25519.PrivateKeySize + curve25519.PublicKeySize*2 + 8]byte
type derivationCacheKey [curve25519.PrivateKeySize + curve25519.PublicKeySize]byte

type carrotEnoteCache struct {
	EphemeralPubkey      curve25519.X25519PublicKey
	SenderReceiverUnctx  curve25519.X25519PublicKey
	SecretSenderReceiver types.Hash
}
type ephemeralPublicKeyWithViewTag struct {
	PublicKey curve25519.PublicKeyBytes
	ViewTag   uint8
}

type DerivationCacheInterface interface {
	GetEphemeralPublicKey(a *address.PackedAddress, txKeySlice curve25519.PrivateKeyBytes, txKeyScalar *curve25519.Scalar, outputIndex uint64) (curve25519.PublicKeyBytes, uint8)
	GetDeterministicTransactionKey(seed types.Hash, prevId types.Hash) *crypto.KeyPair[curve25519.VarTimeOperations]
	GetCarrotCoinbaseEnote(a *address.PackedAddressWithSubaddress, seed types.Hash, blockIndex, amount uint64) *carrot.CoinbaseEnoteV1
}

type DerivationCache struct {
	carrotEnoteCache        utils.Cache[carrotEnoteCacheKey, carrotEnoteCache]
	deterministicKeyCache   utils.Cache[deterministicTransactionCacheKey, *crypto.KeyPair[curve25519.VarTimeOperations]]
	derivationCache         utils.Cache[derivationCacheKey, curve25519.PublicKeyBytes]
	ephemeralPublicKeyCache utils.Cache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag]
	pubKeyToTableCache      utils.Cache[curve25519.PublicKeyBytes, *curve25519.Generator]
	pubKeyToPointCache      utils.Cache[curve25519.PublicKeyBytes, *curve25519.VarTimePublicKey]
}

func NewDerivationLRUCache() *DerivationCache {
	d := &DerivationCache{
		carrotEnoteCache:        utils.NewLRUCache[carrotEnoteCacheKey, carrotEnoteCache](2000),
		deterministicKeyCache:   utils.NewLRUCache[deterministicTransactionCacheKey, *crypto.KeyPair[curve25519.VarTimeOperations]](32),
		ephemeralPublicKeyCache: utils.NewLRUCache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag](2000),
		derivationCache:         utils.NewLRUCache[derivationCacheKey, curve25519.PublicKeyBytes](2000),
		pubKeyToTableCache:      utils.NewLRUCache[curve25519.PublicKeyBytes, *curve25519.Generator](2000),
		pubKeyToPointCache:      utils.NewLRUCache[curve25519.PublicKeyBytes, *curve25519.VarTimePublicKey](2000),
	}
	return d
}

func NewDerivationMapCache() *DerivationCache {
	d := &DerivationCache{
		carrotEnoteCache:        utils.NewMapCache[carrotEnoteCacheKey, carrotEnoteCache](2000),
		deterministicKeyCache:   utils.NewMapCache[deterministicTransactionCacheKey, *crypto.KeyPair[curve25519.VarTimeOperations]](32),
		ephemeralPublicKeyCache: utils.NewMapCache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag](2000),
		derivationCache:         utils.NewMapCache[derivationCacheKey, curve25519.PublicKeyBytes](2000),
		pubKeyToTableCache:      utils.NewMapCache[curve25519.PublicKeyBytes, *curve25519.Generator](2000),
		pubKeyToPointCache:      utils.NewMapCache[curve25519.PublicKeyBytes, *curve25519.VarTimePublicKey](2000),
	}
	return d
}

func NewDerivationNilCache() *DerivationCache {
	d := &DerivationCache{
		carrotEnoteCache:        utils.NewNilCache[carrotEnoteCacheKey, carrotEnoteCache](),
		deterministicKeyCache:   utils.NewNilCache[deterministicTransactionCacheKey, *crypto.KeyPair[curve25519.VarTimeOperations]](),
		ephemeralPublicKeyCache: utils.NewNilCache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag](),
		derivationCache:         utils.NewNilCache[derivationCacheKey, curve25519.PublicKeyBytes](),
		pubKeyToTableCache:      utils.NewNilCache[curve25519.PublicKeyBytes, *curve25519.Generator](),
		pubKeyToPointCache:      utils.NewNilCache[curve25519.PublicKeyBytes, *curve25519.VarTimePublicKey](),
	}
	return d
}

func (d *DerivationCache) Clear() {
	d.carrotEnoteCache.Clear()
	d.deterministicKeyCache.Clear()
	d.ephemeralPublicKeyCache.Clear()
	d.derivationCache.Clear()
	d.pubKeyToPointCache.Clear()
	d.pubKeyToTableCache.Clear()
}

func (d *DerivationCache) GetEphemeralPublicKey(a *address.PackedAddress, txKey curve25519.PrivateKeyBytes, txKeyScalar *curve25519.Scalar, outputIndex uint64) (curve25519.PublicKeyBytes, uint8) {
	var key ephemeralPublicKeyCacheKey
	copy(key[:], txKey[:])
	copy(key[curve25519.PrivateKeySize:], a.ToPackedAddress().Bytes())
	binary.LittleEndian.PutUint64(key[curve25519.PrivateKeySize+curve25519.PublicKeySize*2:], outputIndex)

	if ephemeralPubKey, ok := d.ephemeralPublicKeyCache.Get(key); ok {
		return ephemeralPubKey.PublicKey, ephemeralPubKey.ViewTag
	} else {
		viewTable := d.getPublicKeyTable(*a.ViewPublicKey())
		spendPoint := d.getPublicKeyPoint(*a.SpendPublicKey())
		derivation := d.getDerivation(*a.ViewPublicKey(), txKey, viewTable, txKeyScalar)
		pKB, viewTag := address.GetEphemeralPublicKeyAndViewTagNoAllocate(spendPoint.P(), derivation, outputIndex)
		d.ephemeralPublicKeyCache.Set(key, ephemeralPublicKeyWithViewTag{PublicKey: pKB, ViewTag: viewTag})
		return pKB, viewTag
	}
}

func (d *DerivationCache) GetDeterministicTransactionKey(seed types.Hash, prevId types.Hash) *crypto.KeyPair[curve25519.VarTimeOperations] {
	var key deterministicTransactionCacheKey
	copy(key[:], seed[:])
	copy(key[types.HashSize:], prevId[:])

	if kp, ok := d.deterministicKeyCache.Get(key); ok {
		return kp
	} else {
		kp = crypto.NewKeyPairFromPrivate[curve25519.VarTimeOperations](GetDeterministicTransactionPrivateKey(new(curve25519.Scalar), seed, prevId))
		d.deterministicKeyCache.Set(key, kp)
		return kp
	}
}

func (d *DerivationCache) getDerivation(viewPublicKeyBytes curve25519.PublicKeyBytes, txKey curve25519.PrivateKeyBytes, g *curve25519.Generator, txKeyScalar *curve25519.Scalar) curve25519.PublicKeyBytes {
	var key derivationCacheKey
	copy(key[:], viewPublicKeyBytes[:])
	copy(key[curve25519.PublicKeySize:], txKey[:])

	if derivation, ok := d.derivationCache.Get(key); ok {
		return derivation
	} else {
		derivation = address.GetDerivationNoAllocateTable(g, txKeyScalar)
		d.derivationCache.Set(key, derivation)
		return derivation
	}
}

func (d *DerivationCache) getPublicKeyPoint(publicKey curve25519.PublicKeyBytes) *curve25519.VarTimePublicKey {
	if point, ok := d.pubKeyToPointCache.Get(publicKey); ok {
		return point
	} else {
		point = curve25519.DecodeCompressedPoint(new(curve25519.VarTimePublicKey), publicKey)
		d.pubKeyToPointCache.Set(publicKey, point)
		return point
	}
}

func (d *DerivationCache) getPublicKeyTable(publicKey curve25519.PublicKeyBytes) *curve25519.Generator {
	if table, ok := d.pubKeyToTableCache.Get(publicKey); ok {
		return table
	} else {
		table = curve25519.NewGenerator(publicKey.Point().P())
		d.pubKeyToTableCache.Set(publicKey, table)
		return table
	}
}

func (d *DerivationCache) GetCarrotCoinbaseEnote(a *address.PackedAddressWithSubaddress, seed types.Hash, blockIndex, amount uint64) *carrot.CoinbaseEnoteV1 {
	var key carrotEnoteCacheKey
	copy(key[:], a[:])
	copy(key[curve25519.PublicKeySize*2+1:], seed[:])
	binary.LittleEndian.PutUint64(key[curve25519.PublicKeySize*2+1+types.HashSize:], blockIndex)

	proposal := carrot.PaymentProposalV1[curve25519.VarTimeOperations]{
		Destination: carrot.DestinationV1{
			Address: *a,
		},
		Amount:     amount,
		Randomness: carrot.GetP2PoolDeterministicCarrotOutputRandomness(&blake2b.Digest{}, seed, blockIndex, a.SpendPublicKey(), a.ViewPublicKey()),
	}

	// assume all entries here have been checked ahead of time
	proposal.UnsafeForceTorsionChecked()

	var hasher blake2b.Digest
	var enote carrot.CoinbaseEnoteV1
	inputContext := carrot.MakeCoinbaseInputContext(blockIndex)

	if kp, ok := d.carrotEnoteCache.Get(key); ok {
		// calculate non-cacheable part
		proposal.CoinbaseOutputFromPartial(&hasher, &enote, inputContext[:], kp.EphemeralPubkey, kp.SenderReceiverUnctx, kp.SecretSenderReceiver)
		enote.BlockIndex = blockIndex

		return &enote
	} else {
		ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver, err := proposal.OutputPartial(&hasher, inputContext[:], true)
		if err != nil {
			return nil
		}
		d.carrotEnoteCache.Set(key, carrotEnoteCache{
			EphemeralPubkey:      ephemeralPubkey,
			SenderReceiverUnctx:  senderReceiverUnctx,
			SecretSenderReceiver: secretSenderReceiver,
		})

		// calculate non-cacheable part
		proposal.CoinbaseOutputFromPartial(&hasher, &enote, inputContext[:], ephemeralPubkey, senderReceiverUnctx, secretSenderReceiver)
		enote.BlockIndex = blockIndex

		return &enote
	}
}
