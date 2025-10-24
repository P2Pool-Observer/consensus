package sidechain

import (
	"encoding/binary"

	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	"git.gammaspectra.live/P2Pool/edwards25519"
)

type carrotEnoteCacheKey [crypto.PublicKeySize*2 + 1 + types.HashSize + 8]byte
type deterministicTransactionCacheKey [crypto.PublicKeySize + types.HashSize]byte
type ephemeralPublicKeyCacheKey [crypto.PrivateKeySize + crypto.PublicKeySize*2 + 8]byte
type derivationCacheKey [crypto.PrivateKeySize + crypto.PublicKeySize]byte

type carrotEnoteCache struct {
	EphemeralPubkey      crypto.X25519PublicKey
	SenderReceiverUnctx  crypto.X25519PublicKey
	SecretSenderReceiver types.Hash
}
type ephemeralPublicKeyWithViewTag struct {
	PublicKey crypto.PublicKeyBytes
	ViewTag   uint8
}

type DerivationCacheInterface interface {
	GetEphemeralPublicKey(a *address.PackedAddress, txKeySlice crypto.PrivateKeySlice, txKeyScalar *crypto.PrivateKeyScalar, outputIndex uint64) (crypto.PublicKeyBytes, uint8)
	GetDeterministicTransactionKey(seed types.Hash, prevId types.Hash) *crypto.KeyPair
	GetCarrotCoinbaseEnote(a *address.PackedAddressWithSubaddress, seed types.Hash, blockIndex, amount uint64) *carrot.CoinbaseEnoteV1
}

type DerivationCache struct {
	carrotEnoteCache        utils.Cache[carrotEnoteCacheKey, carrotEnoteCache]
	deterministicKeyCache   utils.Cache[deterministicTransactionCacheKey, *crypto.KeyPair]
	derivationCache         utils.Cache[derivationCacheKey, crypto.PublicKeyBytes]
	ephemeralPublicKeyCache utils.Cache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag]
	pubKeyToTableCache      utils.Cache[crypto.PublicKeyBytes, *edwards25519.PrecomputedTable]
	pubKeyToPointCache      utils.Cache[crypto.PublicKeyBytes, *edwards25519.Point]
}

func NewDerivationLRUCache() *DerivationCache {
	d := &DerivationCache{
		carrotEnoteCache:        utils.NewLRUCache[carrotEnoteCacheKey, carrotEnoteCache](2000),
		deterministicKeyCache:   utils.NewLRUCache[deterministicTransactionCacheKey, *crypto.KeyPair](32),
		ephemeralPublicKeyCache: utils.NewLRUCache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag](2000),
		derivationCache:         utils.NewLRUCache[derivationCacheKey, crypto.PublicKeyBytes](2000),
		pubKeyToTableCache:      utils.NewLRUCache[crypto.PublicKeyBytes, *edwards25519.PrecomputedTable](2000),
		pubKeyToPointCache:      utils.NewLRUCache[crypto.PublicKeyBytes, *edwards25519.Point](2000),
	}
	return d
}

func NewDerivationMapCache() *DerivationCache {
	d := &DerivationCache{
		carrotEnoteCache:        utils.NewMapCache[carrotEnoteCacheKey, carrotEnoteCache](2000),
		deterministicKeyCache:   utils.NewMapCache[deterministicTransactionCacheKey, *crypto.KeyPair](32),
		ephemeralPublicKeyCache: utils.NewMapCache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag](2000),
		derivationCache:         utils.NewMapCache[derivationCacheKey, crypto.PublicKeyBytes](2000),
		pubKeyToTableCache:      utils.NewMapCache[crypto.PublicKeyBytes, *edwards25519.PrecomputedTable](2000),
		pubKeyToPointCache:      utils.NewMapCache[crypto.PublicKeyBytes, *edwards25519.Point](2000),
	}
	return d
}

func NewDerivationNilCache() *DerivationCache {
	d := &DerivationCache{
		carrotEnoteCache:        utils.NewNilCache[carrotEnoteCacheKey, carrotEnoteCache](),
		deterministicKeyCache:   utils.NewNilCache[deterministicTransactionCacheKey, *crypto.KeyPair](),
		ephemeralPublicKeyCache: utils.NewNilCache[ephemeralPublicKeyCacheKey, ephemeralPublicKeyWithViewTag](),
		derivationCache:         utils.NewNilCache[derivationCacheKey, crypto.PublicKeyBytes](),
		pubKeyToTableCache:      utils.NewNilCache[crypto.PublicKeyBytes, *edwards25519.PrecomputedTable](),
		pubKeyToPointCache:      utils.NewNilCache[crypto.PublicKeyBytes, *edwards25519.Point](),
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

func (d *DerivationCache) GetEphemeralPublicKey(a *address.PackedAddress, txKeySlice crypto.PrivateKeySlice, txKeyScalar *crypto.PrivateKeyScalar, outputIndex uint64) (crypto.PublicKeyBytes, uint8) {
	var key ephemeralPublicKeyCacheKey
	copy(key[:], txKeySlice)
	copy(key[crypto.PrivateKeySize:], a.ToPackedAddress().Bytes())
	binary.LittleEndian.PutUint64(key[crypto.PrivateKeySize+crypto.PublicKeySize*2:], outputIndex)

	if ephemeralPubKey, ok := d.ephemeralPublicKeyCache.Get(key); ok {
		return ephemeralPubKey.PublicKey, ephemeralPubKey.ViewTag
	} else {
		viewTable := d.getPublicKeyTable(*a.ViewPublicKey())
		spendPoint := d.getPublicKeyPoint(*a.SpendPublicKey())
		derivation := d.getDerivation(*a.ViewPublicKey(), txKeySlice, viewTable, txKeyScalar.Scalar())
		pKB, viewTag := address.GetEphemeralPublicKeyAndViewTagNoAllocate(spendPoint, derivation, outputIndex)
		d.ephemeralPublicKeyCache.Set(key, ephemeralPublicKeyWithViewTag{PublicKey: pKB, ViewTag: viewTag})
		return pKB, viewTag
	}
}

func (d *DerivationCache) GetDeterministicTransactionKey(seed types.Hash, prevId types.Hash) *crypto.KeyPair {
	var key deterministicTransactionCacheKey
	copy(key[:], seed[:])
	copy(key[types.HashSize:], prevId[:])

	if kp, ok := d.deterministicKeyCache.Get(key); ok {
		return kp
	} else {
		priv := GetDeterministicTransactionPrivateKey(seed, prevId).AsBytes()
		pub := priv.PublicKey().AsBytes()
		privBytes := priv.AsBytes()
		kp = &crypto.KeyPair{PrivateKey: &privBytes, PublicKey: &pub}
		d.deterministicKeyCache.Set(key, kp)
		return kp
	}
}

func (d *DerivationCache) getDerivation(viewPublicKeyBytes crypto.PublicKeyBytes, txKeySlice crypto.PrivateKeySlice, viewPublicKeyTable *edwards25519.PrecomputedTable, txKey *edwards25519.Scalar) crypto.PublicKeyBytes {
	var key derivationCacheKey
	copy(key[:], viewPublicKeyBytes[:])
	copy(key[crypto.PublicKeySize:], txKeySlice[:])

	if derivation, ok := d.derivationCache.Get(key); ok {
		return derivation
	} else {
		derivation = address.GetDerivationNoAllocateTable(viewPublicKeyTable, txKey)
		d.derivationCache.Set(key, derivation)
		return derivation
	}
}

func (d *DerivationCache) getPublicKeyPoint(publicKey crypto.PublicKeyBytes) *edwards25519.Point {
	if point, ok := d.pubKeyToPointCache.Get(publicKey); ok {
		return point
	} else {
		point = publicKey.AsPoint().Point()
		d.pubKeyToPointCache.Set(publicKey, point)
		return point
	}
}

func (d *DerivationCache) getPublicKeyTable(publicKey crypto.PublicKeyBytes) *edwards25519.PrecomputedTable {
	if table, ok := d.pubKeyToTableCache.Get(publicKey); ok {
		return table
	} else {
		table = edwards25519.PointTablePrecompute(publicKey.AsPoint().Point())
		d.pubKeyToTableCache.Set(publicKey, table)
		return table
	}
}

func (d *DerivationCache) GetCarrotCoinbaseEnote(a *address.PackedAddressWithSubaddress, seed types.Hash, blockIndex, amount uint64) *carrot.CoinbaseEnoteV1 {
	var key carrotEnoteCacheKey
	copy(key[:], a[:])
	copy(key[crypto.PublicKeySize*2+1:], seed[:])
	binary.LittleEndian.PutUint64(key[crypto.PublicKeySize*2+1+types.HashSize:], blockIndex)

	proposal := carrot.PaymentProposalV1{
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
