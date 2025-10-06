package sidechain

import (
	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type NilDerivationCache struct {
}

func (d *NilDerivationCache) Clear() {

}

func (d *NilDerivationCache) GetEphemeralPublicKey(a *address.PackedAddress, _ crypto.PrivateKeySlice, txKeyScalar *crypto.PrivateKeyScalar, outputIndex uint64) (crypto.PublicKeyBytes, uint8) {
	var derivation crypto.PublicKeyPoint
	address.GetDerivationNoAllocate(derivation.Point(), a.ViewPublicKey().AsPoint().Point(), txKeyScalar.Scalar())
	ephemeralPubKey, viewTag := address.GetEphemeralPublicKeyAndViewTagNoAllocate(a.SpendPublicKey().AsPoint().Point(), derivation.AsBytes(), outputIndex)

	return ephemeralPubKey.AsBytes(), viewTag
}

func (d *NilDerivationCache) GetDeterministicTransactionKey(seed types.Hash, prevId types.Hash) *crypto.KeyPair {
	return crypto.NewKeyPairFromPrivate(GetDeterministicTransactionPrivateKey(seed, prevId))
}

func (d *NilDerivationCache) GetCarrotCoinbaseEnote(a *address.PackedAddressWithSubaddress, seed types.Hash, blockIndex, amount uint64) *carrot.CoinbaseEnoteV1 {
	proposal := carrot.PaymentProposalV1{
		Destination: carrot.DestinationV1{
			Address: *a,
		},
		Amount:     amount,
		Randomness: carrot.GetP2PoolDeterministicCarrotOutputRandomness(&blake2b.Digest{}, seed, blockIndex, a.SpendPublicKey(), a.ViewPublicKey()),
	}

	var enote carrot.CoinbaseEnoteV1
	err := proposal.CoinbaseOutput(&enote, blockIndex)
	if err != nil {
		return nil
	}
	return &enote
}
