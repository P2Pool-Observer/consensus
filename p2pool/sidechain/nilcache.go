package sidechain

import (
	"git.gammaspectra.live/P2Pool/blake2b"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address/carrot"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type NilDerivationCache struct {
}

func (d *NilDerivationCache) Clear() {

}

func (d *NilDerivationCache) GetEphemeralPublicKey(a *address.PackedAddress, _ curve25519.PrivateKeyBytes, txKeyScalar *curve25519.Scalar, outputIndex uint64) (curve25519.PublicKeyBytes, uint8) {
	spendPub, _ := new(curve25519.VarTimePublicKey).SetBytes(a.SpendPublicKey()[:])
	viewPub, _ := new(curve25519.VarTimePublicKey).SetBytes(a.ViewPublicKey()[:])
	ephemeralPubKey, viewTag := address.GetEphemeralPublicKeyAndViewTag(new(curve25519.VarTimePublicKey), spendPub, viewPub, txKeyScalar, outputIndex)

	return ephemeralPubKey.AsBytes(), viewTag
}

func (d *NilDerivationCache) GetDeterministicTransactionKey(seed types.Hash, prevId types.Hash) *crypto.KeyPair[curve25519.VarTimeOperations] {
	return crypto.NewKeyPairFromPrivate[curve25519.VarTimeOperations](GetDeterministicTransactionPrivateKey(new(curve25519.Scalar), seed, prevId))
}

func (d *NilDerivationCache) GetCarrotCoinbaseEnote(a *address.PackedAddressWithSubaddress, seed types.Hash, blockIndex, amount uint64) *carrot.CoinbaseEnoteV1 {
	proposal := carrot.PaymentProposalV1[curve25519.VarTimeOperations]{
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
