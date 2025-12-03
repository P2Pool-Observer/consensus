package original

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/bulletproofs"
)

type BatchVerifier[T curve25519.PointOperations] bulletproofs.InternalBatchVerifier[T]

func (bv *BatchVerifier[T]) Verify() bool {
	return (*bulletproofs.InternalBatchVerifier[T])(bv).Verify(curve25519.FromPoint[T](crypto.GeneratorG.Point), curve25519.FromPoint[T](crypto.GeneratorH.Point), bulletproofs.Generator)
}
