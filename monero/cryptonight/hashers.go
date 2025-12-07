package cryptonight

import (
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight/internal/blake256"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight/internal/groestl"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight/internal/jh"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight/internal/skein"
)

func finalHash(i uint8, data []byte, out []byte) {
	switch i & 0x03 {
	case 0:
		var digest blake256.Digest
		digest.HashSize = blake256.Size * 8
		digest.Reset()
		_, _ = digest.Write(data)
		digest.Sum(out[:0])
		return
	case 1:
		var digest groestl.Digest
		digest.HashBitLen = 256
		digest.Reset()
		_, _ = digest.Write(data)
		digest.Sum(out[:0])
		return
	case 2:
		var digest jh.State
		digest.HashBitLen = 256
		digest.X = jh.JH256H0
		_, _ = digest.Write(data)
		digest.Sum(out[:0])
		return
	case 3:
		skein.Sum256((*[32]byte)(out), data, nil)
		return
	}
	panic("unreachable")
}
