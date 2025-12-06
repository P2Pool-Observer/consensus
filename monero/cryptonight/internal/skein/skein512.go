package skein

import "git.gammaspectra.live/P2Pool/consensus/v5/monero/cryptonight/internal/skein/threefish"

type HashFunc struct {
	hashsize      int
	hVal, hValCpy [9]uint64
	tweak         [3]uint64
	block         [BlockSize]byte
	off           int
	hasMsg        bool
}

func (s *HashFunc) BlockSize() int { return BlockSize }

func (s *HashFunc) Size() int { return s.hashsize }

func (s *HashFunc) Reset() {
	for i := range s.block {
		s.block[i] = 0
	}
	s.off = 0
	s.hasMsg = false

	s.hVal = s.hValCpy

	s.tweak[0] = 0
	s.tweak[1] = CfgMessage<<56 | FirstBlock
}

func (s *HashFunc) Write(p []byte) (n int, err error) {
	s.hasMsg = true

	n = len(p)
	var block [8]uint64

	dif := BlockSize - s.off
	if s.off > 0 && n > dif {
		s.off += copy(s.block[s.off:], p[:dif])
		p = p[dif:]
		if s.off == BlockSize && len(p) > 0 {
			bytesToBlock(&block, s.block[:])
			s.update(&block)
			s.off = 0
		}
	}

	if length := len(p); length > BlockSize {
		nn := length & (^(BlockSize - 1)) // length -= (length % BlockSize)
		if length == nn {
			nn -= BlockSize
		}
		for i := 0; i < len(p[:nn]); i += BlockSize {
			bytesToBlock(&block, p[i:])
			s.update(&block)
		}
		p = p[nn:]
	}

	if len(p) > 0 {
		s.off += copy(s.block[s.off:], p)
	}
	return
}

func (s *HashFunc) Sum(b []byte) []byte {
	s0 := *s // copy

	if s0.hasMsg {
		s0.finalizeHash()
	}

	var out [BlockSize]byte
	var ctr uint64
	for i := s0.hashsize; i > 0; i -= BlockSize {
		s0.output(&out, ctr)
		ctr++
		b = append(b, out[:]...)
	}
	return b[:s0.hashsize]
}

func (s *HashFunc) update(block *[8]uint64) {
	threefish.IncrementTweak(&(s.tweak), BlockSize)

	threefish.UBI512(block, &(s.hVal), &(s.tweak))

	s.tweak[1] &^= FirstBlock
}

func (s *HashFunc) output(dst *[BlockSize]byte, counter uint64) {
	var block [8]uint64
	block[0] = counter

	hVal := s.hVal
	var outTweak = [3]uint64{8, CfgOutput<<56 | FirstBlock | FinalBlock, 0}

	threefish.UBI512(&block, &hVal, &outTweak)
	block[0] ^= counter

	blockToBytes(dst[:], &block)
}

func (s *HashFunc) Init(hashsize int, conf *Config) {
	if hashsize < 1 {
		panic("skein: invalid hashsize for Skein-512")
	}

	s.hashsize = hashsize

	var key, pubKey, keyID, nonce, personal []byte
	if conf != nil {
		key = conf.Key
		pubKey = conf.PublicKey
		keyID = conf.KeyID
		nonce = conf.Nonce
		personal = conf.Personal
	}

	if len(key) > 0 {
		s.tweak[0] = 0
		s.tweak[1] = CfgKey<<56 | FirstBlock
		_, _ = s.Write(key)
		s.finalizeHash()
	}

	var cfg [32]byte
	schemaId := SchemaID
	cfg[0] = byte(schemaId)
	cfg[1] = byte(schemaId >> 8)
	cfg[2] = byte(schemaId >> 16)
	cfg[3] = byte(schemaId >> 24)
	cfg[4] = byte(schemaId >> 32)
	cfg[5] = byte(schemaId >> 40)
	cfg[6] = byte(schemaId >> 48)
	cfg[7] = byte(schemaId >> 56)

	bits := uint64(s.hashsize * 8)
	cfg[8] = byte(bits)
	cfg[9] = byte(bits >> 8)
	cfg[10] = byte(bits >> 16)
	cfg[11] = byte(bits >> 24)
	cfg[12] = byte(bits >> 32)
	cfg[13] = byte(bits >> 40)
	cfg[14] = byte(bits >> 48)
	cfg[15] = byte(bits >> 56)

	s.tweak[0] = 0
	s.tweak[1] = CfgConfig<<56 | FirstBlock
	_, _ = s.Write(cfg[:])
	s.finalizeHash()

	if len(personal) > 0 {
		s.tweak[0] = 0
		s.tweak[1] = CfgPersonal<<56 | FirstBlock
		_, _ = s.Write(personal)
		s.finalizeHash()
	}

	if len(pubKey) > 0 {
		s.tweak[0] = 0
		s.tweak[1] = CfgPublicKey<<56 | FirstBlock
		_, _ = s.Write(pubKey)
		s.finalizeHash()
	}

	if len(keyID) > 0 {
		s.tweak[0] = 0
		s.tweak[1] = CfgKeyID<<56 | FirstBlock
		_, _ = s.Write(keyID)
		s.finalizeHash()
	}

	if len(nonce) > 0 {
		s.tweak[0] = 0
		s.tweak[1] = CfgNonce<<56 | FirstBlock
		_, _ = s.Write(nonce)
		s.finalizeHash()
	}

	s.hValCpy = s.hVal

	s.Reset()
}

func (s *HashFunc) finalizeHash() {
	threefish.IncrementTweak(&(s.tweak), uint64(s.off))
	s.tweak[1] |= FinalBlock

	for i := s.off; i < len(s.block); i++ {
		s.block[i] = 0
	}
	s.off = 0

	var block [8]uint64
	bytesToBlock(&block, s.block[:])

	threefish.UBI512(&block, &(s.hVal), &(s.tweak))
}

func bytesToBlock(block *[8]uint64, src []byte) {
	for i := range block {
		j := i * 8
		block[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 |
			uint64(src[j+3])<<24 | uint64(src[j+4])<<32 | uint64(src[j+5])<<40 |
			uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}
}

func blockToBytes(dst []byte, block *[8]uint64) {
	i := 0
	for _, v := range block {
		dst[i] = byte(v)
		dst[i+1] = byte(v >> 8)
		dst[i+2] = byte(v >> 16)
		dst[i+3] = byte(v >> 24)
		dst[i+4] = byte(v >> 32)
		dst[i+5] = byte(v >> 40)
		dst[i+6] = byte(v >> 48)
		dst[i+7] = byte(v >> 56)
		i += 8
	}
}
