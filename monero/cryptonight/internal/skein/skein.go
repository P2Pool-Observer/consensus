package skein

import "hash"

// Sum256 computes the 256 bit Skein512 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum256(out *[32]byte, msg, key []byte) {
	var out512 [64]byte
	var s HashFunc

	if len(key) > 0 {
		s.Init(32, &Config{Key: key})
	} else {
		s.hVal = iv256
		s.hValCpy = iv256
		s.hashsize = 32
		s.tweak[0] = 0
		s.tweak[1] = CfgMessage<<56 | FirstBlock
	}

	_, _ = s.Write(msg)

	s.finalizeHash()
	s.output(&out512, 0)

	copy(out[:], out512[:32])
}

// Sum returns the Skein256 checksum with the given hash size of msg using the (optional)
// conf for configuration. The hashsize must be > 0.
func Sum(msg []byte, hashsize int, conf *Config) []byte {
	s := New(hashsize, conf)
	s.Write(msg)
	return s.Sum(nil)
}

// New512 returns a hash.Hash computing the Skein256 512 bit checksum.
// The key is optional and turns the hash into a MAC.
func New512(key []byte) hash.Hash {
	s := new(HashFunc)

	s.Init(64, &Config{Key: key})

	return s
}

// New256 returns a hash.Hash computing the Skein256 256 bit checksum.
// The key is optional and turns the hash into a MAC.
func New256(key []byte) hash.Hash {
	s := new(HashFunc)

	s.Init(32, &Config{Key: key})

	return s
}

// New returns a hash.Hash computing the Skein256 checksum with the given hash size.
// The conf is optional and configurates the hash.Hash
func New(hashsize int, conf *Config) hash.Hash {
	s := new(HashFunc)
	s.Init(hashsize, conf)
	return s
}
