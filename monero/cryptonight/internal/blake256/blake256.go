// Written in 2011-2012 by Dmitry Chestnykh.
//
// To the extent possible under law, the author have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// http://creativecommons.org/publicdomain/zero/1.0/

// Package blake256 implements BLAKE-256 and BLAKE-224 hash functions (SHA-3
// candidate).
package blake256

// BlockSize The block size of the hash algorithm in bytes.
const BlockSize = 64

// Size The size of BLAKE-256 hash in bytes.
const Size = 32

// Size224 The size of BLAKE-224 hash in bytes.
const Size224 = 28

type Digest struct {
	HashSize int             // hash output size in bits (224 or 256)
	h        [8]uint32       // current chain value
	s        [4]uint32       // salt (zero by default)
	t        uint64          // message bits counter
	nullt    bool            // special case for finalization: skip counter
	x        [BlockSize]byte // buffer for data not yet compressed
	nx       int             // number of bytes in buffer
}

var (
	// Initialization values.
	iv256 = [8]uint32{
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
		0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}

	iv224 = [8]uint32{
		0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
		0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4}

	pad = [64]byte{0x80}
)

// Reset resets the state of Digest. It leaves salt intact.
func (d *Digest) Reset() {
	if d.HashSize == 224 {
		d.h = iv224
	} else {
		d.h = iv256
	}
	d.t = 0
	d.nx = 0
	d.nullt = false
}

func (d *Digest) Size() int { return d.HashSize >> 3 }

func (d *Digest) BlockSize() int { return BlockSize }

func (d *Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := min(len(p), BlockSize-d.nx)
		d.nx += copy(d.x[d.nx:], p)
		if d.nx == BlockSize {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

// Sum returns the calculated checksum.
func (d *Digest) Sum(in []byte) []byte {
	sum := d.checkSum()
	if d.Size() == Size224 {
		return append(in, sum[:Size224]...)
	}
	return append(in, sum[:]...)
}

func (d *Digest) checkSum() [Size]byte {
	nx := uint64(d.nx)
	l := d.t + nx<<3
	var size [8]byte
	size[0] = byte(l >> 56)
	size[1] = byte(l >> 48)
	size[2] = byte(l >> 40)
	size[3] = byte(l >> 32)
	size[4] = byte(l >> 24)
	size[5] = byte(l >> 16)
	size[6] = byte(l >> 8)
	size[7] = byte(l)

	if nx == 55 {
		// One padding byte.
		d.t -= 8
		if d.HashSize == 224 {
			_, _ = d.Write([]byte{0x80})
		} else {
			_, _ = d.Write([]byte{0x81})
		}
	} else {
		if nx < 55 {
			// Enough space to fill the block.
			if nx == 0 {
				d.nullt = true
			}
			d.t -= 440 - nx<<3
			_, _ = d.Write(pad[0 : 55-nx])
		} else {
			// Need 2 compressions.
			d.t -= 512 - nx<<3
			_, _ = d.Write(pad[0 : 64-nx])
			d.t -= 440
			_, _ = d.Write(pad[1:56])
			d.nullt = true
		}
		if d.HashSize == 224 {
			_, _ = d.Write([]byte{0x00})
		} else {
			_, _ = d.Write([]byte{0x01})
		}
		d.t -= 8
	}
	d.t -= 64
	_, _ = d.Write(size[:])

	var out [Size]byte
	j := 0
	for _, s := range d.h[:d.HashSize>>5] {
		out[j+0] = byte(s >> 24)
		out[j+1] = byte(s >> 16)
		out[j+2] = byte(s >> 8)
		out[j+3] = byte(s >> 0)
		j += 4
	}
	return out
}
