package groestl

import (
	"encoding/binary"
	"hash"
)

// Digest is being used during algorithm execution. Provides easy
// access to all information about current state of data processing.
type Digest struct {
	HashBitLen int
	chaining   [16]uint64
	blocks     uint64
	buf        [128]byte
	nbuf       int
	columns    int
	rounds     int
}

// Reset Equivalent to Init from reference implementation. Initiates values
// for Digest struct, therefore determines exact type of groestl algorithm.
func (d *Digest) Reset() {
	for i := range d.chaining {
		d.chaining[i] = 0
	}

	d.blocks = 0
	d.nbuf = 0

	if d.HashBitLen <= 256 {
		d.columns = 8
		d.rounds = 10
	} else {
		d.columns = 16
		d.rounds = 14
	}

	d.chaining[d.columns-1] = uint64(d.HashBitLen)
}

func New224() *Digest {
	d := new(Digest)
	d.HashBitLen = 224
	d.Reset()
	return d
}

func New256() *Digest {
	d := new(Digest)
	d.HashBitLen = 256
	d.Reset()
	return d
}

func New384() *Digest {
	d := new(Digest)
	d.HashBitLen = 384
	d.Reset()
	return d
}

func New512() *Digest {
	d := new(Digest)
	d.HashBitLen = 512
	d.Reset()
	return d
}

func New() hash.Hash {
	return New256()
}

func (d *Digest) Size() int {
	return d.HashBitLen
}

func (d *Digest) BlockSize() int {
	if d.HashBitLen <= 256 {
		return 64
	} else {
		return 128
	}
}

func (d *Digest) Write(p []byte) (n int, err error) {
	n = len(p)
	if d.nbuf > 0 {
		nn := copy(d.buf[d.nbuf:], p)
		d.nbuf += nn
		if d.nbuf == d.BlockSize() {
			err = d.transform(d.buf[:d.BlockSize()])
			if err != nil {
				panic(err)
			}
			d.nbuf = 0
		}
		p = p[nn:]
	}
	if len(p) >= d.BlockSize() {
		nn := len(p) &^ (d.BlockSize() - 1)
		err = d.transform(p[:nn])
		if err != nil {
			panic(err)
		}
		p = p[nn:]
	}
	if len(p) > 0 {
		d.nbuf = copy(d.buf[:], p)
	}
	return
}

func (d *Digest) Sum(in []byte) []byte {
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash...)
}

func (d *Digest) checkSum() []byte {
	bs := d.BlockSize()
	var tmp [128]byte
	tmp[0] = 0x80

	if d.nbuf > (bs - 8) {
		_, _ = d.Write(tmp[:(bs - d.nbuf)])
		_, _ = d.Write(tmp[8:bs])
	} else {
		_, _ = d.Write(tmp[0:(bs - d.nbuf - 8)])
	}

	binary.BigEndian.PutUint64(tmp[:], d.blocks+1)
	_, _ = d.Write(tmp[:8])

	if d.nbuf != 0 {
		panic("padding failed")
	}

	d.finalTransform()

	// store chaining in output byteslice
	hash := make([]byte, d.columns*4)
	for i := range d.columns / 2 {
		binary.BigEndian.PutUint64(hash[(i*8):(i+1)*8], d.chaining[i+(d.columns/2)])
	}
	hash = hash[(len(hash) - d.HashBitLen/8):]
	return hash
}

func Sum224(data []byte) []byte {
	d := New224()
	_, _ = d.Write(data)
	return d.checkSum()
}

func Sum256(data []byte) []byte {
	d := New256()
	_, _ = d.Write(data)
	return d.checkSum()
}

func Sum384(data []byte) []byte {
	d := New384()
	_, _ = d.Write(data)
	return d.checkSum()
}

func Sum512(data []byte) []byte {
	d := New512()
	_, _ = d.Write(data)
	return d.checkSum()
}
