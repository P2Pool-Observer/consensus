package groestl

import (
	"encoding/binary"
)

// Digest is being used during algorithm execution. Provides easy
// access to all information about current state of data processing.
type Digest struct {
	HashBitLen int
	chaining   [16]uint64
	blocks     uint64
	buf        [128]byte
	nbuf       int
}

const columns = 8
const rounds = 10

// Reset Equivalent to Init from reference implementation. Initiates values
// for Digest struct, therefore determines exact type of groestl algorithm.
func (d *Digest) Reset() {
	for i := range d.chaining {
		d.chaining[i] = 0
	}

	d.blocks = 0
	d.nbuf = 0

	if d.HashBitLen != 256 {
		panic("unsupported")
	}

	d.chaining[columns-1] = uint64(d.HashBitLen)
}

func New256() *Digest {
	d := new(Digest)
	d.HashBitLen = 256
	d.Reset()
	return d
}

func (d *Digest) Size() int {
	return d.HashBitLen
}

const blockSize = 64

func (d *Digest) BlockSize() int {
	return blockSize
}

func (d *Digest) Write(p []byte) (n int, err error) {
	n = len(p)
	if d.nbuf > 0 {
		nn := copy(d.buf[d.nbuf:], p)
		d.nbuf += nn
		if d.nbuf == blockSize {
			err = d.transform(d.buf[:blockSize])
			if err != nil {
				panic(err)
			}
			d.nbuf = 0
		}
		p = p[nn:]
	}
	if len(p) >= blockSize {
		nn := len(p) &^ (blockSize - 1)
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
	return d.checkSum(in)
}

func (d *Digest) checkSum(out []byte) []byte {
	var tmp [128]byte
	tmp[0] = 0x80

	if d.nbuf > (blockSize - 8) {
		_, _ = d.Write(tmp[:(blockSize - d.nbuf)])
		_, _ = d.Write(tmp[8:blockSize])
	} else {
		_, _ = d.Write(tmp[0:(blockSize - d.nbuf - 8)])
	}

	binary.BigEndian.PutUint64(tmp[:], d.blocks+1)
	_, _ = d.Write(tmp[:8])

	if d.nbuf != 0 {
		panic("padding failed")
	}

	d.finalTransform()

	// store chaining in output byteslice
	var hash [columns * 4]byte
	for i := range columns / 2 {
		binary.BigEndian.PutUint64(hash[(i*8):(i+1)*8], d.chaining[i+(columns/2)])
	}
	out = append(out, hash[:]...)
	return out
}

func Sum256(data []byte) []byte {
	d := New256()
	_, _ = d.Write(data)
	return d.checkSum(nil)
}
