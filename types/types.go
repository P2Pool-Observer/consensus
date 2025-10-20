package types

import (
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"runtime"
	"unsafe"

	fasthex "github.com/tmthrgd/go-hex"
)

const HashSize = 32

type Hash [HashSize]byte

var ZeroHash Hash

func (h Hash) MarshalJSON() ([]byte, error) {
	var buf [HashSize*2 + 2]byte
	buf[0] = '"'
	buf[HashSize*2+1] = '"'
	fasthex.Encode(buf[1:], h[:])
	return buf[:], nil
}

func MustHashFromString(s string) Hash {
	if h, err := HashFromString(s); err != nil {
		panic(err)
	} else {
		return h
	}
}

func HashFromString(s string) (Hash, error) {
	var h Hash
	if buf, err := fasthex.DecodeString(s); err != nil {
		return h, err
	} else {
		if len(buf) != HashSize {
			return h, errors.New("wrong hash size")
		}
		copy(h[:], buf)
		return h, nil
	}
}

func HashFromBytes(buf []byte) (h Hash) {
	if len(buf) != HashSize {
		return
	}
	copy(h[:], buf)
	return
}

// Compare consensus way of comparison
func (h Hash) Compare(other Hash) int {
	//golang might free other otherwise
	defer runtime.KeepAlive(other)
	defer runtime.KeepAlive(h)
	a := unsafe.Slice((*uint64)(unsafe.Pointer(&h)), len(h)/int(unsafe.Sizeof(uint64(0))))
	b := unsafe.Slice((*uint64)(unsafe.Pointer(&other)), len(other)/int(unsafe.Sizeof(uint64(0))))

	if a[3] < b[3] {
		return -1
	}
	if a[3] > b[3] {
		return 1
	}

	if a[2] < b[2] {
		return -1
	}
	if a[2] > b[2] {
		return 1
	}

	if a[1] < b[1] {
		return -1
	}
	if a[1] > b[1] {
		return 1
	}

	if a[0] < b[0] {
		return -1
	}
	if a[0] > b[0] {
		return 1
	}

	return 0
}

func (h Hash) Slice() []byte {
	return h[:]
}

func (h Hash) String() string {
	return fasthex.EncodeToString(h[:])
}

func (h Hash) Uint64() uint64 {
	return binary.LittleEndian.Uint64(h[:])
}

func (h *Hash) Scan(src any) error {
	if src == nil {
		return nil
	} else if buf, ok := src.([]byte); ok {
		if len(buf) == 0 {
			return nil
		}
		if len(buf) != HashSize {
			return errors.New("invalid hash size")
		}
		copy((*h)[:], buf)

		return nil
	}
	return errors.New("invalid type")
}

func (h *Hash) Value() (driver.Value, error) {
	if *h == ZeroHash {
		return nil, nil
	}
	return (*h)[:], nil
}

func (h *Hash) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || len(b) == 2 {
		return nil
	}

	if len(b) != HashSize*2+2 {
		return errors.New("wrong hash size")
	}

	if _, err := fasthex.Decode(h[:], b[1:len(b)-1]); err != nil {
		return err
	} else {
		return nil
	}
}

type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	buf := make([]byte, len(b)*2+2)
	buf[0] = '"'
	buf[len(buf)-1] = '"'
	fasthex.Encode(buf[1:], b)
	return buf, nil
}

func (b Bytes) String() string {
	return fasthex.EncodeToString(b)
}

func (b *Bytes) UnmarshalJSON(buf []byte) error {
	if len(buf) < 2 || (len(buf)%2) != 0 || buf[0] != '"' || buf[len(buf)-1] != '"' {
		return errors.New("invalid bytes")
	}

	*b = make(Bytes, (len(buf)-2)/2)

	if _, err := fasthex.Decode(*b, buf[1:len(buf)-1]); err != nil {
		return err
	} else {
		return nil
	}
}

// FixedBytes Implements a fixed size array for encoding/decoding helper
// Add any desired size in this list
type FixedBytes[T ~[3]byte | ~[8]byte | ~[16]byte | ~[32]byte | ~[64]byte] struct {
	t T
}

func MakeFixed[T ~[3]byte | ~[8]byte | ~[16]byte | ~[32]byte | ~[64]byte](v T) FixedBytes[T] {
	return FixedBytes[T]{
		t: v,
	}
}

func (b FixedBytes[T]) MarshalJSON() ([]byte, error) {
	buf := make([]byte, len(b.t)*2+2)
	buf[0] = '"'
	buf[len(buf)-1] = '"'
	fasthex.Encode(buf[1:], b.Slice())
	return buf, nil
}

func (b *FixedBytes[T]) Slice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&b.t)), len(b.t))
}

func (b FixedBytes[T]) Value() T {
	return b.t
}

func (b FixedBytes[T]) String() string {
	return fasthex.EncodeToString(b.Slice())
}

func (b *FixedBytes[T]) UnmarshalJSON(buf []byte) error {
	if len(buf) < 2 || (len(buf)%2) != 0 || buf[0] != '"' || buf[len(buf)-1] != '"' {
		return errors.New("invalid bytes")
	}

	if (len(buf)-2)/2 != len(b.t) {
		return errors.New("wrong length")
	}

	if _, err := fasthex.Decode(b.Slice(), buf[1:len(buf)-1]); err != nil {
		return err
	} else {
		return nil
	}
}
