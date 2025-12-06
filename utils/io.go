package utils

import (
	"io"
	"math"
	"runtime"
	"slices"
	"unsafe"
)

// ReadFullProgressive Reads into buf up to size bytes by doubling size each time
func ReadFullProgressive[T ~[]byte](r io.Reader, dst *T, size int) (n int, err error) {
	if size < 0 {
		return 0, io.EOF
	}

	buf := *dst

	var offset int

	// reserve some, start with 64 KiB
	buf = slices.Grow(buf[:0], min(math.MaxUint16+1, size))
	buf = buf[:min(math.MaxUint16+1, size)]

	// special reader to grow extra over time
	for {
		// only read last part past read offset
		if n, err = ReadFullNoEscape(r, buf[offset:]); err != nil {
			return offset + n, err
		}
		offset += n

		if offset >= size || n == 0 {
			break
		}

		// double size or just remainder
		buf = slices.Grow(buf[:0], min(offset*2, size))
		buf = buf[:min(offset*2, size)]
	}
	*dst = buf
	return offset, nil
}

type Serializable interface {
	AppendBinary(preAllocatedBuf []byte) (data []byte, err error)
	FromReader(reader ReaderAndByteReader) (err error)
	BufferLength() (n int)
}

// ReadLittleEndianInteger Reads a defined Integer type that has a defined size. Does not support reading int/uint types.
func ReadLittleEndianInteger[T ~uint8 | ~int8 | ~uint16 | ~int16 | ~uint32 | ~int32 | ~uint64 | ~int64](r io.Reader, x *T) (err error) {
	var zero T
	// #nosec G103 -- verified using unsafe.Sizeof
	buf := unsafe.Slice((*byte)(unsafe.Pointer(x)), unsafe.Sizeof(zero))
	_, err = ReadFullNoEscape(r, buf)
	runtime.KeepAlive(x)
	return err
}
