package utils

import (
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	_ "unsafe"
)

// These functions allow defeat of the escape analysis to prevent heap allocations.
// It is the caller responsibility to ensure this is safe

func _read(reader io.Reader, buf []byte) (n int, err error) {
	return reader.Read(buf)
}
func _readByte(reader io.ByteReader) (byte, error) {
	return reader.ReadByte()
}

func _binaryReadNoEscape(r io.Reader, order binary.ByteOrder, data any) error {
	return binary.Read(r, order, data)
}

func _write(writer io.Writer, buf []byte) (n int, err error) {
	return writer.Write(buf)
}

func _sum(hasher hash.Hash, buf []byte) []byte {
	return hasher.Sum(buf)
}

func _reset(hasher hash.Hash) {
	hasher.Reset()
}

func _errorfNoEscape(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}
func _appendfNoEscape(b []byte, format string, a ...any) []byte {
	return fmt.Appendf(b, format, a...)
}
func _sprintfNoEscape(format string, a ...any) string {
	return fmt.Sprintf(format, a...)
}

//go:noescape
//go:linkname ReadNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._read
func ReadNoEscape(reader io.Reader, buf []byte) (n int, err error)

//go:noescape
//go:linkname ReadByteNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._readByte
func ReadByteNoEscape(reader io.ByteReader) (byte, error)

func ReadFullNoEscape(reader io.Reader, buf []byte) (n int, err error) {
	minRead := len(buf)
	if len(buf) < minRead {
		return 0, io.ErrShortBuffer
	}
	for n < minRead && err == nil {
		var nn int
		nn, err = ReadNoEscape(reader, buf[n:])
		n += nn
	}
	if n >= minRead {
		err = nil
	} else if n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

//go:noescape
//go:linkname BinaryReadNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._binaryReadNoEscape
func BinaryReadNoEscape(r io.Reader, order binary.ByteOrder, data any) error

//go:noescape
//go:linkname WriteNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._write
func WriteNoEscape(writer io.Writer, buf []byte) (n int, err error)

//go:noescape
//go:linkname SumNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._sum
func SumNoEscape(hasher hash.Hash, buf []byte) []byte

//go:noescape
//go:linkname ResetNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._reset
func ResetNoEscape(hasher hash.Hash)

//go:noescape
//go:linkname ErrorfNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._errorfNoEscape
func ErrorfNoEscape(format string, a ...any) error

//go:noescape
//go:linkname AppendfNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._appendfNoEscape
func AppendfNoEscape(b []byte, format string, a ...any) []byte

//go:noescape
//go:linkname SprintfNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._sprintfNoEscape
func SprintfNoEscape(format string, a ...any) string
