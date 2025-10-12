package utils

import (
	"hash"
	"io"

	_ "unsafe"
)

// These functions allow defeat of the escape analysis to prevent heap allocations.
// It is the caller responsibility to ensure this is safe

func _read(reader io.Reader, buf []byte) (n int, err error) {
	return reader.Read(buf)
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

//go:noescape
//go:linkname ReadNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._read
func ReadNoEscape(reader io.Reader, buf []byte) (n int, err error)

//go:noescape
//go:linkname WriteNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._write
func WriteNoEscape(writer io.Writer, buf []byte) (n int, err error)

//go:noescape
//go:linkname SumNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._sum
func SumNoEscape(hasher hash.Hash, buf []byte) []byte

//go:noescape
//go:linkname ResetNoEscape git.gammaspectra.live/P2Pool/consensus/v5/utils._reset
func ResetNoEscape(hasher hash.Hash)
