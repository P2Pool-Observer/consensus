package crypto

import (
	"git.gammaspectra.live/P2Pool/consensus/v4/types"
	"git.gammaspectra.live/P2Pool/edwards25519"
	"git.gammaspectra.live/P2Pool/sha3"
)

func Keccak256(data ...[]byte) (result types.Hash) {
	h := sha3.NewLegacyKeccak256()
	for _, b := range data {
		h.Write(b)
	}
	HashFastSum(h, result[:])

	return
}

func Keccak256Single(data []byte) (result types.Hash) {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	HashFastSum(h, result[:])

	return
}

func HashToScalar(data ...[]byte) *edwards25519.Scalar {
	h := PooledKeccak256(data...)

	c := GetEdwards25519Scalar()
	BytesToScalar32(h, c)

	return c
}

func HashToScalarNoAllocate(data ...[]byte) edwards25519.Scalar {
	h := Keccak256(data...)

	var c edwards25519.Scalar
	BytesToScalar32(h, &c)
	return c
}

func HashToScalarNoAllocateSingle(data []byte) edwards25519.Scalar {
	h := Keccak256Single(data)

	var c edwards25519.Scalar
	BytesToScalar32(h, &c)
	return c
}

// HashFastSum sha3.Sum clones the state by allocating memory. prevent that. b must be pre-allocated to the expected size, or larger
func HashFastSum(hash *sha3.HasherState, b []byte) []byte {
	_ = b[31] // bounds check hint to compiler; see golang.org/issue/14808
	_, _ = hash.Read(b[:types.HashSize])
	return b
}

/* TODO: wait for HashToPoint in edwards25519

// HashToPoint Equivalent of Monero's HashToEC
func HashToPointOld(publicKey PublicKey) *edwards25519.Point {

	p := moneroutil.Key(publicKey.AsBytes())
	var key moneroutil.Key

	result := new(moneroutil.ExtendedGroupElement)
	var p1 moneroutil.ProjectiveGroupElement
	var p2 moneroutil.CompletedGroupElement
	h := moneroutil.Key(Keccak256(p[:]))

	log.Printf("old %s", hex.EncodeToString(h[:]))

	p1.FromBytes(&h)

	p1.ToBytes(&key)
	log.Printf("old t %s", hex.EncodeToString(key[:]))

	moneroutil.GeMul8(&p2, &p1)
	p2.ToExtended(result)

	result.ToBytes(&key)
	log.Printf("old c %s", hex.EncodeToString(key[:]))
	out, _ := GetEdwards25519Point().SetBytes(key[:])
	return out
}

var cofactor = new(field.Element).Mult32(new(field.Element).One(), 8)

// HashToPoint Equivalent of Monero's HashToEC
func HashToPoint(publicKey PublicKey) *edwards25519.Point {
	//TODO: make this work with existing edwards25519 library
	h := Keccak256Single(publicKey.AsSlice())

	log.Printf("new %s", hex.EncodeToString(h[:]))

	e, err := new(field.Element).SetBytes(h[:])
	if err != nil {
		panic("hash to point failed")
	}
	log.Printf("new t %s", hex.EncodeToString(e.Bytes()))
	e.Multiply(cofactor, e)

	log.Printf("new c %s", hex.EncodeToString(e.Bytes()))
	p, _ := GetEdwards25519Point().SetBytes(e.Bytes())
	return p

	var p1 edwards25519.Point
	p1.MultByCofactor(&p1)
	return p
}

*/
