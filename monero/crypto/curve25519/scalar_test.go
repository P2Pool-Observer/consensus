package curve25519

import (
	"testing"

	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

func TestUnreducedScalarRecover(t *testing.T) {
	// https://www.moneroinflation.com/static/data_py/report_scalars_df.pdf, Table 4
	testUnreducedScalarRecover(t,
		"cb2be144948166d0a9edb831ea586da0c376efa217871505ad77f6ff80f203f8",
		"b8ffd6a1aee47828808ab0d4c8524cb5c376efa217871505ad77f6ff80f20308",
	)
	testUnreducedScalarRecover(t,
		"343d3df8a1051c15a400649c423dc4ed58bef49c50caef6ca4a618b80dee22f4",
		"21113355bc682e6d7a9d5b3f2137a30259bef49c50caef6ca4a618b80dee2204",
	)
	testUnreducedScalarRecover(t,
		"c14f75d612800ca2c1dcfa387a42c9cc086c005bc94b18d204dd61342418eba7",
		"4f473804b1d27ab2c789c80ab21d034a096c005bc94b18d204dd61342418eb07",
	)
	testUnreducedScalarRecover(t,
		"000102030405060708090a0b0c0d0e0f826c4f6e2329a31bc5bc320af0b2bcbb",
		"a124cfd387f461bf3719e03965ee6877826c4f6e2329a31bc5bc320af0b2bc0b",
	)

}

func testUnreducedScalarRecover(t *testing.T, storedHex, recoveredHex string) {
	stored := types.MustBytes32FromString[UnreducedScalar](storedHex)
	recovered := types.MustBytes32FromString[PrivateKeyBytes](recoveredHex)
	if stored.VarTimeScalar(new(Scalar)).Equal(recovered.Scalar()) == 0 {
		t.Fatalf("unreduced scalar did not recover")
	}
}
