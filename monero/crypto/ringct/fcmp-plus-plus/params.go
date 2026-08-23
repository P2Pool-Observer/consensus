package fcmp_plus_plus

import (
	"sync"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/curve25519"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/helioselene"
	ec_gadgets "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/fcmp-plus-plus/ec-gadgets"
	gb "git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto/ringct/generalized-bulletproofs"
)

type Curves[
	POC any, PC1 any, PC2 any,
	FC1 any, FC2 any,
] struct {
	OC           curve.Ciphersuite[POC, FC1]
	OCParameters ec_gadgets.Parameters

	C1           curve.Ciphersuite[PC1, FC2]
	C1Parameters ec_gadgets.Parameters

	C2           curve.Ciphersuite[PC2, FC1]
	C2Parameters ec_gadgets.Parameters
}

var MoneroCurves = NewCurves[curve25519.Ciphersuite, helioselene.SeleneCiphersuite, helioselene.HeliosCiphersuite]()

func NewCurves[
	OC curve.Ciphersuite[POC, FC1], C1 curve.Ciphersuite[PC1, FC2], C2 curve.Ciphersuite[PC2, FC1],
	POC any, PC1 any, PC2 any,
	FC1 any, FC2 any,
]() Curves[POC, PC1, PC2, FC1, FC2] {
	var oc OC
	var c1 C1
	var c2 C2
	return Curves[POC, PC1, PC2, FC1, FC2]{
		OC:           oc,
		OCParameters: ec_gadgets.NewParameters(oc.ScalarBits()),
		C1:           c1,
		C1Parameters: ec_gadgets.NewParameters(c1.ScalarBits()),
		C2:           c2,
		C2Parameters: ec_gadgets.NewParameters(c2.ScalarBits()),
	}
}

type Params[
	POC any, PC1 any, PC2 any,
	FC1 any, FC2 any,
] struct {
	Curve1Generators gb.Generators[PC1]
	Curve2Generators gb.Generators[PC2]

	Curve1HashInit PC1
	Curve2HashInit PC2

	GTable  ec_gadgets.GeneratorTable[FC1]
	TTable  ec_gadgets.GeneratorTable[FC1]
	UTable  ec_gadgets.GeneratorTable[FC1]
	VTable  ec_gadgets.GeneratorTable[FC1]
	H1Table ec_gadgets.GeneratorTable[FC2]
	H2Table ec_gadgets.GeneratorTable[FC1]
}

func (curves Curves[POC, PC1, PC2, FC1, FC2]) Params[FC1E curve.Field[FC1], FC2E curve.Field[FC2]](
	curve1Generators *gb.Generators[PC1],
	curve2Generators *gb.Generators[PC2],
	curve1HashInit *PC1,
	curve2HashInit *PC2,
	G, T, U, V *POC,
) *Params[POC, PC1, PC2, FC1, FC2] {
	ocCurveSpec := ec_gadgets.CurveSpec[FC1]{A: *curves.OC.A(), B: *curves.OC.B()}

	gx, gy, err := curves.OC.XY(G)
	if err != nil {
		panic(err)
	}
	GTable := ec_gadgets.NewGeneratorTable[FC1, FC1E](curves.OCParameters.ScalarBits, &ocCurveSpec, &gx, &gy)

	tx, ty, err := curves.OC.XY(T)
	if err != nil {
		panic(err)
	}
	TTable := ec_gadgets.NewGeneratorTable[FC1, FC1E](curves.OCParameters.ScalarBits, &ocCurveSpec, &tx, &ty)

	ux, uy, err := curves.OC.XY(U)
	if err != nil {
		panic(err)
	}
	UTable := ec_gadgets.NewGeneratorTable[FC1, FC1E](curves.OCParameters.ScalarBits, &ocCurveSpec, &ux, &uy)

	vx, vy, err := curves.OC.XY(V)
	if err != nil {
		panic(err)
	}
	VTable := ec_gadgets.NewGeneratorTable[FC1, FC1E](curves.OCParameters.ScalarBits, &ocCurveSpec, &vx, &vy)

	c1CurveSpec := ec_gadgets.CurveSpec[FC2]{A: *curves.C1.A(), B: *curves.C1.B()}
	h1x, h1y, err := curves.C1.XY(&curve1Generators.H)
	if err != nil {
		panic(err)
	}
	H1Table := ec_gadgets.NewGeneratorTable[FC2, FC2E](curves.C1Parameters.ScalarBits, &c1CurveSpec, &h1x, &h1y)

	c2CurveSpec := ec_gadgets.CurveSpec[FC1]{A: *curves.C2.A(), B: *curves.C2.B()}
	h2x, h2y, err := curves.C2.XY(&curve2Generators.H)
	if err != nil {
		panic(err)
	}
	H2Table := ec_gadgets.NewGeneratorTable[FC1, FC1E](curves.C2Parameters.ScalarBits, &c2CurveSpec, &h2x, &h2y)

	return &Params[POC, PC1, PC2, FC1, FC2]{
		Curve1Generators: *curve1Generators,
		Curve2Generators: *curve2Generators,
		Curve1HashInit:   *curve1HashInit,
		Curve2HashInit:   *curve2HashInit,

		GTable:  GTable,
		TTable:  TTable,
		UTable:  UTable,
		VTable:  VTable,
		H1Table: H1Table,
		H2Table: H2Table,
	}
}

type FCMPParamsType = Params[
	curve25519.Point, helioselene.SelenePoint, helioselene.HeliosPoint,
	helioselene.HeliosField, helioselene.SeleneField,
]

var FCMPParams = sync.OnceValue(func() *FCMPParamsType {
	return MoneroCurves.Params(
		SeleneGenerators(),
		HeliosGenerators(),
		// Hash init generators
		SeleneHashInit,
		HeliosHashInit,
		// G, T, U, V
		curve25519.NewGeneratorPoint(),
		crypto.GeneratorT.Point,
		crypto.GeneratorU.Point,
		crypto.GeneratorV.Point,
	)
})
