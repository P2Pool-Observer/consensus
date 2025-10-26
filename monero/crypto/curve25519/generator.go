package curve25519

import "git.gammaspectra.live/P2Pool/edwards25519"

type Generator struct {
	// Point The point used as Generator
	Point *edwards25519.Point
	// Table Precomputed table of Point to be used in VarTime Precomputed scalar point multiplication
	Table *edwards25519.PrecomputedTable
}

func NewGenerator(point *edwards25519.Point) *Generator {
	return &Generator{
		Point: point,
		Table: edwards25519.PointTablePrecompute(point),
	}
}
