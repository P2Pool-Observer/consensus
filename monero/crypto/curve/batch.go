package curve

// BatchInvert Sets v to sum(inv(z...)), sets each z element to its inverse
// If any z element is zero, it is skipped
//
// Constant time proportional to length of z
func BatchInvert[F any, FE BasicField[F]](v *F, z ...*F) *F {
	var acc, tmp, tmp2, zero F
	FE(&zero).Zero()

	scratch := make([]F, 0, len(z))

	// Keep an accumulator of all of the previous products
	FE(&acc).One()

	// Pass through the input vector, recording the previous
	// products in the scratch space
	for _, p := range z {
		scratch = append(scratch, acc)
		FE(&acc).Select(&acc, FE(&tmp).Multiply(&acc, p), FE(p).Equal(&zero))
	}

	FE(&acc).Invert(&acc)
	// sum(inv(z...))
	FE(v).Set(&acc)

	for i := len(z) - 1; i >= 0; i-- {
		p := z[i]
		skip := FE(p).Equal(&zero)

		FE(&tmp2).Multiply(&scratch[i], &acc)

		FE(&acc).Select(&acc, FE(&tmp).Multiply(&acc, p), skip)
		FE(p).Select(p, &tmp2, skip)
	}

	return v
}
