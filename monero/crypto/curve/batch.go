package curve

// BatchInvert Sets v to sum(inv(inputs...)), sets each input element to its inverse
// If any input element is zero, it is unchanged
//
// Constant time proportional to length of inputs
func BatchInvert[F any, FE BasicField[F]](v *F, inputs ...*F) *F {
	// Montgomery’s Trick and Fast Implementation of Masked AES
	// Genelle, Prouff and Quisquater
	// Section 3.2

	var acc, product, tmp, zero F
	FE(&zero).Zero()

	scratch := make([]F, 0, len(inputs))

	// Keep an accumulator of all of the previous products
	FE(&acc).One()

	// Pass through the input vector, recording the previous
	// products in the scratch space
	for _, p := range inputs {
		scratch = append(scratch, acc)
		// acc <- acc * input, but skipping zeros (constant-time)
		FE(&acc).Select(&acc, FE(&product).Multiply(&acc, p), FE(p).Equal(&zero))
	}

	// acc is nonzero because we skipped zeros in inputs

	// Compute the inverse of all products
	FE(&acc).Invert(&acc)
	// sum(inv(inputs...))
	FE(v).Set(&acc)

	// Pass through the vector backwards to compute the inverses in place
	for i := len(inputs) - 1; i >= 0; i-- {
		p := inputs[i]

		// input <- acc * scratch, then acc <- tmp
		FE(&tmp).Multiply(&scratch[i], &acc)

		// Again, we skip zeros in a constant-time way
		skip := FE(p).Equal(&zero)

		FE(&acc).Select(&acc, FE(&product).Multiply(&acc, p), skip)
		FE(p).Select(p, &tmp, skip)
	}

	return v
}
