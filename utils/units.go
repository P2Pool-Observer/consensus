package utils

func SiUnits(number float64, decimals int) string {
	if number >= 1000000000000 {
		return SprintfNoEscape("%.*f T", decimals, number/1000000000000)
	} else if number >= 1000000000 {
		return SprintfNoEscape("%.*f G", decimals, number/1000000000)
	} else if number >= 1000000 {
		return SprintfNoEscape("%.*f M", decimals, number/1000000)
	} else if number >= 1000 {
		return SprintfNoEscape("%.*f K", decimals, number/1000)
	}

	return SprintfNoEscape("%.*f ", decimals, number)
}

func XMRUnits(v uint64) string {
	const denomination = 1000000000000
	return SprintfNoEscape("%d.%012d", v/denomination, v%denomination)
}
