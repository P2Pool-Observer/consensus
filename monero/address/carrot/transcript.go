package carrot

func FixedTranscript(domainSeparator []byte, args ...[]byte) []byte {
	//todo: proper size
	result := make([]byte, 0, 1+len(domainSeparator)+len(args)*32)

	result = append(result, uint8(len(domainSeparator)))
	result = append(result, domainSeparator...)
	for _, arg := range args {
		result = append(result, arg...)
	}
	return result
}
