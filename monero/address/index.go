package address

import "math"

var ZeroSubaddressIndex = SubaddressIndex{
	Account: 0,
	Offset:  0,
}

var UnknownSubaddressIndex = SubaddressIndex{
	Account: math.MaxUint32,
	Offset:  math.MaxUint32,
}

type SubaddressIndex struct {
	// Account index, also called major_index
	Account uint32
	// Offset within the Account, also called minor_index
	Offset uint32
}

func (index SubaddressIndex) IsUnknown() bool {
	return index == UnknownSubaddressIndex
}

func (index SubaddressIndex) IsZero() bool {
	return index == ZeroSubaddressIndex
}
