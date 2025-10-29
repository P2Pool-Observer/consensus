package address

var ZeroSubaddressIndex = SubaddressIndex{
	Account: 0,
	Offset:  0,
}

type SubaddressIndex struct {
	// Account index, also called major_index
	Account uint32
	// Offset within the Account, also called minor_index
	Offset uint32
}

func (index SubaddressIndex) IsZero() bool {
	return index == ZeroSubaddressIndex
}
