package jh

func SWAP1(x *uint64) {
	*x = (((*x) & 0x5555555555555555) << 1) | (((*x) & 0xaaaaaaaaaaaaaaaa) >> 1)
}

func SWAP2(x *uint64) {
	*x = (((*x) & 0x3333333333333333) << 2) | (((*x) & 0xcccccccccccccccc) >> 2)
}
func SWAP4(x *uint64) {
	*x = (((*x) & 0x0f0f0f0f0f0f0f0f) << 4) | (((*x) & 0xf0f0f0f0f0f0f0f0) >> 4)
}
func SWAP8(x *uint64) {
	*x = (((*x) & 0x00ff00ff00ff00ff) << 8) | (((*x) & 0xff00ff00ff00ff00) >> 8)
}
func SWAP16(x *uint64) {
	*x = (((*x) & 0x0000ffff0000ffff) << 16) | (((*x) & 0xffff0000ffff0000) >> 16)
}
func SWAP32(x *uint64) {
	*x = ((*x) << 32) | ((*x) >> 32)
}

func SS(m0, m1, m2, m3, m4, m5, m6, m7 *uint64, cc0, cc1 uint64) {
	*m3 = ^*m3
	*m7 = ^*m7
	*m0 ^= ((^*m2) & (cc0))
	*m4 ^= ((^*m6) & (cc1))
	temp0 := (cc0) ^ (*m0 & *m1)
	temp1 := (cc1) ^ (*m4 & *m5)
	*m0 ^= (*m2 & *m3)
	*m4 ^= (*m6 & *m7)
	*m3 ^= ((^*m1) & *m2)
	*m7 ^= ((^*m5) & *m6)
	*m1 ^= (*m0 & *m2)
	*m5 ^= (*m4 & *m6)
	*m2 ^= (*m0 & (^*m3))
	*m6 ^= (*m4 & (^*m7))
	*m0 ^= (*m1 | *m3)
	*m4 ^= (*m5 | *m7)
	*m3 ^= (*m1 & *m2)
	*m7 ^= (*m5 & *m6)
	*m1 ^= (temp0 & *m0)
	*m5 ^= (temp1 & *m4)
	*m2 ^= temp0
	*m6 ^= temp1
}

func L(m0, m1, m2, m3, m4, m5, m6, m7 *uint64) {
	*m4 ^= *m1
	*m5 ^= *m2
	*m6 ^= *m0 ^ *m3
	*m7 ^= *m0
	*m0 ^= *m5
	*m1 ^= *m6
	*m2 ^= *m4 ^ *m7
	*m3 ^= *m4
}
