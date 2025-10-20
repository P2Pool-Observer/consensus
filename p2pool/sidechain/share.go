package sidechain

import (
	"slices"
	"sync"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/crypto"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type Shares []*Share

func (s Shares) Index(addr address.PackedAddressWithSubaddress) int {
	return slices.IndexFunc(s, func(share *Share) bool {
		return share.Address == addr
	})
}

func fastShareCompare(a *Share, b *Share) int {
	// Fast tests first. Skips further checks
	if diff := int(a.Address.SpendPublicKey()[crypto.PublicKeySize-1]) - int(b.Address.SpendPublicKey()[crypto.PublicKeySize-1]); diff != 0 {
		return diff
	}
	if a.Address == b.Address {
		return 0
	}

	return a.Address.ComparePacked(&b.Address)
}

// Sort Consensus way of sorting Shares
func (s Shares) Sort() {
	slices.SortFunc(s, fastShareCompare)
}

func (s Shares) Clone() (o Shares) {
	o = make(Shares, len(s))
	preAllocatedStructs := make([]Share, len(s))
	for i := range s {
		o[i] = &preAllocatedStructs[i]
		o[i].Address = s[i].Address
		o[i].Weight = s[i].Weight
	}
	return o
}

// Compact Merges duplicate Share entries based on Address
// len(s) must be greater than 0
func (s Shares) Compact() Shares {
	if len(s) == 0 {
		return s
	}

	// Sort shares based on address
	s.Sort()

	index := 0

	for _, share := range s[1:] {
		if s[index].Address == share.Address {
			s[index].Weight = s[index].Weight.Add(share.Weight)
		} else {
			index++
			s[index].Address = share.Address
			s[index].Weight = share.Weight
		}
	}

	return s[:index+1]
}

type PreAllocatedSharesPool struct {
	pool sync.Pool
}

func NewPreAllocatedSharesPool[T uint64 | int](n T) *PreAllocatedSharesPool {
	p := &PreAllocatedSharesPool{}
	p.pool.New = func() any {
		return PreAllocateShares(n)
	}
	return p
}

func (p *PreAllocatedSharesPool) Get() Shares {
	return p.pool.Get().(Shares)
}

func (p *PreAllocatedSharesPool) Put(s Shares) {
	p.pool.Put(s)
}

func PreAllocateShares[T uint64 | int](n T) Shares {
	preAllocatedShares := make(Shares, n)
	// Preserve locality
	preAllocatedStructs := make([]Share, n)
	for i := range preAllocatedShares {
		preAllocatedShares[i] = &preAllocatedStructs[i]
	}
	return preAllocatedShares
}

type Share struct {
	Address address.PackedAddressWithSubaddress
	Weight  types.Difficulty
}
