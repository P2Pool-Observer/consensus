package stratum

import (
	"git.gammaspectra.live/P2Pool/consensus/v3/p2pool/mempool"
	"git.gammaspectra.live/P2Pool/consensus/v3/types"
	"github.com/dolthub/swiss"
	"time"
)

type MiningMempool swiss.Map[types.Hash, *mempool.Entry]

func (m *MiningMempool) m() *swiss.Map[types.Hash, *mempool.Entry] {
	return (*swiss.Map[types.Hash, *mempool.Entry])(m)
}

// Add Inserts a transaction into the mempool.
func (m *MiningMempool) Add(tx *mempool.Entry) (added bool) {
	mm := m.m()
	if !mm.Has(tx.Id) {
		if tx.TimeReceived.IsZero() {
			tx.TimeReceived = time.Now()
		}
		mm.Put(tx.Id, tx)
		added = true
	}

	return added
}

func (m *MiningMempool) Swap(pool mempool.Mempool) {
	currentTime := time.Now()

	mm := m.m()
	for _, tx := range pool {
		if v, ok := mm.Get(tx.Id); ok {
			//tx is already here, use previous seen time
			tx.TimeReceived = v.TimeReceived
		} else {
			tx.TimeReceived = currentTime
		}
	}

	mm.Clear()

	for _, tx := range pool {
		mm.Put(tx.Id, tx)
	}
}

func (m *MiningMempool) Select(highFee uint64, receivedSince time.Duration) (pool mempool.Mempool) {
	pool = make(mempool.Mempool, 0, m.m().Count())

	currentTime := time.Now()

	m.m().Iter(func(_ types.Hash, tx *mempool.Entry) (stop bool) {
		if currentTime.Sub(tx.TimeReceived) > receivedSince || tx.Fee >= highFee {
			pool = append(pool, tx)
		}
		return false
	})

	return pool
}
