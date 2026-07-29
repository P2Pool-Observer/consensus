package stratum

import (
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v5/p2pool/mempool"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
)

type MiningMempool map[types.Hash]*mempool.Entry

// Add Inserts a transaction into the mempool.
func (m MiningMempool) Add(tx *mempool.Entry) (added bool) {
	if _, ok := m[tx.Id]; !ok {
		if tx.TimeReceivedMilli == 0 {
			tx.TimeReceivedMilli = time.Now().UnixMilli()
		}
		m[tx.Id] = tx
		added = true
	}

	return added
}

func (m MiningMempool) Swap(pool mempool.Mempool) {
	currentTime := time.Now()

	for _, tx := range pool {
		if v, ok := m[tx.Id]; ok {
			//tx is already here, use previous seen time
			tx.TimeReceivedMilli = v.TimeReceivedMilli
		} else {
			tx.TimeReceivedMilli = currentTime.UnixMilli()
		}
	}

	clear(m)

	for _, tx := range pool {
		m[tx.Id] = tx
	}
}

func (m MiningMempool) Select(highFee uint64, receivedSince time.Duration) (pool mempool.Mempool) {
	receivedSinceMilli := int64(receivedSince / time.Millisecond)
	currentTimeMilli := time.Now().UnixMilli()

	pool = make(mempool.Mempool, 0, len(m))

	for _, tx := range m {
		if (currentTimeMilli-tx.TimeReceivedMilli) > receivedSinceMilli || tx.Fee >= highFee {
			pool = append(pool, tx)
		}
	}

	return pool
}
