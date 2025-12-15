package stratum

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"git.gammaspectra.live/P2Pool/consensus/v5/monero"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/address"
	"git.gammaspectra.live/P2Pool/consensus/v5/p2pool/sidechain"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
)

type MinerTrackingEntry struct {
	Lock         sync.RWMutex
	Counter      atomic.Uint64
	LastTemplate atomic.Uint64
	Templates    map[uint64]*Template
	LastJob      time.Time
}

type Client struct {
	Lock       sync.RWMutex
	Conn       net.Conn
	encoder    *utils.JSONEncoder
	decoder    *utils.JSONDecoder
	Agent      string
	Login      bool
	Extensions struct {
		Algo bool
	}
	MergeMiningExtra sidechain.MergeMiningExtra
	Address          address.PackedAddress
	Subaddress       *address.PackedAddress
	Password         string
	RigId            string
	buf              []byte
	RpcId            uint32
	InternalId       uint64
}

func (c *Client) GetAddress(majorVersion uint8) address.PackedAddressWithSubaddress {
	if c.Subaddress != nil && majorVersion >= monero.HardForkCarrotVersion {
		return address.NewPackedAddressWithSubaddress(c.Subaddress, true)
	}
	return address.NewPackedAddressWithSubaddress(&c.Address, false)
}

func (c *Client) Write(b []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(time.Second * 5)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}
