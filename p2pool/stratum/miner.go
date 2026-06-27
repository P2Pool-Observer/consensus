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

func AlgoForMajorVersion[T uint8 | int | uint64](version T) string {
	if version < monero.HardForkCryptoNightV1 {
		return AlgoCryptoNight_V0
	} else if version < monero.HardForkCryptoNightV2 {
		return AlgoCryptoNight_V1
	} else if version < monero.HardForkCryptoNightR {
		return AlgoCryptoNight_V2
	} else if version < monero.HardForkRandomX {
		return AlgoCryptoNight_R
	} else if version < monero.HardForkRandomXV2 {
		return AlgoRandomX_V0
	} else {
		return AlgoRandomX_V2
	}
}

const (
	AlgoRandomX_V0 = "rx/0"
	AlgoRandomX_V2 = "rx/2"

	AlgoCryptoNight_V0 = "cn/0"
	AlgoCryptoNight_V1 = "cn/1"
	AlgoCryptoNight_V2 = "cn/2"
	AlgoCryptoNight_R  = "cn/r"
)

type ClientExtensions struct {
	Algo bool

	RandomX_V0 bool
	RandomX_V2 bool

	CryptoNight_V0 bool
	CryptoNight_V1 bool
	CryptoNight_V2 bool
	CryptoNight_R  bool
}

func (e ClientExtensions) HasAlgo(algo string) bool {
	if e.Algo {
		switch algo {
		case AlgoRandomX_V0:
			return e.RandomX_V0
		case AlgoRandomX_V2:
			return e.RandomX_V2
		case AlgoCryptoNight_V0:
			return e.CryptoNight_V0
		case AlgoCryptoNight_V1:
			return e.CryptoNight_V1
		case AlgoCryptoNight_V2:
			return e.CryptoNight_V2
		case AlgoCryptoNight_R:
			return e.CryptoNight_R
		default:
			return false
		}
	} else {
		return algo == AlgoRandomX_V0
	}

}

type Client struct {
	Lock             sync.RWMutex
	Conn             net.Conn
	encoder          *utils.JSONEncoder
	decoder          *utils.JSONDecoder
	Agent            string
	Login            bool
	Extensions       ClientExtensions
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
