package p2p

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	unsafeRandom "math/rand/v2" //nolint:depguard
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"git.gammaspectra.live/P2Pool/consensus/v5/merge_mining"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/block"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/randomx"
	"git.gammaspectra.live/P2Pool/consensus/v5/monero/transaction"
	"git.gammaspectra.live/P2Pool/consensus/v5/p2pool/sidechain"
	p2pooltypes "git.gammaspectra.live/P2Pool/consensus/v5/p2pool/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/types"
	"git.gammaspectra.live/P2Pool/consensus/v5/utils"
	fasthex "github.com/tmthrgd/go-hex"
)

const DefaultBanTime = time.Second * 600
const PeerListResponseMaxPeers = 16
const PeerRequestDelay = 60

const MaxBufferSize = 128 * 1024

var smallBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, 16384)
	},
}

func getBuffer(length int) []byte {
	if length <= 16384 {
		return smallBufferPool.Get().([]byte)
	}
	return make([]byte, length)
}

func returnBuffer(x []byte) {
	if len(x) <= 16384 {
		//nolint:staticcheck
		smallBufferPool.Put(x)
	}
}

func ensureEOF(r io.Reader) error {
	var buf [1]byte
	if _, err := r.Read(buf[:]); err == nil || !errors.Is(err, io.EOF) {
		return errors.New("leftover bytes on reader")
	}
	return nil
}

type HostPort struct {
	Host string
	Port uint16
}

func (hp HostPort) Addr() netip.Addr {
	addr, err := netip.ParseAddr(hp.Host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func IsBlockedPort(port uint16) bool {
	// block common protocol ports to prevent abuse
	return port < 1024 || port == 8080
}

func (hp HostPort) String() string {
	return hp.Host + ":" + strconv.FormatUint(uint64(hp.Port), 10)
}

type Client struct {
	// Peer general static-ish information
	PeerId             atomic.Uint64
	VersionInformation p2pooltypes.PeerVersionInformation
	ListenPort         atomic.Uint32
	ConnectionTime     time.Time
	HostPort           HostPort

	// Peer general dynamic-ish information
	BroadcastMaxHeight atomic.Uint64
	PingDuration       atomic.Int64

	// Internal values
	Owner                                *Server
	Connection                           net.Conn
	banErrorLock                         sync.Mutex
	banError                             error
	LastBroadcastTimestamp               atomic.Int64
	LastBlockRequestTimestamp            atomic.Int64
	LastIncomingPeerListRequestTime      time.Time
	LastActiveTimestamp                  atomic.Int64
	LastPeerListRequestTimestamp         atomic.Int64
	NextOutgoingPeerListRequestTimestamp atomic.Int64

	expectedMessage      MessageId
	IsIncomingConnection bool

	Closed atomic.Bool
	//State properties
	HandshakeComplete     atomic.Bool
	SentHandshakeSolution atomic.Bool

	LastKnownTip atomic.Pointer[sidechain.PoolBlock]

	BroadcastedHashes *utils.CircularBuffer[types.Hash]
	RequestedHashes   *utils.CircularBuffer[types.Hash]

	blockPendingRequests chan types.Hash

	handshakeChallenge HandshakeChallenge

	closeChannel chan struct{}
}

func NewClient(owner *Server, source HostPort, conn net.Conn) *Client {
	c := &Client{
		Owner:                owner,
		Connection:           conn,
		ConnectionTime:       time.Now(),
		HostPort:             source,
		expectedMessage:      MessageHandshakeChallenge,
		closeChannel:         make(chan struct{}),
		BroadcastedHashes:    utils.NewCircularBuffer[types.Hash](8),
		RequestedHashes:      utils.NewCircularBuffer[types.Hash](16),
		blockPendingRequests: make(chan types.Hash, 100), //allow max 100 pending block requests at the same time
	}

	c.LastActiveTimestamp.Store(time.Now().Unix())

	return c
}

func (c *Client) BanError() error {
	c.banErrorLock.Lock()
	defer c.banErrorLock.Unlock()
	return c.banError
}

func (c *Client) SetError(err error) {
	c.banErrorLock.Lock()
	defer c.banErrorLock.Unlock()
	if c.banError == nil {
		c.banError = err
	}
}

func (c *Client) Ban(duration time.Duration, err error) {

	c.SetError(err)
	c.Owner.Ban(c.HostPort.Addr(), duration, err)
	c.Owner.RemoveFromHostPeerList(c.HostPort.Host)
	c.Close()
}

func (c *Client) OnAfterHandshake() {
	c.SendListenPort()
	c.SendBlockRequest(types.ZeroHash)
	utils.Logf("P2PClient", "Peer %s after handshake complete: sent LISTEN_PORT + tip BLOCK_REQUEST", c.HostPort.String())

	c.LastBroadcastTimestamp.Store(time.Now().Unix())
}

func (c *Client) getNextBlockRequest() (id types.Hash, ok bool) {
	select {
	case id = <-c.blockPendingRequests:
		return id, true
	default:
		return types.ZeroHash, false
	}
}

// PreferredAddressPort Return the address and port to which the peer is most probably reachable
func (c *Client) PreferredAddressPort() netip.AddrPort {
	addr := c.HostPort.Addr()
	if !addr.IsValid() {
		return netip.AddrPortFrom(addr, 0)
	}

	if listenPort := c.ListenPort.Load(); listenPort != 0 && !IsBlockedPort(uint16(listenPort)) {
		return netip.AddrPortFrom(c.HostPort.Addr(), uint16(listenPort))
	}

	//take default from consensus
	return netip.AddrPortFrom(c.HostPort.Addr(), c.Owner.Consensus().DefaultPort())
}

func (c *Client) SendListenPort() {
	c.SendMessage(&ClientMessage{
		MessageId: MessageListenPort,
		Buffer:    binary.LittleEndian.AppendUint32(nil, uint32(c.Owner.ExternalListenPort())),
	})
}

func (c *Client) SendMissingBlockRequestAtRandom(hash types.Hash, allowedClients []*Client) []*Client {
	if hash == types.ZeroHash || c.Owner.SideChain().GetPoolBlockByTemplateId(hash) != nil {
		return allowedClients
	}

	if b := c.Owner.GetCachedBlock(hash); b != nil {
		utils.Logf("P2PClient", "Using cached block for id = %x", hash.Slice())
		if _, err, _ := c.Owner.SideChain().AddPoolBlockExternal(b); err == nil {
			return allowedClients
		}
	}

	if len(allowedClients) == 0 {
		allowedClients = append(allowedClients, c)
	}

	for len(allowedClients) > 0 {
		k := unsafeRandom.IntN(len(allowedClients)) % len(allowedClients) // #nosec G404
		client := allowedClients[k]
		if client.IsGood() && len(client.blockPendingRequests) < 20 {
			client.SendBlockRequest(hash)
			break
		} else {
			allowedClients = slices.Delete(allowedClients, k, k+1)
		}
	}
	return allowedClients
}

func (c *Client) SendMissingBlockRequest(hash types.Hash) {
	if hash == types.ZeroHash || c.Owner.SideChain().GetPoolBlockByTemplateId(hash) != nil {
		return
	}

	if b := c.Owner.GetCachedBlock(hash); b != nil {
		utils.Logf("P2PClient", "Using cached block for id = %x", hash.Slice())
		if missingBlocks, err, _ := c.Owner.SideChain().AddPoolBlockExternal(b); err == nil {
			for _, id := range missingBlocks {
				c.SendMissingBlockRequest(id)
			}
			return
		}
	}

	// do not re-request hashes that have been requested
	if !c.RequestedHashes.PushUnique(hash) {
		return
	}

	// If the initial sync is not finished yet, try to ask the fastest peer too
	if !c.Owner.SideChain().PreCalcFinished() {
		fastest := c.Owner.GetFastestClient()
		if fastest != nil && c != fastest && !c.Owner.SideChain().PreCalcFinished() {
			//send towards the fastest peer as well
			fastest.SendMissingBlockRequest(hash)
		}
	}

	c.SendBlockRequest(hash)
}

func (c *Client) SendUniqueBlockRequest(hash types.Hash) {
	if hash == types.ZeroHash {
		return
	}

	// do not re-request hashes that have been requested
	if !c.RequestedHashes.PushUnique(hash) {
		return
	}

	c.SendBlockRequest(hash)
}

func (c *Client) SendBlockRequest(id types.Hash) {
	c.SendBlockRequestWithBound(id, 80)
}

func (c *Client) SendBlockRequestWithBound(id types.Hash, bound int) bool {
	if len(c.blockPendingRequests) < bound {
		c.blockPendingRequests <- id
		c.SendMessage(&ClientMessage{
			MessageId: MessageBlockRequest,
			Buffer:    id[:],
		})
		return true
	}
	return false
}

func (c *Client) SendBlockNotify(id types.Hash) {
	c.SendMessage(&ClientMessage{
		MessageId: MessageBlockNotify,
		Buffer:    id[:],
	})
}

func (c *Client) SendBlockResponse(block *sidechain.PoolBlock) {
	if block != nil {
		blockData, err := block.AppendBinaryFlags(make([]byte, 0, block.BufferLength()), false, false)
		if block.Thinned.Load() {
			// return thin
			c.SendMessage(&ClientMessage{
				MessageId: MessageBlockResponse,
				Buffer:    binary.LittleEndian.AppendUint32(nil, 0),
			})
			return
		}
		if err != nil {
			utils.Logf("P2PClient", "Peer %s tried to respond with a block but received error, disconnecting: %s", c.HostPort, err)
			c.Close()
			return
		}

		c.SendMessage(&ClientMessage{
			MessageId: MessageBlockResponse,
			Buffer:    append(binary.LittleEndian.AppendUint32(make([]byte, 0, len(blockData)+4), uint32(len(blockData))), blockData...),
		})

	} else {
		c.SendMessage(&ClientMessage{
			MessageId: MessageBlockResponse,
			Buffer:    binary.LittleEndian.AppendUint32(nil, 0),
		})
	}
}

func (c *Client) SendPeerListRequest() {
	// #nosec G404
	c.NextOutgoingPeerListRequestTimestamp.Store(time.Now().Unix() + PeerRequestDelay + int64(unsafeRandom.Uint64()%(PeerRequestDelay+1)))
	c.SendMessage(&ClientMessage{
		MessageId: MessagePeerListRequest,
	})
	c.LastPeerListRequestTimestamp.Store(time.Now().UnixMicro())
	//utils.Logf("P2PClient", "Sending PEER_LIST_REQUEST to %s", c.HostPort.String())
}

func (c *Client) SendPeerListResponse(list []netip.AddrPort) {
	if len(list) > PeerListResponseMaxPeers {
		return
	}
	buf := make([]byte, 0, 1+len(list)*(1+16+2))
	buf = append(buf, byte(len(list)))
	for i := range list {
		//TODO: check ipv4 gets sent properly
		if list[i].Addr().Is6() && !p2pooltypes.IsPeerVersionInformation(list[i]) {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
		ip := list[i].Addr().As16()
		buf = append(buf, ip[:]...)
		buf = binary.LittleEndian.AppendUint16(buf, list[i].Port())
	}
	c.SendMessage(&ClientMessage{
		MessageId: MessagePeerListResponse,
		Buffer:    buf,
	})
}

func (c *Client) IsGood() bool {
	return c.HandshakeComplete.Load() && c.ListenPort.Load() > 0
}

func (c *Client) OnConnection(ourPeerId uint64) {
	c.LastActiveTimestamp.Store(time.Now().Unix())

	c.sendHandshakeChallenge()

	var messageIdBuf [1]byte
	var messageId MessageId
	for !c.Closed.Load() {
		if _, err := utils.ReadFullNoEscape(c, messageIdBuf[:]); err != nil {
			c.Close()
			return
		}

		messageId = MessageId(messageIdBuf[0])

		if !c.HandshakeComplete.Load() && messageId != c.expectedMessage {
			c.Ban(DefaultBanTime, utils.ErrorfNoEscape("unexpected pre-handshake message: got %d, expected %d", messageId, c.expectedMessage))
			return
		}

		switch messageId {
		case MessageHandshakeChallenge:
			if c.HandshakeComplete.Load() {
				c.Ban(DefaultBanTime, errors.New("got HANDSHAKE_CHALLENGE but handshake is complete"))
				return
			}

			var challenge HandshakeChallenge
			var peerId uint64
			if _, err := utils.ReadFullNoEscape(c, challenge[:]); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}
			if err := utils.ReadLittleEndianInteger(c, &peerId); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			if peerId == c.Owner.PeerId() || peerId == c.Owner.AlternatePeerId() {
				c.HandshakeComplete.Store(true)
				c.SetError(errors.New("connected to self"))
				//tried to connect to self
				c.Close()
				return
			}

			c.PeerId.Store(peerId)

			if ok, otherClient := func() (bool, *Client) {
				c.Owner.clientsLock.RLock()
				defer c.Owner.clientsLock.RUnlock()
				for _, client := range c.Owner.clients {
					if client != c && client.PeerId.Load() == peerId {
						return true, client
					}
				}
				return false, nil
			}(); ok {
				c.HandshakeComplete.Store(true)
				c.SetError(utils.ErrorfNoEscape("already connected as %s (%d)", otherClient.HostPort, otherClient.PeerId.Load()))
				//same peer
				utils.Logf("P2PClient", "Connected to other same peer: %s (%d) is also %s (%d)", c.HostPort, c.PeerId.Load(), otherClient.HostPort, otherClient.PeerId.Load())
				c.Close()
				return
			}

			c.sendHandshakeSolution(challenge)

			c.expectedMessage = MessageHandshakeSolution

			if c.HandshakeComplete.Load() && c.SentHandshakeSolution.Load() {
				c.OnAfterHandshake()
			}

		case MessageHandshakeSolution:
			if c.HandshakeComplete.Load() {
				c.Ban(DefaultBanTime, errors.New("got HANDSHAKE_SOLUTION but handshake is complete"))
				return
			}

			var challengeHash types.Hash
			var solution uint64
			if _, err := utils.ReadFullNoEscape(c, challengeHash[:]); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}
			if err := utils.ReadLittleEndianInteger(c, &solution); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			if c.IsIncomingConnection {
				//TODO: consensus MergeMiningId
				if hash, ok := CalculateChallengeHash(c.handshakeChallenge, c.Owner.HandshakeConsensusId(), solution); !ok {
					//not enough PoW
					c.Ban(DefaultBanTime, utils.ErrorfNoEscape("not enough PoW on HANDSHAKE_SOLUTION, challenge = %s, solution = %d, calculated hash = %s, expected hash = %s", fasthex.EncodeToString(c.handshakeChallenge[:]), solution, hash.String(), challengeHash.String()))
					return
				} else if hash != challengeHash {
					//wrong hash
					c.Ban(DefaultBanTime, utils.ErrorfNoEscape("wrong hash HANDSHAKE_SOLUTION, challenge = %s, solution = %d, calculated hash = %s, expected hash = %s", fasthex.EncodeToString(c.handshakeChallenge[:]), solution, hash.String(), challengeHash.String()))
					return
				}
			} else {
				//TODO: consensus MergeMiningId
				if hash, _ := CalculateChallengeHash(c.handshakeChallenge, c.Owner.HandshakeConsensusId(), solution); hash != challengeHash {
					//wrong hash
					c.Ban(DefaultBanTime, utils.ErrorfNoEscape("wrong hash HANDSHAKE_SOLUTION, challenge = %s, solution = %d, calculated hash = %s, expected hash = %s", fasthex.EncodeToString(c.handshakeChallenge[:]), solution, hash.String(), challengeHash.String()))
					return
				}
			}
			c.HandshakeComplete.Store(true)

			if c.HandshakeComplete.Load() && c.SentHandshakeSolution.Load() {
				c.OnAfterHandshake()
			}

		case MessageListenPort:
			if c.ListenPort.Load() != 0 {
				c.Ban(DefaultBanTime, errors.New("got LISTEN_PORT but we already received it"))
				return
			}

			var listenPort uint32

			if err := utils.ReadLittleEndianInteger(c, &listenPort); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			if listenPort == 0 || listenPort >= 65536 {
				c.Ban(DefaultBanTime, utils.ErrorfNoEscape("listen port out of range: %d", listenPort))
				return
			}
			c.ListenPort.Store(listenPort)
			c.Owner.UpdateInPeerList(netip.AddrPortFrom(c.HostPort.Addr(), uint16(c.ListenPort.Load())))
		case MessageBlockRequest:
			c.LastBlockRequestTimestamp.Store(time.Now().Unix())

			var templateId types.Hash
			if _, err := utils.ReadFullNoEscape(c, templateId[:]); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			var block *sidechain.PoolBlock
			//if empty, return chain tip
			if templateId == types.ZeroHash {
				utils.Logf("P2PClient", "Peer %s requested tip", c.HostPort.String())
				// Don't return stale chain tip
				if block = c.Owner.SideChain().GetChainTip(); block != nil && ((block.Main.Coinbase.GenHeight+2) < c.Owner.MainChain().GetMinerDataTip().Height || block.Thinned.Load()) {
					block = nil
				}
			} else {
				block = c.Owner.SideChain().GetPoolBlockByTemplateId(templateId)
				if block == nil {
					utils.Logf("P2PClient", "Peer %s requested id = %s, got nil", c.HostPort.String(), templateId)
				} else {
					utils.Logf("P2PClient", "Peer %s requested id = %s, got height = %d, main height = %d", c.HostPort.String(), templateId, block.Side.Height, block.Main.Coinbase.GenHeight)
				}
			}

			if block != nil && c.Owner.VersionInformation().SupportsFeature(p2pooltypes.FeatureBlockNotify) && c.VersionInformation.SupportsFeature(p2pooltypes.FeatureBlockNotify) {
				c.SendBlockNotify(block.Side.Parent)
				for _, uncleId := range block.Side.Uncles {
					c.SendBlockNotify(uncleId)
				}
				if parent := c.Owner.SideChain().GetParent(block); parent != nil {
					c.SendBlockNotify(parent.Side.Parent)
				}
			}

			c.SendBlockResponse(block)
		case MessageBlockResponse:
			block := &sidechain.PoolBlock{
				Metadata: sidechain.PoolBlockReceptionMetadata{
					LocalTime:       time.Now().UTC(),
					AddressPort:     c.PreferredAddressPort(),
					PeerId:          c.PeerId.Load(),
					SoftwareId:      uint32(c.VersionInformation.SoftwareId),
					SoftwareVersion: uint32(c.VersionInformation.SoftwareVersion),
				},
			}

			expectedBlockId, ok := c.getNextBlockRequest()

			if !ok {
				c.Ban(DefaultBanTime, errors.New("unexpected BLOCK_RESPONSE"))
				return
			}

			isChainTipBlockRequest := expectedBlockId == types.ZeroHash

			var blockSize uint32
			if err := utils.ReadLittleEndianInteger(c, &blockSize); err != nil {
				//TODO warn
				c.Ban(DefaultBanTime, err)
				return
			} else if blockSize == 0 {
				utils.Logf("P2PClient", "Peer %s sent nil BLOCK_RESPONSE to id = %s", c.HostPort.String(), expectedBlockId)
				if isChainTipBlockRequest && time.Now().Unix() >= c.NextOutgoingPeerListRequestTimestamp.Load() {
					c.SendPeerListRequest()
				}
				break
			} else {
				reader := bufio.NewReader(utils.LimitByteReader(c, int64(blockSize)))
				if err = block.FromReader(c.Owner.Consensus(), c.Owner.SideChain().DerivationCache(), reader); err != nil {
					//TODO warn
					c.Ban(DefaultBanTime, err)
					return
				} else if err = ensureEOF(reader); err != nil {
					c.Ban(DefaultBanTime, err)
					return
				} else {
					tipHash := block.FastSideTemplateId(c.Owner.Consensus())

					if isChainTipBlockRequest {
						if lastTip := c.LastKnownTip.Load(); lastTip == nil || lastTip.Side.Height <= block.Side.Height {
							if _, err = c.Owner.SideChain().PreprocessBlock(block); err == nil {
								c.LastKnownTip.Store(block)
							}
						}

						utils.Logf("P2PClient", "Peer %s tip is at id = %s, height = %d, main height = %d", c.HostPort.String(), tipHash, block.Side.Height, block.Main.Coinbase.GenHeight)
						peerHeight := block.Main.Coinbase.GenHeight
						ourHeight := c.Owner.MainChain().GetMinerDataTip().Height

						if (peerHeight + 2) < ourHeight {
							c.Ban(DefaultBanTime, utils.ErrorfNoEscape("mining on top of a stale block (mainchain peer height %d, expected >= %d)", peerHeight, ourHeight))
							return
						}

						//Atomic max, not necessary as no external writers exist
						topHeight := max(c.BroadcastMaxHeight.Load(), block.Side.Height)
						for {
							if oldHeight := c.BroadcastMaxHeight.Swap(topHeight); oldHeight <= topHeight {
								break
							} else {
								topHeight = oldHeight
							}
						}

						if time.Now().Unix() >= c.NextOutgoingPeerListRequestTimestamp.Load() {
							c.SendPeerListRequest()
						}
					}
					if c.Owner.SideChain().BlockSeen(block) {
						//utils.Logf("P2PClient", "Peer %s block id = %s, height = %d (nonce %d, extra_nonce %d) was received before, skipping it", c.HostPort.String(), types.HashFromBytes(block.CoinbaseExtra(sidechain.SideIdentifierHash)), block.Side.Height, block.Main.Nonce, block.ExtraNonce())
						break
					}
					if missingBlocks, err, ban := c.Owner.SideChain().AddPoolBlockExternal(block); err != nil {
						if ban {
							c.Ban(DefaultBanTime, err)
							return
						} else {
							utils.Logf("P2PClient", "Peer %s error adding block id = %s, height = %d, main height = %d, timestamp = %d", c.HostPort.String(), tipHash, block.Side.Height, block.Main.Coinbase.GenHeight, block.Main.Timestamp)
							break
						}
					} else {
						if !isChainTipBlockRequest && expectedBlockId != block.SideTemplateId(c.Owner.SideChain().Consensus()) {
							c.Ban(DefaultBanTime, utils.ErrorfNoEscape("expected block id = %s, got %s", expectedBlockId.String(), block.SideTemplateId(c.Owner.SideChain().Consensus()).String()))
							return
						}
						for _, id := range missingBlocks {
							c.SendMissingBlockRequest(id)
						}
					}
				}
			}

		case MessageBlockBroadcast, MessageBlockBroadcastCompact:
			poolBlock := &sidechain.PoolBlock{
				Metadata: sidechain.PoolBlockReceptionMetadata{
					LocalTime:       time.Now().UTC(),
					AddressPort:     c.PreferredAddressPort(),
					PeerId:          c.PeerId.Load(),
					SoftwareId:      uint32(c.VersionInformation.SoftwareId),
					SoftwareVersion: uint32(c.VersionInformation.SoftwareVersion),
				},
			}
			var blockSize uint32
			if err := utils.ReadLittleEndianInteger(c, &blockSize); err != nil {
				//TODO warn
				c.Ban(DefaultBanTime, err)
				return
			} else if blockSize == 0 {
				//NOT found
				//TODO log
				break
			} else if messageId == MessageBlockBroadcastCompact {
				reader := bufio.NewReader(utils.LimitByteReader(c, int64(blockSize)))
				if err = poolBlock.FromCompactReader(c.Owner.Consensus(), c.Owner.SideChain().DerivationCache(), reader); err != nil {
					//TODO warn
					c.Ban(DefaultBanTime, err)
					return
				} else if err = ensureEOF(reader); err != nil {
					c.Ban(DefaultBanTime, err)
					return
				}
			} else {
				reader := bufio.NewReader(utils.LimitByteReader(c, int64(blockSize)))
				if err = poolBlock.FromReader(c.Owner.Consensus(), c.Owner.SideChain().DerivationCache(), reader); err != nil {
					//TODO warn
					c.Ban(DefaultBanTime, err)
					return
				} else if err = ensureEOF(reader); err != nil {
					c.Ban(DefaultBanTime, err)
					return
				}
			}

			//Atomic max, not necessary as no external writers exist
			topHeight := max(c.BroadcastMaxHeight.Load(), poolBlock.Side.Height)
			for {
				if oldHeight := c.BroadcastMaxHeight.Swap(topHeight); oldHeight <= topHeight {
					break
				} else {
					topHeight = oldHeight
				}
			}

			//utils.Logf("P2PClient", "Peer %s broadcast tip is at id = %s, height = %d, main height = %d", c.HostPort.String(), tipHash, block.Side.Height, block.Main.Coinbase.GenHeight)

			if missingBlocks, err := c.Owner.SideChain().PreprocessBlock(poolBlock); err != nil {
				for _, id := range missingBlocks {
					c.SendMissingBlockRequest(id)
				}
				//TODO: ban here, but sort blocks properly, maybe a queue to re-try?
				//nolint:staticcheck
				break
			} else {
				tipHash := poolBlock.FastSideTemplateId(c.Owner.Consensus())

				c.BroadcastedHashes.Push(tipHash)

				c.LastBroadcastTimestamp.Store(time.Now().Unix())

				if lastTip := c.LastKnownTip.Load(); lastTip == nil || lastTip.Side.Height <= poolBlock.Side.Height {
					c.LastKnownTip.Store(poolBlock)
				}

				ourMinerData := c.Owner.MainChain().GetMinerDataTip()

				if poolBlock.Main.PreviousId != ourMinerData.PrevId {
					// This peer is mining on top of a different Monero block, investigate it

					peerHeight := poolBlock.Main.Coinbase.GenHeight
					ourHeight := ourMinerData.Height

					if peerHeight < ourHeight {
						if (ourHeight - peerHeight) < 5 {
							elapsedTime := time.Since(ourMinerData.TimeReceived)
							if (ourHeight-peerHeight) > 1 || elapsedTime > (time.Second*10) {
								utils.Logf("P2PClient", "Peer %s broadcasted a stale block (%d ms late, mainchain height %d, expected >= %d), ignoring it", c.HostPort.String(), elapsedTime.Milliseconds(), peerHeight, ourHeight)
							}
						} else {
							c.Ban(DefaultBanTime, utils.ErrorfNoEscape("broadcasted an unreasonably stale block (mainchain height %d, expected >= %d)", peerHeight, ourHeight))
							return
						}
					} else if peerHeight > ourHeight {
						if peerHeight >= (ourHeight + 2) {
							utils.Logf("P2PClient", "Peer %s is ahead on mainchain (mainchain height %d, your height %d). Is monerod stuck or lagging?", c.HostPort.String(), peerHeight, ourHeight)
						}
					} else {
						utils.Logf("P2PClient", "Peer %s is mining on an alternative mainchain tip (mainchain height %d, previous_id = %s)", c.HostPort.String(), peerHeight, poolBlock.Main.PreviousId)
					}
				}

				if c.Owner.SideChain().BlockSeen(poolBlock) {
					//utils.Logf("P2PClient", "Peer %s block id = %s, height = %d (nonce %d, extra_nonce %d) was received before, skipping it", c.HostPort.String(), types.HashFromBytes(block.CoinbaseExtra(sidechain.SideIdentifierHash)), block.Side.Height, block.Main.Nonce, block.ExtraNonce())
					break
				}

				poolBlock.WantBroadcast.Store(true)
				if missingBlocks, err, ban := c.Owner.SideChain().AddPoolBlockExternal(poolBlock); err != nil {
					if ban {
						c.Ban(DefaultBanTime, err)
					} else {
						utils.Logf("P2PClient", "Peer %s error adding block id = %s, height = %d, main height = %d, timestamp = %d", c.HostPort.String(), tipHash, poolBlock.Side.Height, poolBlock.Main.Coinbase.GenHeight, poolBlock.Main.Timestamp)
					}
					return
				} else {
					for _, id := range missingBlocks {
						c.SendMissingBlockRequest(id)
					}
				}
			}
		case MessagePeerListRequest:
			connectedPeerList := c.Owner.Clients()

			entriesToSend := make([]netip.AddrPort, 0, PeerListResponseMaxPeers)

			// Send every 4th peer on average, selected at random
			peersToSendTarget := min(PeerListResponseMaxPeers, max(len(connectedPeerList)/4, 1))
			n := 0
			for _, peer := range connectedPeerList {
				if addr := peer.HostPort.Addr(); !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || !peer.IsGood() || IsBlockedPort(peer.HostPort.Port) || c.HostPort.Host == peer.HostPort.Host {
					continue
				} else {

					n++

					// Use https://en.wikipedia.org/wiki/Reservoir_sampling algorithm
					if len(entriesToSend) < peersToSendTarget {
						entriesToSend = append(entriesToSend, netip.AddrPortFrom(addr, peer.HostPort.Port))
					}

					// #nosec G404
					k := unsafeRandom.IntN(n)
					if k < peersToSendTarget {
						entriesToSend[k] = netip.AddrPortFrom(addr, peer.HostPort.Port)
					}

				}
			}

			// Check whether to send version to target or not
			if c.LastIncomingPeerListRequestTime.IsZero() && c.Owner.VersionInformation().SupportsFeature(p2pooltypes.FeaturePeerInformationExchange) && c.VersionInformation.SupportsFeature(p2pooltypes.FeaturePeerInformationReceive) {
				//first, send version / protocol information
				if len(entriesToSend) == 0 {
					entriesToSend = append(entriesToSend, c.Owner.VersionInformation().ToAddrPort())
				} else {
					entriesToSend[0] = c.Owner.VersionInformation().ToAddrPort()
				}
			}

			lastLen := len(entriesToSend)

			if lastLen < PeerListResponseMaxPeers {
				//improvement from normal p2pool: pad response with other peers from peer list, not connected
				peerList := c.Owner.PeerList()
				for i := lastLen; i < PeerListResponseMaxPeers && len(peerList) > 0; i++ {
					// #nosec G404
					k := unsafeRandom.IntN(len(peerList)) % len(peerList)
					peer := peerList[k]
					if !slices.ContainsFunc(entriesToSend, func(addrPort netip.AddrPort) bool {
						return addrPort.Addr().Compare(peer.AddressPort.Addr()) == 0
					}) {
						entriesToSend = append(entriesToSend, peer.AddressPort)
					}
				}
			}

			var hasIpv6 bool
			for _, e := range entriesToSend {
				if e.Addr().Is6() {
					hasIpv6 = true
					break
				}
			}

			//include one ipv6, if existent
			if !hasIpv6 {
				peerList := c.Owner.PeerList()
				// #nosec G404
				unsafeRandom.Shuffle(len(peerList), func(i, j int) {
					peerList[i] = peerList[j]
				})
				for _, p := range c.Owner.PeerList() {
					if p.AddressPort.Addr().Is4In6() || p.AddressPort.Addr().Is6() {
						if len(entriesToSend) < PeerListResponseMaxPeers {
							entriesToSend = append(entriesToSend, p.AddressPort)
						} else {
							entriesToSend[len(entriesToSend)-1] = p.AddressPort
						}
						break
					}
				}
			}

			c.LastIncomingPeerListRequestTime = time.Now()

			c.SendPeerListResponse(entriesToSend)
		case MessagePeerListResponse:
			if numPeers, err := c.ReadByte(); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			} else if numPeers > PeerListResponseMaxPeers {
				c.Ban(DefaultBanTime, utils.ErrorfNoEscape("too many peers on PEER_LIST_RESPONSE num_peers = %d", numPeers))
				return
			} else {
				firstPeerResponse := c.PingDuration.Swap(int64(max(time.Since(time.UnixMicro(c.LastPeerListRequestTimestamp.Load())), 0))) == 0
				var rawIp [16]byte
				var port uint16

				if firstPeerResponse {
					utils.Logf("P2PClient", "Peer %s initial PEER_LIST_RESPONSE: num_peers %d", c.HostPort.String(), numPeers)
				}
				for range numPeers {
					if isV6, err := c.ReadByte(); err != nil {
						c.Ban(DefaultBanTime, err)
						return
					} else {
						if _, err = c.Read(rawIp[:]); err != nil {
							c.Ban(DefaultBanTime, err)
							return
						} else if err = utils.ReadLittleEndianInteger(c, &port); err != nil {
							c.Ban(DefaultBanTime, err)
							return
						}

						if isV6 == 0 {
							if rawIp[12] == 0 || rawIp[12] >= 224 {
								// Ignore 0.0.0.0/8 (special-purpose range for "this network") and 224.0.0.0/3 (IP multicast and reserved ranges)

								// Check for protocol version message
								if binary.LittleEndian.Uint32(rawIp[12:]) == 0xFFFFFFFF && port == 0xFFFF {
									c.VersionInformation.Protocol = p2pooltypes.ProtocolVersion(binary.LittleEndian.Uint32(rawIp[0:]))
									c.VersionInformation.SoftwareVersion = p2pooltypes.SoftwareVersion(binary.LittleEndian.Uint32(rawIp[4:]))
									c.VersionInformation.SoftwareId = p2pooltypes.SoftwareId(binary.LittleEndian.Uint32(rawIp[8:]))
									utils.Logf("P2PClient", "Peer %s version information: %s", c.HostPort.String(), c.VersionInformation.String())

									c.afterInitialProtocolExchange()
								}
								continue
							}

							copy(rawIp[:], make([]byte, 10))
							// #nosec G602
							rawIp[10], rawIp[11] = 0xFF, 0xFF

						}

						c.Owner.AddToPeerList(netip.AddrPortFrom(netip.AddrFrom16(rawIp).Unmap(), port))
					}
				}
			}
		case MessageBlockNotify:
			c.LastBlockRequestTimestamp.Store(time.Now().Unix())

			var templateId types.Hash
			if _, err := utils.ReadFullNoEscape(c, templateId[:]); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			c.BroadcastedHashes.Push(templateId)

			// If we don't know about this block, request it from this peer. The peer can do it to speed up our initial sync, for example.
			if tip := c.Owner.SideChain().GetPoolBlockByTemplateId(templateId); tip == nil {
				//TODO: prevent sending duplicate requests
				//nolint:staticcheck
				if c.SendBlockRequestWithBound(templateId, 25) {

				}
			} else {
				if lastTip := c.LastKnownTip.Load(); lastTip == nil || lastTip.Side.Height <= tip.Side.Height {
					c.LastKnownTip.Store(tip)
				}
			}
		case MessageAuxJobDonation:
			var dataSize uint32
			if err := utils.ReadLittleEndianInteger(c, &dataSize); err != nil {
				//TODO warn
				c.Ban(DefaultBanTime, err)
				return
			} else if dataSize == 0 {
				break
			}

			r := bufio.NewReader(utils.LimitByteReader(c, int64(dataSize)))
			var job merge_mining.AuxiliaryJobDonation

			err := job.FromReader(r)
			if err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			if _, err := job.Verify(time.Now()); err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			//TODO: broadcast/save data signatures
		case MessageMoneroBlockBroadcast:
			var dataSize uint32
			if err := utils.ReadLittleEndianInteger(c, &dataSize); err != nil {
				//TODO warn
				c.Ban(DefaultBanTime, err)
				return
			} else if dataSize == 0 {
				break
			}

			r := bufio.NewReader(utils.LimitByteReader(c, int64(dataSize)))
			var hdr MoneroBlockBroadcastHeader

			err := hdr.FromReader(r)
			if err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}

			if hdr.HeaderSize < 43 || hdr.HeaderSize > 128 || hdr.MinerTransactionSize < 64 || hdr.TotalSize() >= uint64(dataSize) {
				c.Ban(DefaultBanTime, errors.New("invalid MONERO_BLOCK_BROADCAST header"))
				return
			}

			b := &block.Block{}
			if err = b.FromReader(r, false, nil); err != nil {
				if errors.Is(err, transaction.ErrInvalidTransactionExtra) {
					// allow these as blocks with invalid tx extra could be published. Thanks Tari
					break
				}
				c.Ban(DefaultBanTime, err)
				return
			}

			minerData := c.Owner.MainChain().GetMinerDataTip()
			if b.Coinbase.UnlockTime < minerData.Height {
				// outdated monero block
				break
			}

			if !c.Owner.BroadcastedMoneroBlocks.PushUnique(b.Id()) {
				// repeated block
				break
			}

			var diff types.Difficulty

			if cm := c.Owner.MainChain().GetChainMainByHeight(b.Coinbase.GenHeight); cm != nil {
				diff = cm.Difficulty
			} else {
				diff = minerData.Difficulty
			}

			// Use 90% of this height's difficulty to account for possible altchain deviations
			diff = diff.Sub(diff.Div64(10))

			if powHash, err := b.PowHashWithError(c.Owner.Consensus().GetHasher(), func(height uint64) (hash types.Hash) {
				if h := c.Owner.MainChain().GetChainMainByHeight(randomx.SeedHeight(height)); h != nil {
					return h.Id
				}
				return types.ZeroHash
			}); err != nil {
				if errors.Is(err, block.ErrNoSeed) {
					// cannot get seed
					break
				}
				c.Ban(DefaultBanTime, err)
				return
			} else if !diff.CheckPoW(powHash) {
				c.Ban(DefaultBanTime, utils.ErrorfNoEscape("diff check failed, PoW hash = %x", powHash.Slice()))
				return
			}

			c.Owner.BroadcastMoneroBlock(c, b)

			// submit to monero
			go c.Owner.SideChain().Server().SubmitBlock(b)

		case MessageInternal:
			internalMessageId, err := utils.ReadCanonicalUvarint(c)
			if err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}
			messageSize, err := utils.ReadCanonicalUvarint(c)
			if err != nil {
				c.Ban(DefaultBanTime, err)
				return
			}
			reader := utils.LimitByteReader(c, int64(messageSize))

			_ = reader

			switch InternalMessageId(internalMessageId) {
			default:
				c.Ban(DefaultBanTime, utils.ErrorfNoEscape("unknown InternalMessageId %d", internalMessageId))
				return
			}
		default:
			c.Ban(DefaultBanTime, utils.ErrorfNoEscape("unknown MessageId %d", messageId))
			return
		}

		c.LastActiveTimestamp.Store(time.Now().Unix())
	}
}

func (c *Client) afterInitialProtocolExchange() {
	//TODO: use notify to send fast sync data
}

func (c *Client) sendHandshakeChallenge() {
	if _, err := rand.Read(c.handshakeChallenge[:]); err != nil {
		utils.Logf("P2PServer", "Unable to generate handshake challenge for %s", c.HostPort.String())
		c.Close()
		return
	}

	var buf [HandshakeChallengeSize + int(unsafe.Sizeof(uint64(0)))]byte
	copy(buf[:], c.handshakeChallenge[:])
	binary.LittleEndian.PutUint64(buf[HandshakeChallengeSize:], c.Owner.PeerId())

	c.SendMessage(&ClientMessage{
		MessageId: MessageHandshakeChallenge,
		Buffer:    buf[:],
	})
}

func (c *Client) sendHandshakeSolution(challenge HandshakeChallenge) {
	stop := &c.Closed
	if c.IsIncomingConnection {
		stop = &atomic.Bool{}
		stop.Store(true)
	}

	//TODO: consensus MergeMiningId
	if solution, hash, ok := FindChallengeSolution(challenge, c.Owner.HandshakeConsensusId(), stop); ok || c.IsIncomingConnection {

		var buf [HandshakeChallengeSize + types.HashSize]byte
		copy(buf[:], hash[:])
		binary.LittleEndian.PutUint64(buf[types.HashSize:], solution)

		c.SendMessage(&ClientMessage{
			MessageId: MessageHandshakeSolution,
			Buffer:    buf[:],
		})
		c.SentHandshakeSolution.Store(true)
	}
}

// Read reads from underlying connection, on error it will Close
func (c *Client) Read(buf []byte) (n int, err error) {
	if n, err = c.Connection.Read(buf); err != nil {
		c.Close()
	}
	return
}

type ClientMessage struct {
	MessageId MessageId
	Buffer    []byte
}

func (c *Client) SendMessage(message *ClientMessage) {
	if !c.Closed.Load() {
		bufLen := len(message.Buffer) + 1
		if bufLen > MaxBufferSize {
			utils.Logf("P2PClient", "Peer %s tried to send more than %d bytes, sent %d, disconnecting", c.HostPort, MaxBufferSize, len(message.Buffer)+1)
			c.Close()
			return
		}

		buf := getBuffer(bufLen)
		defer returnBuffer(buf)
		buf[0] = byte(message.MessageId)
		copy(buf[1:], message.Buffer)
		//c.sendLock.Lock()
		//defer c.sendLock.Unlock()
		if err := c.Connection.SetWriteDeadline(time.Now().Add(time.Second * 5)); err != nil {
			c.Close()
		} else if _, err = c.Connection.Write(buf[:bufLen]); err != nil {
			c.Close()
		}
		//_, _ = c.Write(message.Buffer)
	}
}

// ReadByte reads from underlying connection, on error it will Close
func (c *Client) ReadByte() (b byte, err error) {
	var buf [1]byte
	if _, err = c.Connection.Read(buf[:]); err != nil && c.Closed.Load() {
		c.Close()
	}
	return buf[0], err
}

func (c *Client) Close() bool {
	if c.Closed.Swap(true) {
		return false
	}

	if !c.HandshakeComplete.Load() {
		c.Ban(DefaultBanTime, errors.New("disconnected before finishing handshake"))
	}

	func() {
		c.Owner.clientsLock.Lock()
		defer c.Owner.clientsLock.Unlock()
		if c.Owner.fastestPeer == c {
			c.Owner.fastestPeer = nil
		}
		if i := slices.Index(c.Owner.clients, c); i != -1 {
			c.Owner.clients = slices.Delete(c.Owner.clients, i, i+1)
			if c.IsIncomingConnection {
				c.Owner.NumIncomingConnections.Add(-1)
			} else {
				c.Owner.NumOutgoingConnections.Add(-1)
				c.Owner.PendingOutgoingConnections.Replace(c.HostPort.Host, "")
			}
		}
	}()

	_ = c.Connection.Close()
	close(c.closeChannel)

	utils.Logf("P2PClient", "Peer %s connection closed", c.HostPort.String())
	return true
}
