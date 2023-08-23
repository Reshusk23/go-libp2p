package udpmux

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	logging "github.com/ipfs/go-log/v2"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/pion/ice/v2"
	"github.com/pion/stun"
)

var log = logging.Logger("webrtc-udpmux")

const ReceiveMTU = 1500

// UDPMux multiplexes multiple ICE connections over a single net.PacketConn,
// generally a UDP socket.
//
// The connections are indexed by (ufrag, IP address family) and by remote
// address from which the connection has received valid STUN/RTC packets.
//
// When a new packet is received on the underlying net.PacketConn, we
// first check the address map to see if there is a connection associated with the
// remote address:
// If found, we pass the packet to that connection.
// Otherwise, we check to see if the packet is a STUN packet.
// If it is, we read the ufrag from the STUN packet and use it to check if there
// is a connection associated with the (ufrag, IP address family) pair.
// If found we add the association to the address map.
// Otherwise, this is a previously unseen IP address and the unknownUfragCallback
// callback is called.
type UDPMux struct {
	socket               net.PacketConn
	unknownUfragCallback func(string, net.Addr) error

	storage *udpMuxStorage

	// the context controls the lifecycle of the mux
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

var _ ice.UDPMux = &UDPMux{}

func NewUDPMux(socket net.PacketConn, unknownUfragCallback func(string, net.Addr) error) *UDPMux {
	ctx, cancel := context.WithCancel(context.Background())
	mux := &UDPMux{
		ctx:                  ctx,
		cancel:               cancel,
		socket:               socket,
		unknownUfragCallback: unknownUfragCallback,
		storage:              newUDPMuxStorage(),
	}

	return mux
}

func (mux *UDPMux) Start() {
	mux.wg.Add(1)
	go func() {
		defer mux.wg.Done()
		mux.readLoop()
	}()
}

// GetListenAddresses implements ice.UDPMux
func (mux *UDPMux) GetListenAddresses() []net.Addr {
	return []net.Addr{mux.socket.LocalAddr()}
}

// GetConn implements ice.UDPMux
// It creates a net.PacketConn for a given ufrag if an existing
// one cannot be  found. We differentiate IPv4 and IPv6 addresses
// as a remote is capable of being reachable through multiple different
// UDP addresses of the same IP address family (eg. Server-reflexive addresses
// and peer-reflexive addresses).
func (mux *UDPMux) GetConn(ufrag string, addr net.Addr) (net.PacketConn, error) {
	a, ok := addr.(*net.UDPAddr)
	if !ok && addr != nil {
		return nil, fmt.Errorf("unexpected address type: %T", addr)
	}
	isIPv6 := ok && a.IP.To4() == nil
	return mux.getOrCreateConn(ufrag, isIPv6, addr)
}

// Close implements ice.UDPMux
func (mux *UDPMux) Close() error {
	select {
	case <-mux.ctx.Done():
		return nil
	default:
	}
	mux.cancel()
	mux.socket.Close()
	mux.wg.Wait()
	return nil
}

// RemoveConnByUfrag implements ice.UDPMux
func (mux *UDPMux) RemoveConnByUfrag(ufrag string) {
	if ufrag != "" {
		mux.storage.RemoveConnByUfrag(ufrag)
	}
}

func (mux *UDPMux) getOrCreateConn(ufrag string, isIPv6 bool, addr net.Addr) (net.PacketConn, error) {
	select {
	case <-mux.ctx.Done():
		return nil, io.ErrClosedPipe
	default:
		_, conn := mux.storage.GetOrCreateConn(ufrag, isIPv6, mux, addr)
		return conn, nil
	}
}

// writeTo writes a packet to the underlying net.PacketConn
func (mux *UDPMux) writeTo(buf []byte, addr net.Addr) (int, error) {
	return mux.socket.WriteTo(buf, addr)
}

func (mux *UDPMux) readLoop() {
	for {
		select {
		case <-mux.ctx.Done():
			return
		default:
		}

		buf := pool.Get(ReceiveMTU)

		n, addr, err := mux.socket.ReadFrom(buf)
		if err != nil {
			log.Errorf("error reading from socket: %v", err)
			pool.Put(buf)
			return
		}
		buf = buf[:n]

		if processed := mux.processPacket(buf, addr); !processed {
			pool.Put(buf)
		}
	}
}

func (mux *UDPMux) processPacket(buf []byte, addr net.Addr) (processed bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		log.Errorf("received a non-UDP address: %s", addr)
		return false
	}
	isIPv6 := udpAddr.IP.To4() == nil

	// Connections are indexed by remote address. We first
	// check if the remote address has a connection associated
	// with it. If yes, we push the received packet to the connection
	if conn, ok := mux.storage.GetConnByAddr(udpAddr); ok {
		if err := conn.Push(buf); err != nil {
			log.Debugf("could not push packet: %v", err)
			return false
		}
		return true
	}

	if !stun.IsMessage(buf) {
		log.Debug("incoming message is not a STUN message")
		return false
	}

	msg := &stun.Message{Raw: buf}
	if err := msg.Decode(); err != nil {
		log.Debugf("failed to decode STUN message: %s", err)
		return false
	}
	if msg.Type != stun.BindingRequest {
		log.Debugf("incoming message should be a STUN binding request, got %s", msg.Type)
		return false
	}

	ufrag, err := ufragFromSTUNMessage(msg)
	if err != nil {
		log.Debugf("could not find STUN username: %s", err)
		return false
	}

	connCreated, conn := mux.storage.GetOrCreateConn(ufrag, isIPv6, mux, udpAddr)
	if connCreated {
		if err := mux.unknownUfragCallback(ufrag, udpAddr); err != nil {
			log.Debugf("creating connection failed: %s", err)
			conn.Close()
			return false
		}
	}

	if err := conn.Push(buf); err != nil {
		log.Debugf("could not push packet: %v", err)
		return false
	}
	return true
}

type ufragConnKey struct {
	ufrag  string
	isIPv6 bool
}

// ufragFromSTUNMessage returns the local or ufrag
// from the STUN username attribute. Local ufrag is the ufrag of the
// peer which initiated the connectivity check, e.g in a connectivity
// check from A to B, the username attribute will be B_ufrag:A_ufrag
// with the local ufrag value being A_ufrag. In case of ice-lite, the
// localUfrag value will always be the remote peer's ufrag since ICE-lite
// implementations do not generate connectivity checks. In our specific
// case, since the local and remote ufrag is equal, we can return
// either value.
func ufragFromSTUNMessage(msg *stun.Message) (string, error) {
	attr, err := msg.Get(stun.AttrUsername)
	if err != nil {
		return "", err
	}
	index := bytes.Index(attr, []byte{':'})
	if index == -1 {
		return "", fmt.Errorf("invalid STUN username attribute")
	}
	return string(attr[index+1:]), nil
}

type udpMuxStorage struct {
	sync.Mutex

	ufragMap map[ufragConnKey]*muxedConnection
	addrMap  map[string]*muxedConnection
}

func newUDPMuxStorage() *udpMuxStorage {
	return &udpMuxStorage{
		ufragMap: make(map[ufragConnKey]*muxedConnection),
		addrMap:  make(map[string]*muxedConnection),
	}
}

func (s *udpMuxStorage) RemoveConnByUfrag(ufrag string) {
	s.Lock()
	defer s.Unlock()

	for _, isIPv6 := range [...]bool{true, false} {
		key := ufragConnKey{ufrag: ufrag, isIPv6: isIPv6}
		if conn, ok := s.ufragMap[key]; ok {
			delete(s.ufragMap, key)
			delete(s.addrMap, conn.Address().String())
		}
	}
}

func (s *udpMuxStorage) GetOrCreateConn(ufrag string, isIPv6 bool, mux *UDPMux, addr net.Addr) (created bool, _ *muxedConnection) {
	key := ufragConnKey{ufrag: ufrag, isIPv6: isIPv6}

	s.Lock()
	defer s.Unlock()

	if conn, ok := s.ufragMap[key]; ok {
		return false, conn
	}

	conn := newMuxedConnection(mux, func() { s.RemoveConnByUfrag(ufrag) }, addr)
	s.ufragMap[key] = conn
	s.addrMap[addr.String()] = conn

	return true, conn
}

func (s *udpMuxStorage) GetConnByAddr(addr *net.UDPAddr) (*muxedConnection, bool) {
	s.Lock()
	conn, ok := s.addrMap[addr.String()]
	s.Unlock()
	return conn, ok
}
