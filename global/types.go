package global

import (
	"cmp"
	"fmt"
	"net"
	"strings"
	"sync"
)

type UdpSocket struct {
	addr     *net.UDPAddr
	hostOrIP *string
	port     *int
}

func BuildUdpSocketFromAddr(addr *net.UDPAddr) (*UdpSocket, error) {
	if addr == nil {
		return nil, fmt.Errorf("nil UDP address provided")
	}

	hostOrIP := addr.IP.String()
	port := addr.Port

	if port <= 0 || port > MaxPort {
		return nil, fmt.Errorf("invalid port number: %d", port)
	}

	return &UdpSocket{addr: addr, hostOrIP: &hostOrIP, port: &port}, nil
}

func BuildUdpSocket(ipsocket string, defaultport int) (*UdpSocket, error) {
	part1, part2, ok := strings.Cut(ipsocket, ":")
	var prt int
	if ok {
		prt = Str2Int[int](part2)
		if prt <= 0 || prt > MaxPort {
			return nil, fmt.Errorf("invalid port number: %d", prt)
		}
		prt = cmp.Or(prt, defaultport)
	}
	prt = cmp.Or(prt, defaultport)

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", part1, prt))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address %s: %w", ipsocket, err)
	}

	return &UdpSocket{addr: addr, hostOrIP: &part1, port: &prt}, nil
}

func (us *UdpSocket) UDPAddr() *net.UDPAddr {
	if us.addr == nil {
		return nil
	}
	return us.addr
}

func (us *UdpSocket) String() string {
	if us.hostOrIP == nil || us.port == nil {
		return ""
	}
	if *us.port == SipPort {
		return *us.hostOrIP
	}
	return fmt.Sprintf("%s:%d", *us.hostOrIP, *us.port)
}

// =========================================================================================================

type SystemError struct {
	Code    int
	Details string
}

func NewError(code int, details string) error {
	return &SystemError{Code: code, Details: details}
}

func (se *SystemError) Error() string {
	return fmt.Sprintf("Code: %d - Details: %s", se.Code, se.Details)
}

type SipUdpUserAgent struct {
	mu      sync.RWMutex
	udpSkt  *UdpSocket
	isAlive bool
}

func NewSipUdpUserAgentFromSocket(udpskt *UdpSocket) *SipUdpUserAgent {
	if udpskt == nil {
		return nil
	}
	return &SipUdpUserAgent{udpSkt: udpskt}
}

func NewSipUdpUserAgent(udpaddr *net.UDPAddr) *SipUdpUserAgent {
	if udpaddr == nil {
		return nil
	}
	skt, err := BuildUdpSocketFromAddr(udpaddr)
	if err != nil {
		fmt.Println("Error creating UDP socket:", err)
		return nil
	}
	return &SipUdpUserAgent{udpSkt: skt}
}

func (ua *SipUdpUserAgent) SetAlive(alive bool) {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	ua.isAlive = alive
}

func (ua *SipUdpUserAgent) IsAlive() bool {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return ua.isAlive
}

func (ua *SipUdpUserAgent) GetUDPSocket() *UdpSocket {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return ua.udpSkt
}

func (ua *SipUdpUserAgent) GetUDPAddr() *net.UDPAddr {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return ua.udpSkt.addr
}

func (ua *SipUdpUserAgent) SetUDPAddr(udpAddr *net.UDPAddr) {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	skt, _ := BuildUdpSocketFromAddr(udpAddr)
	ua.udpSkt = skt
}

func (ua *SipUdpUserAgent) String() string {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return fmt.Sprintf("UDPAddr: %s, IsAlive: %t", ua.udpSkt.String(), ua.isAlive)
}

func (ua *SipUdpUserAgent) GetUDPAddrString() string {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return ua.udpSkt.String()
}
