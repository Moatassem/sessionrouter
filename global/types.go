package global

import (
	"fmt"
	"net"
	"sync"
)

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
	udpAddr *net.UDPAddr
	isAlive bool
}

func NewSipUdpUserAgent(udpAddr *net.UDPAddr) *SipUdpUserAgent {
	if udpAddr == nil {
		return nil
	}
	return &SipUdpUserAgent{udpAddr: udpAddr}
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

func (ua *SipUdpUserAgent) GetUDPAddr() *net.UDPAddr {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return ua.udpAddr
}

func (ua *SipUdpUserAgent) SetUDPAddr(udpAddr *net.UDPAddr) {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	ua.udpAddr = udpAddr
}

func (ua *SipUdpUserAgent) String() string {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return fmt.Sprintf("UDPAddr: %s, IsAlive: %t", ua.udpAddr.String(), ua.isAlive)
}

func (ua *SipUdpUserAgent) GetUDPAddrString() string {
	ua.mu.RLock()
	defer ua.mu.RUnlock()
	return ua.udpAddr.String()
}
