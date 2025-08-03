package sip

import (
	"SRGo/global"
	"fmt"
	"log"
	"net"

	"sync"
)

var MediaPortPool *MediaPool

type MediaPool struct {
	alloc map[int]bool
	mu    sync.Mutex
}

func NewMediaPortPool() *MediaPool {
	mpp := &MediaPool{alloc: make(map[int]bool, global.MediaEndPort-global.MediaStartPort+1)}
	for port := global.MediaStartPort; port <= global.MediaEndPort; port++ {
		mpp.alloc[port] = false
	}
	return mpp
}

func (mpp *MediaPool) ReserveSocket() *net.UDPConn {
	mpp.mu.Lock()
	defer mpp.mu.Unlock()
	for port, used := range mpp.alloc {
		if !used {
			socket, err := global.StartListening(ServerIPv4, port, DscpEF)
			if err != nil {
				continue
			}
			mpp.alloc[port] = true
			return socket
		}
	}
	log.Printf("No available ports for IPv4 %s\n", ServerIPv4)
	return nil
}

func (mpp *MediaPool) ReleaseSocket(conn *net.UDPConn) bool {
	if conn == nil {
		return true
	}
	port := global.GetUDPortFromConn(conn)
	conn.Close()

	mpp.mu.Lock()
	defer mpp.mu.Unlock()

	if mpp.alloc[port] {
		mpp.alloc[port] = false
		return true
	}
	global.LogWarning(global.LTMediaStack, fmt.Sprintf("Port [%d] already released!\n", port))
	return false
}
