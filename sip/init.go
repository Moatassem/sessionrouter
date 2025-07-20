package sip

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"SRGo/cl"
	. "SRGo/global"
	"SRGo/phone"
)

type (
	DscpValue = int
)

const (
	// Choose DSCP values (shift left by 2 bits for TOS field)
	DscpCS3  DscpValue = 24 << 2 // SIP
	DscpCS5  DscpValue = 40 << 2 // SIP
	DscpAF31 DscpValue = 26 << 2 // SIP
	DscpAF41 DscpValue = 34 << 2 // SIP
	DscpEF   DscpValue = 46 << 2 // RTP
)

var (
	Sessions                  ConcurrentMapMutex[*SipSession]
	ASUserAgent               *SipUdpUserAgent
	SkipAS                    bool
	ProbingInterval           int // seconds
	IndialogueProbingInterval int // seconds
	sippTesting               bool
	ProxyUdpServer            *net.UDPAddr
	RoutingEngineDB           *RoutingEngine
	ServerIPv4                net.IP
)

func readJsonFile() []byte {
	fmt.Print("Locating Routing DB...")

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error getting executable path:", err)
		return nil
	}
	exeDir := filepath.Dir(exePath)

	jsonPath := filepath.Join(exeDir, "rdb.json")

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return nil
	}

	fmt.Println("Found:", jsonPath)

	return data
}

func StartServer(asUdpskt *UdpSocket, ipv4 string, sup, kai, htp, indint int, uproxy string) *net.UDPConn {
	fmt.Print("Initializing System...")

	Sessions = NewConcurrentMapMutex[*SipSession](QueueSize)

	SkipAS = asUdpskt == nil
	ASUserAgent = NewSipUdpUserAgentFromSocket(asUdpskt)

	InitializeEngine()
	MediaPortPool = NewMediaPortPool()

	fmt.Println("Done")

	if SkipAS {
		RoutingEngineDB = NewRoutingEngine()
		RoutingEngineDB.ReloadConfig()
	}

	SipUdpPort = sup
	HttpTcpPort = htp
	ProbingInterval = kai

	if indint == -1 {
		IndialogueProbingInterval = IdProbingSec
	} else {
		IndialogueProbingInterval = indint
		sippTesting = true
		LogInfo(LTConfiguration, "Custom In-Dialogue Probing provided - SIPp testing mode activated")
	}

	if uproxy != "" {
		if prxy, ok := BuildUdpAddr(uproxy, SipPort); !ok {
			LogWarning(LTConfiguration, fmt.Sprintf("Bad Proxy UDP Server specified [%s] - Ignored", uproxy))
		} else {
			ProxyUdpServer = prxy
			LogInfo(LTConfiguration, fmt.Sprintf("Proxy UDP Server provided [%s] - Proxy mode activated", uproxy))
		}
	}

	if ipv4 == "" {
		serverIPs, err := GetLocalIPs()
		if err != nil || len(serverIPs) == 0 {
			LogWarning(LTConfiguration, "No self IPv4 address provided!")
		}
		ServerIPv4 = serverIPs[0]
	} else {
		ServerIPv4 = net.ParseIP(ipv4)
	}

	fmt.Print("Attempting to listen on SIP...")
	serverUDPListener, err := StartListening(ServerIPv4, SipUdpPort, DscpAF41)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	startWorkers(serverUDPListener)
	udpLoopWorkers(serverUDPListener)
	fmt.Println("Success: UDP", serverUDPListener.LocalAddr().String())

	fmt.Print("Starting SIP Probing...")
	go periodicUAProbing(serverUDPListener)
	fmt.Println("Done")

	fmt.Print("Setting Rate Limiter...")
	CallLimiter = cl.NewCallLimiter(RateLimit, Prometrics, &WtGrp)
	fmt.Println("Done:", ratelimitStringer())

	return serverUDPListener
}

func ratelimitStringer() string {
	switch RateLimit {
	case -1:
		return "Unlimited CAPS"
	case 0:
		return "No Calls Allowed!"
	default:
		return fmt.Sprintf("%d CAPS", RateLimit)
	}
}

func periodicUAProbing(conn *net.UDPConn) {
	WtGrp.Add(1)
	defer WtGrp.Done()
	ticker := time.NewTicker(time.Duration(ProbingInterval) * time.Second)
	for range ticker.C {
		ProbeUA(conn, ASUserAgent)
		for _, phne := range phone.Phones.All() {
			if phne.IsReachable && phne.IsRegistered {
				ProbeUA(conn, phne.GetUA())
			}
		}
	}
}

// =================================================================================================
// Worker Pattern

var (
	WorkerCount = runtime.NumCPU()
	QueueSize   = 2500
	packetQueue = make(chan Packet, QueueSize)
)

type Packet struct {
	sourceAddr *net.UDPAddr
	buffer     *[]byte
	bytesCount int
}

func startWorkers(conn *net.UDPConn) {
	// Start worker pool
	WtGrp.Add(WorkerCount)
	for range WorkerCount {
		go worker(conn, packetQueue)
	}
}

func udpLoopWorkers(conn *net.UDPConn) {
	WtGrp.Add(1)
	go func() {
		defer WtGrp.Done()
		for {
			buf, _ := BufferPool.Get().(*[]byte)
			n, addr, err := conn.ReadFromUDP(*buf)
			if err != nil {
				fmt.Println(err)
				continue
			}
			packetQueue <- Packet{sourceAddr: addr, buffer: buf, bytesCount: n}
		}
	}()
}

func worker(conn *net.UDPConn, queue <-chan Packet) {
	defer WtGrp.Done()
	for packet := range queue {
		processPacket(packet, conn)
	}
}

func processPacket(packet Packet, conn *net.UDPConn) {
	pdu := (*packet.buffer)[:packet.bytesCount]
	for len(pdu) > 0 {
		msg, pdutmp, err := processPDU(pdu)
		if err != nil {
			// fmt.Println("Bad PDU -", err)
			// fmt.Println(string(pdu))
			break
		} else if msg == nil {
			break
		}
		pdu = pdutmp
		ss, newSesType := sessionGetter(msg)
		if ss != nil {
			ss.SetRemoteUDPnListenser(packet.sourceAddr, conn)
		}
		sipStack(msg, ss, newSesType)
	}
	BufferPool.Put(packet.buffer)
}
