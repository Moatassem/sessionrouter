package main

import (
	"SRGo/global"
	"SRGo/prometheus"
	"SRGo/sip"
	"SRGo/webserver"
	"fmt"
	"log"
	"os"
)

// environment variables
//
//nolint:revive
const (
	AS_SIP_UdpIpPort    string = "as_sip_udp"
	Own_IP_IPv4         string = "server_ipv4"
	Own_SIP_UdpPort     string = "sip_udp_port"
	Own_Http_Port       string = "http_port"
	KeepAlive_Interval  string = "ka_interval"
	AutoServerIPv4      string = "auto_server_ipv4"
	InDialogue_Interval string = "indialogue_interval"
	ProxyUdpServer      string = "proxy_udp_server"
)

func main() {
	greeting()

	global.Prometrics = prometheus.NewMetrics(global.B2BUANameVersion)
	conn := sip.StartServer(checkArgs())

	defer conn.Close() // close SIP server connection

	webserver.StartWS()
	global.WtGrp.Wait()
}

func greeting() {
	global.LogInfo(global.LTSystem, fmt.Sprintf("Welcome to %s - Product of %s 2025", global.B2BUANameVersion, global.ASCIIPascal(global.EntityName)))
}

func checkArgs() (*global.UdpSocket, string, int, int, int, int, string) {
	var (
		udpskt                                   *global.UdpSocket
		sipuport, kaInter, httpport, indiagInter int
	)

	siplyr, ok := os.LookupEnv(AS_SIP_UdpIpPort)
	if !ok {
		global.LogWarning(global.LTConfiguration, "No AS address provided! - Switching to internal Routing Engine")
		goto skipAS
	}

	{
		var err error
		if udpskt, err = global.BuildUdpSocket(siplyr, global.SipPort); err != nil {
			log.Println("Error resolving AS UDP address:", err)
			os.Exit(1)
		}
		global.LogInfo(global.LTConfiguration, fmt.Sprintf("AS Routing: [%s]", siplyr))
	}

skipAS:
	ipv4, ok := os.LookupEnv(Own_IP_IPv4)
	if !ok {
		if _, ok = os.LookupEnv(AutoServerIPv4); !ok {
			global.LogWarning(global.LTConfiguration, "No self IPv4 address provided and 'auto_server_ipv4' not specified")
			os.Exit(1)
		}
	}

	proxyserver := os.Getenv(ProxyUdpServer)

	if indiag, ok := os.LookupEnv(InDialogue_Interval); ok {
		indiagInter = global.Str2Int[int](indiag)
	} else {
		indiagInter = -1
	}

	sup := os.Getenv(Own_SIP_UdpPort)
	//nolint:mnd
	sipuport, _ = global.Str2IntDefaultMinMax(sup, 5060, 5000, 6000)

	hp := os.Getenv(Own_Http_Port)
	//nolint:mnd
	httpport, _ = global.Str2IntDefaultMinMax(hp, 8080, 80, 9080)

	kai := os.Getenv(KeepAlive_Interval)
	//nolint:mnd
	kaInter, ok = global.Str2IntDefaultMinMax(kai, global.OodProbingSec, 5, 9999999)
	if ok {
		global.LogInfo(global.LTConfiguration, fmt.Sprintf("Setting KeepAlive interval [%d]", kaInter))
	} else {
		kaInter = global.OodProbingSec
		global.LogWarning(global.LTConfiguration, fmt.Sprintf("Setting default KeepAlive interval [%d]", kaInter))
	}

	return udpskt, ipv4, sipuport, kaInter, httpport, indiagInter, proxyserver
}
