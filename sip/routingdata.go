package sip

import (
	"SRGo/global"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sync"
)

type (
	RDB struct {
		UserpartPattern string      `json:"userpartPattern"`
		RD              RoutingData `json:"routingData"`
	}

	RoutingData struct {
		InRegex   *regexp.Regexp `json:"-"`
		RemoteUDP *net.UDPAddr   `json:"-"`
		IsDB      bool           `json:"-"`

		NoAnswerTimeout int `json:"noAnswerTimeout"`
		No18xTimeout    int `json:"no18xTimeout"`
		MaxCallDuration int `json:"maxCallDuration"`

		OutRuriUserpart string `json:"outRuriUserpart"`
		OutRuriHostport string `json:"outRuriHostport"`

		OutCallFlow CallFlow `json:"outCallFlow"`
	}

	CallFlow string

	RoutingEngine struct {
		mu       sync.RWMutex
		routings []*RoutingData
	}
)

const (
	Transparent           CallFlow = "Transparent"
	TransformEarlyToFinal CallFlow = "TransformEarlyToFinal"
)

func NewRoutingEngine() *RoutingEngine {
	return &RoutingEngine{}
}

func (re *RoutingEngine) ReloadConfig() {
	data := readJsonFile()
	re.ReadConfig(data)
}

func (re *RoutingEngine) ReadConfig(data []byte) {
	re.mu.Lock()
	defer re.mu.Unlock()

	var rdp []RDB
	if err := json.Unmarshal(data, &rdp); err != nil {
		return
	}

	total := len(rdp)

	re.routings = make([]*RoutingData, 0, total)

	fmt.Println("Loading Routing DB...")
	for _, r := range rdp {
		if r.RD.No18xTimeout <= 0 && r.RD.NoAnswerTimeout <= 0 {
			fmt.Println("Both No18xTimeout and NoAnswerTimeout are disabled - Skipped")
			continue
		}
		upRegex, err := regexp.Compile(r.UserpartPattern)
		if err != nil {
			fmt.Println("Invalid UserpartPattern - ", err.Error())
			continue
		}
		r.RD.InRegex = upRegex
		if r.RD.OutRuriHostport != "" {
			uaddr, ok := global.BuildUdpAddr(r.RD.OutRuriHostport, global.SipPort)
			if !ok {
				fmt.Println("Bad OutRURIHostport - Skipped")
				continue
			}
			r.RD.RemoteUDP = uaddr
		}
		r.RD.IsDB = true
		re.routings = append(re.routings, &r.RD)
	}

	fmt.Printf("Routing DB loaded: Total: %d, Valid: %d\n", total, len(re.routings))
}

func (re *RoutingEngine) Get(userpart string) (*RoutingData, string) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for _, rd := range re.routings {
		if up, ok := global.TranslatePattern(userpart, rd.InRegex, rd.OutRuriUserpart); ok {
			return rd, up
		}
	}

	return nil, ""
}
