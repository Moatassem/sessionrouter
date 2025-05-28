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
	RawRoutingRecord struct {
		UserpartPattern string        `json:"userpartPattern"`
		RD              RoutingRecord `json:"routingRecord"`
	}

	RoutingRecord struct {
		InRegex         *regexp.Regexp `json:"-"`
		RemoteUDP       *net.UDPAddr   `json:"-"`
		IsDB            bool           `json:"-"`
		UserpartPattern string         `json:"userpartPattern"`

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
		routings []*RoutingRecord
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

	var rdp []RawRoutingRecord
	if err := json.Unmarshal(data, &rdp); err != nil {
		return
	}

	total := len(rdp)

	re.routings = make([]*RoutingRecord, 0, total)

	fmt.Println("Loading Routing DB...")
	for _, r := range rdp {
		if r.RD.No18xTimeout <= 0 && r.RD.NoAnswerTimeout <= 0 {
			fmt.Println("Both No18xTimeout and NoAnswerTimeout are disabled - Skipped")
			continue
		}
		upRegex, err := regexp.Compile(r.UserpartPattern)
		if err != nil {
			fmt.Printf("Invalid UserpartPattern: %s - Skipped\n", err.Error())
			continue
		}
		r.RD.UserpartPattern = upRegex.String()
		r.RD.InRegex = upRegex
		if r.RD.OutRuriHostport != "" {
			uaddr, ok := global.BuildUdpAddr(r.RD.OutRuriHostport, global.SipPort)
			if !ok {
				fmt.Printf("Bad OutRuriHostport: %s - Skipped\n", r.RD.OutRuriHostport)
				continue
			}
			r.RD.RemoteUDP = uaddr
		}
		r.RD.IsDB = true
		re.routings = append(re.routings, &r.RD)
	}

	fmt.Printf("Routing DB loaded: Total: %d, Valid: %d\n", total, len(re.routings))
}

func (re *RoutingEngine) Get(userpart string) (*RoutingRecord, string) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	for _, rd := range re.routings {
		if up, ok := global.TranslatePattern(userpart, rd.InRegex, rd.OutRuriUserpart); ok {
			return rd, up
		}
	}

	return nil, ""
}

func (re *RoutingEngine) MarshalJSON() ([]byte, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	return json.Marshal(re.routings)
}
