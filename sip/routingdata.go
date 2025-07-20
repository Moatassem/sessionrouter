package sip

import (
	"SRGo/global"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
)

type (
	RoutingRecord struct {
		InRegex         *regexp.Regexp    `json:"-"`
		RemoteUDPSocket *global.UdpSocket `json:"-"`
		IsDB            bool              `json:"-"`
		UserpartPattern string            `json:"userpartPattern"`

		NoAnswerTimeout int `json:"noAnswerTimeout"`
		No18xTimeout    int `json:"no18xTimeout"`
		MaxCallDuration int `json:"maxCallDuration"`

		DisallowDifferent18x bool `json:"disallowDifferent18x"` // for 18x responses, if false, multiple different 18x responses can be sent
		DisallowSimilar18x   bool `json:"disallowSimilar18x"`   // for 18x responses, if false, multiple similar 18x responses can be sent

		SteerMedia bool `json:"steerMedia"`

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
	EchoResponder         CallFlow = "EchoResponder"
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

	var rdp []struct {
		UserpartPattern string        `json:"userpartPattern"`
		RD              RoutingRecord `json:"routingRecord"`
	}
	if err := json.Unmarshal(data, &rdp); err != nil {
		return
	}

	total := len(rdp)

	re.routings = make([]*RoutingRecord, 0, total)

	fmt.Print("Loading Routing DB...")
	for _, r := range rdp {
		if r.RD.OutCallFlow != EchoResponder && r.RD.No18xTimeout <= 0 && r.RD.NoAnswerTimeout <= 0 {
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
			uaddr, err := global.BuildUdpSocket(r.RD.OutRuriHostport, global.SipPort)
			if err != nil {
				fmt.Printf("Bad OutRuriHostport: %s (%q) - Skipped\n", r.RD.OutRuriHostport, err)
				continue
			}
			r.RD.RemoteUDPSocket = uaddr
		}
		r.RD.IsDB = true
		re.routings = append(re.routings, &r.RD)
	}

	fmt.Printf("Done: Total Records: %d, Valid Records: %d\n", total, len(re.routings))
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
