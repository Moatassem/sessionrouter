package phone

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"sync"

	"SRGo/global"
	"SRGo/sip/state"
)

var Phones = NewIPPhoneRepo()

type IPPhoneRepo struct {
	phones map[string]*IPPhone
	mu     sync.RWMutex
}

func NewIPPhoneRepo() *IPPhoneRepo {
	return &IPPhoneRepo{phones: make(map[string]*IPPhone)}
}

func (r *IPPhoneRepo) IsPhoneExt(ext string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.phones[ext]
	return ok
}

func (r *IPPhoneRepo) Get(ext string) (*IPPhone, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	phone, ok := r.phones[ext]
	return phone, ok
}

func (r *IPPhoneRepo) AddOrUpdate(ext, ruri, ipport string, expires int) state.SessionState {
	r.mu.Lock()
	defer r.mu.Unlock()
	phone, ok := r.phones[ext]
	if !ok {
		phone = &IPPhone{Extension: ext, RURI: ruri}
		r.phones[ext] = phone
	}
	ua := phone.GetUA()
	if ua != nil && ua.GetUDPAddrString() == ipport {
		goto finish
	}
	{
		phone.IsReachable = true
		udpaddr, ok := global.BuildUdpAddr(ipport, global.SipPort)
		if !ok {
			log.Println("Error resolving UDP address")
			phone.IsReachable = false
			phone.SetUA(nil)
			goto finish
		}
		phone.SetUA(global.NewSipUdpUserAgent(udpaddr))
	}
finish:
	phone.IsRegistered = expires > 0
	log.Printf("IPPhone: [%s]\n", phone)
	if phone.IsRegistered {
		return state.Registered
	}
	return state.Unregistered
}

func (r *IPPhoneRepo) Remove(ext string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.phones, ext)
}

func (r *IPPhoneRepo) All() []*IPPhone {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Collect(maps.Values(r.phones))
}

// =================================================================================================

type IPPhone struct {
	UA           *global.SipUdpUserAgent `json:"-"`
	Extension    string                  `json:"extension"`
	RURI         string                  `json:"ruri"`
	IsReachable  bool                    `json:"isReachable"`
	IsRegistered bool                    `json:"isRegistered"`
	mu           sync.RWMutex            `json:"-"`
}

func (p *IPPhone) String() string {
	if p.UA != nil {
		return fmt.Sprintf(`Extension: %s, RURI: %s, IsRegistered: %t, %s`, p.Extension, p.RURI, p.IsRegistered, p.UA.String())
	}
	return fmt.Sprintf(`Extension: %s, RURI: %s, IsRegistered: %t`, p.Extension, p.RURI, p.IsRegistered)
}

func (p *IPPhone) SetUA(ua *global.SipUdpUserAgent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.UA = ua
}

func (p *IPPhone) GetUA() *global.SipUdpUserAgent {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.UA
}
