package sip

import (
	"fmt"

	. "SRGo/global"
)

// -------------------------------------------

type StartLine struct {
	UserParameters map[string]string
	UriParameters  map[string]string
	UriScheme      string
	UserPart       string
	OriginalUP     string
	HostPart       string
	Password       string
	ReasonPhrase   string
	RUri           string
	UriHeaders     string
	Method         Method
	StatusCode     int
}

func (ssl *StartLine) BuildRURI(useOriginalUP bool) {
	var up string
	if useOriginalUP {
		up = ssl.OriginalUP
	} else {
		up = ssl.UserPart
	}
	if up == "" {
		ssl.RUri = fmt.Sprintf("%s:%s%s%s", ssl.UriScheme, ssl.HostPart, GenerateParameters(ssl.UriParameters), ssl.UriHeaders)
		return
	}
	ssl.RUri = fmt.Sprintf("%s:%s%s%s@%s%s%s", ssl.UriScheme, up, GenerateParameters(ssl.UserParameters), ssl.Password, ssl.HostPart, GenerateParameters(ssl.UriParameters), ssl.UriHeaders)
}

func (ssl *StartLine) GetStartLine(mt MessageType) string {
	if mt == REQUEST {
		return fmt.Sprintf("%s %s %s\r\n", ssl.Method.String(), ssl.RUri, SipVersion)
	}
	return fmt.Sprintf("%s %d %s\r\n", SipVersion, ssl.StatusCode, ssl.ReasonPhrase)
}

type RequestPack struct {
	CustomHeaders SipHeaders
	RUriUP        string
	FromUP        string
	Method        Method
	Max70         bool
	IsProbing     bool
}

type ResponsePack struct {
	CustomHeaders  SipHeaders
	LinkedPRACKST  *Transaction
	ReasonPhrase   string
	ContactHeader  string
	StatusCode     int
	PRACKRequested bool
}

func NewResponsePackRFWarning(stc int, rsnphrs, warning string) ResponsePack {
	return ResponsePack{
		StatusCode:    stc,
		ReasonPhrase:  rsnphrs,
		CustomHeaders: NewSHQ850OrSIP(0, warning, ""),
	}
}

// reason != "" ==> Warning & Reason headers are always created.
//
// reason == "" ==>
//
// stc == 0 ==> only Warning header
//
// stc != 0 ==> only Reason header
func NewResponsePackSRW(stc int, warning string, reason string) ResponsePack {
	var hdrs SipHeaders
	if reason == "" {
		hdrs = NewSHQ850OrSIP(stc, warning, "")
	} else {
		hdrs = NewSHQ850OrSIP(0, warning, "")
		hdrs.SetHeader(Reason, reason)
	}
	return ResponsePack{
		StatusCode:    stc,
		CustomHeaders: hdrs,
	}
}

func NewResponsePackSIPQ850Details(stc, q850c int, details string) ResponsePack {
	hdrs := NewSHQ850OrSIP(q850c, details, "")
	return ResponsePack{
		StatusCode:    stc,
		CustomHeaders: hdrs,
	}
}

func NewResponsePackWarning(stc int, warning string) ResponsePack {
	hdrs := NewSHQ850OrSIP(0, warning, "")
	return ResponsePack{
		StatusCode:    stc,
		CustomHeaders: hdrs,
	}
}
