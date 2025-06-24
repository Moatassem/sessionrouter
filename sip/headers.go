package sip

import (
	"fmt"
	"strings"

	. "SRGo/global"
)

type SipHeaders struct {
	_map map[string][]string
}

func NewSipHeaders() SipHeaders {
	return SipHeaders{_map: make(map[string][]string)}
}

func NewSHsFromMap(mp map[string][]string) SipHeaders {
	headers := NewSipHeaders()
	for k, v := range mp {
		headers.AddValues(k, v)
	}
	return headers
}

// Used mainly in outbound messages or when pointer is needed i.e. mutable
func NewSHsPointer(setDefaults bool) *SipHeaders {
	headers := NewSipHeaders()
	if setDefaults {
		headers.AddHeader(User_Agent, B2BUANameVersion)
		headers.AddHeader(Server, B2BUANameVersion)
		// headers.AddHeader(Allow, AllowedMethods)
	}
	return &headers
}

func NewSHQ850OrSIP(q850OrSip int, details string, retryAfter string) SipHeaders {
	headers := NewSipHeaders()
	if retryAfter != "" {
		headers.AddHeader(Retry_After, retryAfter)
	}
	if q850OrSip == 0 {
		if strings.TrimSpace(details) != "" {
			headers.AddHeader(Warning, fmt.Sprintf("399 %s \"%s\"", B2BUAName, details))
		}
	} else {
		var reason string
		if q850OrSip <= 127 {
			reason = "Q.850;cause=" + Int2Str(q850OrSip)
		} else {
			reason = "SIP;cause=" + Int2Str(q850OrSip)
		}
		if strings.TrimSpace(details) != "" {
			reason += fmt.Sprintf(";text=\"%s\"", details)
		}
		headers.AddHeader(Reason, reason)
	}
	return headers
}

// ==========================================

func (headers SipHeaders) InternalMap() map[string][]string {
	if headers._map == nil {
		return nil
	}
	return headers._map
}

// returns headers as lowercase
func (headers *SipHeaders) GetHeaderNames() []string {
	lst := make([]string, 0, len(headers._map))
	for h := range headers._map {
		lst = append(lst, h)
	}
	return lst
}

func (headers *SipHeaders) HeaderNameExists(header HeaderEnum) bool {
	return headers.HeaderExists(header.String())
}

// headerName is case insensitive
func (headers *SipHeaders) HeaderExists(headerName string) bool {
	headerName = ASCIIToLower(headerName)
	_, ok := headers._map[headerName]
	return ok
}

func (headers *SipHeaders) HeaderCount(headerName string) int {
	headerName = ASCIIToLower(headerName)
	v, ok := headers._map[headerName]
	if ok {
		return len(v)
	}
	return 0
}

func (headers *SipHeaders) DoesValueExistInHeader(headerName string, headerValue string) bool {
	headerValue = ASCIIToLower(headerValue)
	_, values := headers.Values(headerName)
	for _, hv := range values {
		if strings.Contains(ASCIIToLower(hv), headerValue) {
			return true
		}
	}
	return false
}

func (headers *SipHeaders) AddHeader(header HeaderEnum, headerValue string) {
	headers.Add(header.String(), headerValue)
}

func (headers *SipHeaders) AddHeaderValues(header HeaderEnum, headerValues []string) {
	headers.AddValues(header.String(), headerValues)
}

func (headers *SipHeaders) Add(headerName string, headerValue string) {
	headerName = ASCIIToLower(headerName)
	v := headers._map[headerName]
	headers._map[headerName] = append(v, headerValue)
}

func (headers *SipHeaders) AddValues(headerName string, headerValues []string) {
	headerName = ASCIIToLower(headerName)
	v := headers._map[headerName]
	headers._map[headerName] = append(v, headerValues...)
}

func (headers *SipHeaders) SetHeader(header HeaderEnum, headerValue string) {
	headers.Set(header.String(), headerValue)
}

func (headers *SipHeaders) Set(headerName string, headerValue string) {
	headerName = ASCIIToLower(headerName)
	headers._map[headerName] = []string{headerValue}
}

func (headers *SipHeaders) HeaderValues(header HeaderEnum) []string {
	_, values := headers.Values(header.String())
	return values
}

func (headers *SipHeaders) ValuesHeader(header HeaderEnum) (bool, []string) {
	return headers.Values(header.String())
}

func (headers *SipHeaders) Values(headerName string) (bool, []string) {
	headerName = ASCIIToLower(headerName)
	v, ok := headers._map[headerName]
	if ok {
		return true, v
	}

	return false, nil
}

// returns headers with proper case - 'exceptHeaders' MUST be lower case headers!
func (headers *SipHeaders) ValuesWithHeaderPrefix(headersPrefix string, exceptHeaders ...string) map[string][]string {
	headersPrefix = ASCIIToLower(headersPrefix)
	data := make(map[string][]string)
outer:
	for k, v := range headers._map {
		if strings.HasPrefix(k, headersPrefix) {
			for _, eh := range exceptHeaders {
				if eh == k {
					continue outer
				}
			}
			data[HeaderCase(k)] = v
		}
	}
	return data
}

func (headers *SipHeaders) DeleteHeadersWithPrefix(headersPrefix string) {
	headersPrefix = ASCIIToLower(headersPrefix)

	var hdrs []string
	for ky := range headers._map {
		if strings.HasPrefix(ky, headersPrefix) {
			hdrs = append(hdrs, ky)
		}
	}
	for _, hdr := range hdrs {
		delete(headers._map, hdr)
	}
}

func (headers *SipHeaders) ValueHeader(header HeaderEnum) string {
	return headers.Value(header.String())
}

func (headers *SipHeaders) Value(headerName string) string {
	if ok, v := headers.Values(headerName); ok {
		return v[0]
	}
	return ""
}

func (headers *SipHeaders) DeleteHeader(header HeaderEnum) bool {
	return headers.Delete(header.String())
}

func (headers *SipHeaders) Delete(headerName string) bool {
	headerName = ASCIIToLower(headerName)
	_, ok := headers._map[headerName]
	if ok {
		delete(headers._map, headerName)
	}
	return ok
}

func (headers *SipHeaders) ContainsToTag() bool {
	toheader := headers._map["to"]
	return strings.Contains(ASCIIToLower(toheader[0]), ";tag=")
}

func (headers *SipHeaders) AnyMandatoryHeadersMissing(m Method) (bool, string) {
	for _, mh := range MandatoryHeaders {
		if !headers.HeaderExists(mh) {
			return true, mh
		}
	}
	if m == INVITE {
		mh := Max_Forwards.String()
		if !headers.HeaderExists(mh) {
			return true, mh
		}
		mh = Contact.String()
		if !headers.HeaderExists(mh) {
			return true, mh
		}
	}
	return false, ""
}
