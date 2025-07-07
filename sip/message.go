package sip

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"

	. "SRGo/global"
	"SRGo/numtype"

	"github.com/Moatassem/sdp"
)

type SipMessage struct {
	MsgType   MessageType
	StartLine *StartLine
	Headers   *SipHeaders
	Body      *MessageBody
	Bytes     []byte // used to store the generated body bytes for sending msgs

	// all fields below are only set in incoming messages
	FromHeader string
	ToHeader   string
	PAIHeaders []string
	DivHeaders []string

	CallID    string
	FromTag   string
	ToTag     string
	ViaBranch string

	ViaUdpAddr *net.UDPAddr

	RCURI string

	MaxFwds       int
	CSeqNum       uint32
	CSeqMethod    Method
	ContentLength int // only set for incoming messages
}

func NewRequestMessage(md Method, up string) *SipMessage {
	sipmsg := &SipMessage{
		MsgType: REQUEST,
		StartLine: &StartLine{
			Method:     md,
			UriScheme:  "sip",
			UserPart:   up,
			OriginalUP: up,
		},
	}
	return sipmsg
}

func NewResponseMessage(sc int, rp string) *SipMessage {
	if sc < 100 || sc > 699 {
		LogWarning(LTSIPStack, fmt.Sprintf("[%d] - Bad status code in NewResponseMessage - replaced by 400", sc))
		sc = 400
	}
	sipmsg := &SipMessage{
		MsgType: RESPONSE,
		StartLine: &StartLine{
			StatusCode:   sc,
			ReasonPhrase: cmp.Or(rp, DicResponse[sc], DicResponse[(sc/100)*100]),
		},
	}
	return sipmsg
}

// ==========================================================================

func (sipmsg *SipMessage) String() string {
	var part1, part2 string
	if sipmsg.MsgType == REQUEST {
		part1 = sipmsg.StartLine.Method.String()
	} else {
		part1 = Int2Str(sipmsg.StartLine.StatusCode)
	}
	part2 = sipmsg.ContentType()
	if part2 == "" {
		return part1
	}
	return fmt.Sprintf("%s [%s]", part1, part2)
}

func (sipmsg *SipMessage) getAddBodyParts() []int {
	hv := ASCIIToLower(sipmsg.Headers.ValueHeader(P_Add_BodyPart))
	hv = strings.ReplaceAll(hv, " ", "")
	partflags := strings.Split(hv, ",")
	var flags []int
	for k, v := range BodyAddParts {
		if slices.Contains(partflags, v) {
			flags = append(flags, k)
		}
	}
	// drop the special header afterwards
	sipmsg.Headers.DeleteHeader(P_Add_BodyPart)
	return flags
}

func (sipmsg *SipMessage) AddRequestedBodyParts() {
	pflags := sipmsg.getAddBodyParts()
	if len(pflags) == 0 {
		return
	}
	// if sipmsg.Body
	msgbdy := sipmsg.Body
	hdrs := sipmsg.Headers
	if len(msgbdy.PartsContents) == 1 {
		frstbt := OnlyKey(msgbdy.PartsContents)
		cntnthdrsmap := hdrs.ValuesWithHeaderPrefix("Content-", Content_Length.LowerCaseString())
		hdrs.DeleteHeadersWithPrefix("Content-")
		msgbdy.PartsContents[frstbt] = ContentPart{Headers: NewSHsFromMap(cntnthdrsmap), Bytes: msgbdy.PartsContents[frstbt].Bytes}
	}
	for _, pf := range pflags {
		switch pf {
		case AddXMLPIDFLO:
			bt := PIDFXML
			xml := `<?xml version="1.0" encoding="UTF-8"?><presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:gp="urn:ietf:params:xml:ns:pidf:geopriv10" xmlns:cl="urn:ietf:params:xml:ns:pidf:geopriv10:civicLoc" xmlns:btd="http://btd.orange-business.com" entity="pres:geotarget@btip.orange-business.com"><tuple id="sg89ae"><status><gp:geopriv><gp:location-info><cl:civicAddress><cl:country>FR</cl:country><cl:A2>35</cl:A2><cl:A3>CESSON SEVIGNE</cl:A3><cl:A6>DU CHENE GERMAIN</cl:A6><cl:HNO>9</cl:HNO><cl:STS>RUE</cl:STS><cl:PC>35510</cl:PC><cl:CITYCODE>99996</cl:CITYCODE></cl:civicAddress></gp:location-info><gp:usage-rules></gp:usage-rules></gp:geopriv></status></tuple></presence>`
			xmlbytes := []byte(xml)
			msgbdy.PartsContents[bt] = NewContentPart(bt, xmlbytes)
		case AddINDATA:
			bt := VndOrangeInData
			binbytes, _ := hex.DecodeString("77124700830e8307839069391718068a019288000d0a")
			sh := NewSipHeaders()
			sh.AddHeader(Content_Type, DicBodyContentType[bt])
			sh.AddHeader(Content_Transfer_Encoding, "binary")
			sh.AddHeader(Content_Disposition, "signal;handling=optional")
			msgbdy.PartsContents[bt] = ContentPart{Headers: sh, Bytes: binbytes}
		}
	}
}

// TODO need to check:
// if only one part left: to remove ContentPart object - see KeepOnlyPart
// if nothing left: to nullify parts i.e. sipmsg.Body.PartsBytes = nil
// func (sipmsg *SipMessage) dropBodyPart(bt BodyType) {
// 	delete(messagebody.PartsBytes, bt)
// }

func (sipmsg *SipMessage) KeepOnlyBodyPart(bt BodyType) bool {
	msgbdy := sipmsg.Body
	kys := Keys(msgbdy.PartsContents) // get all keys
	if len(kys) == 1 && kys[0] == bt {
		return true // to avoid removing Content-* headers while there is no Content headers inside the single body part
	}
	for _, ky := range kys {
		if ky == bt {
			continue
		}
		delete(msgbdy.PartsContents, ky) // remove other keys
	}
	if len(msgbdy.PartsContents) == 0 { // return if no remaining parts
		return false
	}
	cntprt := msgbdy.PartsContents[bt]
	smhdrs := sipmsg.Headers
	smhdrs.DeleteHeadersWithPrefix("Content-")            // remove all existing Content-* headers
	for _, hdr := range cntprt.Headers.GetHeaderNames() { // set Content-* headers from kept body part
		smhdrs.Set(hdr, cntprt.Headers.Value(hdr))
	}
	msgbdy.PartsContents[bt] = ContentPart{Bytes: cntprt.Bytes}
	return true
}

func (sipmsg *SipMessage) GetBodyPart(bt BodyType) (ContentPart, bool) {
	cntnt, ok := sipmsg.Body.PartsContents[bt]
	return cntnt, ok
}

func (sipmsg *SipMessage) ParseSDPPartAndBuildAnswer() (int, string, bool) {
	sdpses, err := sdp.Parse(sipmsg.Body.PartsContents[SDP].Bytes)
	if err != nil {
		LogError(LTSDPStack, fmt.Sprintf("Failed to parse SDP for Echo Responder: %v", err))
		return 400, "Failed to parse SDP for Echo Responder", false
	}
	sdpses2, _, err := sdpses.BuildEchoResponderAnswer(sdp.SupportedCodecsStringList...)
	if err != nil {
		LogError(LTSDPStack, fmt.Sprintf("Failed to build Echo Responder SDP: %v", err))
		return 488, "Failed to build Echo Responder SDP", false
	}
	sipmsg.Body.SdpSession = sdpses2
	return 200, "", sdpses.IsCallHeld()
}

// ===========================================================================

func (sipmsg *SipMessage) IsOutOfDialgoue() bool {
	return sipmsg.ToTag == ""
}

func (sipmsg *SipMessage) GetRSeqFromRAck() (rSeq, cSeq uint32, ok bool) {
	rAck := sipmsg.Headers.ValueHeader(RAck)
	if rAck == "" {
		LogError(LTSIPStack, "Empty RAck header")
		ok = false
		return
	}
	mtch := DicFieldRegExp[RAckHeader].FindStringSubmatch(rAck)
	if mtch == nil { // Ensure we have both RSeq and CSeq from the match
		LogError(LTSIPStack, "Malformed RAck header")
		ok = false
		return
	}
	rSeq = Str2Uint[uint32](mtch[1])
	cSeq = Str2Uint[uint32](mtch[2])
	ok = true
	return
}

func (sipmsg *SipMessage) IsOptionSupportedOrRequired(opt string) bool {
	hdr := sipmsg.Headers.ValueHeader(Require)
	if strings.Contains(hdr, opt) {
		return true
	}
	hdr = sipmsg.Headers.ValueHeader(Supported)
	return strings.Contains(hdr, opt)
}

func (sipmsg *SipMessage) IsOptionSupported(o string) bool {
	hdr := sipmsg.Headers.ValueHeader(Supported)
	hdr = ASCIIToLower(hdr)
	return hdr != "" && strings.Contains(hdr, o)
}

func (sipmsg *SipMessage) IsOptionRequired(o string) bool {
	hdr := sipmsg.Headers.ValueHeader(Require)
	hdr = ASCIIToLower(hdr)
	return hdr != "" && strings.Contains(hdr, o)
}

func (sipmsg *SipMessage) IsMethodAllowed(m Method) bool {
	hdr := sipmsg.Headers.ValueHeader(Allow)
	hdr = ASCIIToLower(hdr)
	return hdr != "" && strings.Contains(hdr, ASCIIToLower(m.String()))
}

func (sipmsg *SipMessage) IsKnownRURIScheme() bool {
	for _, s := range UriSchemes {
		if s == sipmsg.StartLine.UriScheme {
			return true
		}
	}
	return false
}

func (sipmsg *SipMessage) GetReferToRUIR() (string, string) {
	ok, values := sipmsg.Headers.ValuesHeader(Refer_To)
	if !ok {
		return "", "No Refer-To header"
	}
	if len(values) > 1 {
		return "", "Multiple Refer-To headers found"
	}
	value := values[0]
	if strings.Contains(ASCIIToLower(value), "replaces") {
		return "", "Refer-To with Replaces"
	}
	mtch := RMatch(value, URIFull)
	if len(mtch) == 0 {
		return "", "Badly formatted URI"
	}
	return mtch[1], ""
}

func (sipmsg *SipMessage) WithNoReferSubscription() bool {
	if sipmsg.Headers.DoesValueExistInHeader(Require.String(), "norefersub") {
		return true
	}
	if sipmsg.Headers.DoesValueExistInHeader(Supported.String(), "norefersub") {
		return true
	}
	if sipmsg.Headers.DoesValueExistInHeader(Refer_Sub.String(), "false") {
		return true
	}
	return false
}

func (sipmsg *SipMessage) IsResponse() bool {
	return sipmsg.MsgType == RESPONSE
}

func (sipmsg *SipMessage) IsRequest() bool {
	return sipmsg.MsgType == REQUEST
}

func (sipmsg *SipMessage) GetMethod() Method {
	return sipmsg.StartLine.Method
}

func (sipmsg *SipMessage) GetStatusCode() int {
	return sipmsg.StartLine.StatusCode
}

func (sipmsg *SipMessage) GetRegistrationData() (contact, ext, ruri, ipport string, expiresInt int) {
	// TODO fix the Regex
	contact = sipmsg.Headers.ValueHeader(Contact)
	contact1 := strings.Replace(contact, "-", ";", 1)

	if mtch := RMatch(contact1, ContactHeader); len(mtch) > 0 {
		ruri = mtch[0]
		ext = mtch[2]
		ipport = mtch[5]
	} else {
		expiresInt = -100 // bad contact
		return
	}

	if mtch := RMatch(contact, ExpiresParameter); len(mtch) > 0 {
		expiresInt = Str2Int[int](mtch[1])
		return
	}
	expires := sipmsg.Headers.ValueHeader(Expires)
	if expires != "" {
		expiresInt = Str2Int[int](expires)
		return
	}
	expires = "3600"
	sipmsg.Headers.SetHeader(Expires, expires)
	expiresInt = Str2Int[int](expires)
	return
}

func (sipmsg *SipMessage) TranslateRM(ss *SipSession, tx *Transaction, nt numtype.NumberType, newNumber string) {
	if newNumber == "" {
		return
	}
	localsocket := GetUDPAddrFromConn(ss.UDPListenser())
	rep := fmt.Sprintf("${1}%s$2", newNumber)

	switch nt {
	case numtype.CalledRURI:
		sipmsg.StartLine.RUri = RReplaceNumberOnly(sipmsg.StartLine.RUri, rep)
		sipmsg.StartLine.UserPart = newNumber
		ss.RemoteContactURI = sipmsg.StartLine.RUri
	case numtype.CalledTo:
		sipmsg.Headers.SetHeader(To, RReplaceNumberOnly(sipmsg.Headers.ValueHeader(To), rep))
		ss.ToHeader = sipmsg.Headers.ValueHeader(To)
		tx.To = ss.ToHeader
	case numtype.CalledBoth:
		sipmsg.StartLine.RUri = RReplaceNumberOnly(sipmsg.StartLine.RUri, rep)
		sipmsg.StartLine.UserPart = newNumber
		ss.RemoteContactURI = sipmsg.StartLine.RUri

		sipmsg.Headers.SetHeader(To, RReplaceNumberOnly(sipmsg.Headers.ValueHeader(To), rep))
		ss.ToHeader = sipmsg.Headers.ValueHeader(To)
		tx.To = ss.ToHeader
	case numtype.CallingFrom:
		sipmsg.Headers.SetHeader(From, RReplaceNumberOnly(sipmsg.Headers.ValueHeader(From), rep))
		ss.FromHeader = sipmsg.Headers.ValueHeader(From)
		tx.From = ss.FromHeader
	case numtype.CallingPAI:
		if sipmsg.Headers.HeaderExists(P_Asserted_Identity.String()) {
			sipmsg.Headers.SetHeader(P_Asserted_Identity, RReplaceNumberOnly(sipmsg.Headers.ValueHeader(P_Asserted_Identity), rep))
		} else {
			sipmsg.Headers.SetHeader(P_Asserted_Identity, fmt.Sprintf("<sip:%s@%s;user=phone>", newNumber, localsocket.IP))
		}
	case numtype.CallingBoth:
		if sipmsg.Headers.HeaderExists(P_Asserted_Identity.String()) {
			sipmsg.Headers.SetHeader(P_Asserted_Identity, RReplaceNumberOnly(sipmsg.Headers.ValueHeader(P_Asserted_Identity), rep))
		} else {
			sipmsg.Headers.SetHeader(P_Asserted_Identity, fmt.Sprintf("<sip:%s@%s;user=phone>", newNumber, localsocket.IP))
		}

		sipmsg.Headers.SetHeader(From, RReplaceNumberOnly(sipmsg.Headers.ValueHeader(From), rep))
		ss.FromHeader = sipmsg.Headers.ValueHeader(From)
		tx.From = ss.FromHeader
	}
}

func (sipmsg *SipMessage) PrepareMessageBytes(ss *SipSession) {
	var bb bytes.Buffer
	var headers []string

	byteschan := make(chan []byte)
	defer close(byteschan)

	// generate body bytes in a separate goroutine
	go func(bc chan<- []byte) {
		var bbc bytes.Buffer
		if sipmsg.WithNoBodyOrZeroParts() {
			sipmsg.Headers.SetHeader(Content_Type, "")
			sipmsg.Headers.SetHeader(MIME_Version, "")
		} else {
			bdyparts := sipmsg.Body.PartsContents
			if len(bdyparts) == 1 {
				k, v := FirstKeyValue(bdyparts)
				sipmsg.Headers.SetHeader(Content_Type, DicBodyContentType[k])
				sipmsg.Headers.SetHeader(MIME_Version, "")
				bbc.Write(v.Bytes)
			} else {
				sipmsg.Headers.SetHeader(Content_Type, "multipart/mixed;boundary="+MultipartBoundary)
				sipmsg.Headers.SetHeader(MIME_Version, "1.0")
				isfirstline := true
				for _, ct := range bdyparts {
					if !isfirstline {
						bbc.WriteString("\r\n")
					}
					bbc.WriteString(fmt.Sprintf("--%s\r\n", MultipartBoundary))
					for _, h := range ct.Headers.GetHeaderNames() {
						_, values := ct.Headers.Values(h)
						for _, hv := range values {
							bbc.WriteString(fmt.Sprintf("%s: %s\r\n", HeaderCase(h), hv))
						}
					}
					bbc.WriteString("\r\n")
					bbc.Write(ct.Bytes)
					isfirstline = false
				}
				bbc.WriteString(fmt.Sprintf("\r\n--%s--\r\n", MultipartBoundary))
			}
		}

		bodybytes := bbc.Bytes()
		sipmsg.Headers.SetHeader(Content_Length, Int2Str(len(bodybytes)))

		bc <- bodybytes
	}(byteschan)

	// startline
	if sipmsg.IsRequest() {
		sl := sipmsg.StartLine
		bb.WriteString(sl.GetStartLine(REQUEST))
		headers = DicRequestHeaders[sl.Method]
	} else {
		sl := sipmsg.StartLine
		bb.WriteString(sl.GetStartLine(RESPONSE))
		headers = DicResponseHeaders[sl.StatusCode]
	}

	// body - build body type, length, multipart and related headers
	bodybytes := <-byteschan

	// headers - build and write
	for _, h := range headers {
		_, values := sipmsg.Headers.Values(h)
		for _, hv := range values {
			if hv != "" {
				bb.WriteString(fmt.Sprintf("%s: %s\r\n", h, hv))
			}
		}
	}

	// P- headers build and write
	pHeaders := sipmsg.Headers.ValuesWithHeaderPrefix("P-")
	for h, hvs := range pHeaders {
		for _, hv := range hvs {
			if hv != "" {
				bb.WriteString(fmt.Sprintf("%s: %s\r\n", h, hv))
			}
		}
	}

	// write separator
	bb.WriteString("\r\n")

	// write body bytes
	bb.Write(bodybytes)

	// save generated bytes for retransmissions
	sipmsg.Bytes = bb.Bytes()
}

func (sipmsg *SipMessage) ParseNPrepareSDP(ss *SipSession) {
	if sipmsg.WithNoBody() {
		return
	}
	msgbody := sipmsg.Body
	ct, _ := sipmsg.GetBodyPart(SDP)

	var (
		sdpSession *sdp.Session
		err        error
	)

	if msgbody.SdpSession != nil {
		sdpSession = msgbody.SdpSession
	} else if msgbody.ContainsSDP() {
		sdpSession, err = sdp.Parse(ct.Bytes)
		if err != nil {
			LogError(LTConfiguration, fmt.Sprintf("Failed to parse SDP: %v", err))
			return
		}
		sdpSession.Name = B2BUANameVersion
	} else {
		return
	}

	if ss.RoutingData != nil && (ss.RoutingData.SteerMedia || ss.RoutingData.OutCallFlow == EchoResponder) && ss.MediaConn != nil {
		if lnkdss := ss.LinkedSession; lnkdss != nil {
			lnkdss.SetRemoteMediaUdpAddr(sdpSession.GetEffectiveMediaUdpAddr(sdp.Audio))
		}
		ipv4, port := GetUDPIPPortFromConn(ss.MediaConn)
		sdpSession.SetConnection(sdp.Audio, ipv4, port, false)
	}

	if ss.SDPSessionID == 0 {
		ss.SDPSessionID = int64(RandomNum(1000, 9000))
	}
	sdpSession.Origin.SessionID = ss.SDPSessionID

	if ss.SDPSession == nil {
		ss.SDPSession = sdpSession
		ss.SDPSessionVersion = 1
	} else if !ss.SDPSession.Equals(sdpSession) {
		ss.SDPSession = sdpSession
		ss.SDPSessionVersion++
	}

	sdpSession.Origin.SessionVersion = ss.SDPSessionVersion

	ct.Bytes = sdpSession.Bytes()
	msgbody.PartsContents[SDP] = ct
}

func (sipmsg *SipMessage) WithNoBody() bool {
	return sipmsg.Body == nil
}

func (sipmsg *SipMessage) WithNoBodyOrZeroParts() bool {
	return sipmsg.Body == nil || len(sipmsg.Body.PartsContents) == 0
}

func (sipmsg *SipMessage) WithUnknownBodyPart() bool {
	if sipmsg.WithNoBody() {
		return false
	}
	if len(sipmsg.Body.PartsContents) == 0 { // means PartsContents initialized but nothing added
		return true
	}
	for k := range sipmsg.Body.PartsContents {
		if k == Unknown {
			return true
		}
	}
	return false
}

func (sipmsg *SipMessage) IsMultiPartBody() bool {
	if sipmsg.WithNoBody() {
		return false
	}
	return len(sipmsg.Body.PartsContents) >= 2
}

func (sipmsg *SipMessage) ContainsSDP() bool {
	if sipmsg.WithNoBody() {
		return false
	}
	_, ok := sipmsg.Body.PartsContents[SDP]
	return ok
}

func (sipmsg *SipMessage) IsT38Image() bool {
	if sipmsg.WithNoBody() {
		return false
	}
	sess, err := sdp.Parse(sipmsg.Body.PartsContents[SDP].Bytes)
	if err != nil {
		return false
	}
	return sess.IsT38Image()
}

func (sipmsg *SipMessage) IsJSON() bool {
	if sipmsg.WithNoBody() {
		return false
	}
	_, ok := sipmsg.Body.PartsContents[AppJson]
	return ok
}

func (sipmsg *SipMessage) ContentType() string {
	if sipmsg.WithNoBody() {
		return ""
	}
	switch len(sipmsg.Body.PartsContents) {
	case 0:
		return ""
	case 1:
		return DicBodyContentType[OnlyKey(sipmsg.Body.PartsContents)]
	default:
		return DicBodyContentType[MultipartMixed]
	}
}
