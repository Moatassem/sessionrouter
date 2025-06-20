package sip

import (
	"SRGo/global"
	. "SRGo/global"
	"fmt"

	"github.com/Moatassem/sdp"
)

type MessageBody struct {
	PartsContents map[BodyType]ContentPart // used to store incoming/outgoing body parts
	MessageBytes  []byte                   // used to store the generated body bytes for sending msgs
}

type ContentPart struct {
	Headers SipHeaders
	Bytes   []byte
}

func EmptyBody() MessageBody {
	var mb MessageBody
	return mb
}

func NewContentPart(bt BodyType, bytes []byte) ContentPart {
	var ct ContentPart
	ct.Bytes = bytes
	ct.Headers = NewSipHeaders()
	ct.Headers.AddHeader(Content_Type, DicBodyContentType[bt])
	return ct
}

// ===============================================================

func NewMSCXML(xml string) MessageBody {
	hdrs := NewSipHeaders()
	hdrs.AddHeader(Content_Length, DicBodyContentType[MSCXML])
	return MessageBody{PartsContents: map[BodyType]ContentPart{MSCXML: {hdrs, []byte(xml)}}}
}

func NewJSON(jsonbytes []byte) MessageBody {
	hdrs := NewSipHeaders()
	hdrs.AddHeader(Content_Length, DicBodyContentType[AppJson])
	return MessageBody{PartsContents: map[BodyType]ContentPart{AppJson: {hdrs, jsonbytes}}}
}

func NewInData(binbytes []byte) MessageBody {
	hdrs := NewSipHeaders()
	hdrs.AddHeader(Content_Length, DicBodyContentType[VndOrangeInData])
	return MessageBody{PartsContents: map[BodyType]ContentPart{AppJson: {hdrs, binbytes}}}
}

// ===============================================================

func (messagebody *MessageBody) ParseNPrepareSDP(ss *SipSession) {
	if !messagebody.ContainsSDP() {
		return
	}

	ct := messagebody.PartsContents[SDP]

	sdpSession, err := sdp.Parse(ct.Bytes)
	if err != nil {
		LogError(LTConfiguration, fmt.Sprintf("Failed to parse SDP: %v", err))
		return
	}

	sdpSession.Name = global.B2BUAName

	if ss.RoutingData != nil && ss.RoutingData.SteerMedia && ss.MediaConn != nil {
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
		ss.SDPSessionVersion += 1
	}

	sdpSession.Origin.SessionVersion = ss.SDPSessionVersion

	ct.Bytes = sdpSession.Bytes()
	messagebody.PartsContents[SDP] = ct
}

func (messagebody *MessageBody) WithNoBody() bool {
	return messagebody.PartsContents == nil
}

func (messagebody *MessageBody) WithUnknownBodyPart() bool {
	if messagebody.WithNoBody() {
		return false
	}
	if len(messagebody.PartsContents) == 0 { // means PartsContents initialized but nothing added
		return true
	}
	for k := range messagebody.PartsContents {
		if k == Unknown {
			return true
		}
	}
	return false
}

func (messagebody *MessageBody) IsMultiPartBody() bool {
	if messagebody.WithNoBody() {
		return false
	}
	return len(messagebody.PartsContents) >= 2
}

func (messagebody *MessageBody) ContainsSDP() bool {
	if messagebody.WithNoBody() {
		return false
	}
	_, ok := messagebody.PartsContents[SDP]

	return ok
}

func (messagebody *MessageBody) IsT38Image() bool {
	sess, err := sdp.Parse(messagebody.PartsContents[SDP].Bytes)
	if err != nil {
		return false
	}
	return sess.IsT38Image()
}

func (messagebody *MessageBody) IsJSON() bool {
	if messagebody.WithNoBody() {
		return false
	}
	_, ok := messagebody.PartsContents[AppJson]
	return ok
}

func (messagebody *MessageBody) ContentType() string {
	switch len(messagebody.PartsContents) {
	case 0:
		return ""
	case 1:
		return DicBodyContentType[FirstKey(messagebody.PartsContents)]
	default:
		return DicBodyContentType[MultipartMixed]
	}
}

func (messagebody *MessageBody) ContentLength() int {
	return len(messagebody.MessageBytes)
}
