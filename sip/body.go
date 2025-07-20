package sip

import (
	. "SRGo/global"

	"github.com/Moatassem/sdp"
)

type MessageBody struct {
	PartsContents map[BodyType]ContentPart // used to store incoming/outgoing body parts
	SdpSession    *sdp.Session             // used to store SDP session for the SDP body part
}

type ContentPart struct {
	Headers SipHeaders
	Bytes   []byte
}

func NewBody() *MessageBody {
	return &MessageBody{PartsContents: make(map[BodyType]ContentPart)}
}

func ZeroBody() *MessageBody {
	return nil
}

func NewContentPart(bt BodyType, bytes []byte) ContentPart {
	var ct ContentPart
	ct.Bytes = bytes
	ct.Headers = NewSipHeaders()
	ct.Headers.AddHeader(Content_Type, DicBodyContentType[bt])
	return ct
}

// ===============================================================

func NewMSCXML(xml string) *MessageBody {
	hdrs := NewSipHeaders()
	hdrs.AddHeader(Content_Length, DicBodyContentType[MSCXML])
	return &MessageBody{PartsContents: map[BodyType]ContentPart{MSCXML: {hdrs, []byte(xml)}}}
}

func NewJSON(jsonbytes []byte) *MessageBody {
	hdrs := NewSipHeaders()
	hdrs.AddHeader(Content_Length, DicBodyContentType[AppJson])
	return &MessageBody{PartsContents: map[BodyType]ContentPart{AppJson: {hdrs, jsonbytes}}}
}

func NewInData(binbytes []byte) *MessageBody {
	hdrs := NewSipHeaders()
	hdrs.AddHeader(Content_Length, DicBodyContentType[VndOrangeInData])
	return &MessageBody{PartsContents: map[BodyType]ContentPart{AppJson: {hdrs, binbytes}}}
}

func (msgbody *MessageBody) ContainsSDP() bool {
	_, ok := msgbody.PartsContents[SDP]
	return ok
}
