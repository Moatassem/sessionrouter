package sip

import (
	. "SRGo/global"
	"SRGo/guid"
	"cmp"
	"fmt"
	"slices"
	"time"
)

func (session *SipSession) SendCreatedResponse(trans *Transaction, sc int, msgbody *MessageBody) {
	session.SendCreatedResponseDetailed(trans, ResponsePack{StatusCode: sc}, msgbody)
}

func (session *SipSession) SendCreatedResponseDetailed(trans *Transaction, rspspk ResponsePack, msgbody *MessageBody) {
	if trans == nil {
		trans = session.GetLastUnACKedInvSYNC(INBOUND)
		if trans == nil {
			LogError(LTSIPStack, fmt.Sprintf("SendCreatedResponseDetailed: No UnACKed INVITE transaction found to send response (%d) on Call-ID (%s)", rspspk.StatusCode, session.CallID))
			return
		}
	}

	stc := rspspk.StatusCode
	trans.Lock.Lock()
	if IsProvisional18x(stc) && rspspk.LinkedPRACKST == nil && (msgbody == nil || !msgbody.ContainsSDP()) {
		if (session.RoutingData.DisallowSimilar18x && slices.Contains(trans.Responses, stc)) || (session.RoutingData.DisallowDifferent18x && slices.ContainsFunc(trans.Responses, func(x int) bool { return IsProvisional18x(x) && x != stc })) {
			trans.Lock.Unlock()
			return
		}
	}
	trans.Responses = append(trans.Responses, stc)
	trans.IsFinalized = cmp.Or(trans.IsFinalized, stc >= 200)
	trans.Lock.Unlock()

	sipmsg := NewResponseMessage(stc, rspspk.ReasonPhrase)
	sipmsg.Headers = session.createHeadersForResponse(trans, rspspk)

	sipmsg.Body = msgbody
	sipmsg.ParseNPrepareSDP(session)

	trans.SentMessage = sipmsg
	session.SendSTMessage(trans)
}

//nolint:cyclop
func (session *SipSession) createHeadersForResponse(trans *Transaction, rspnspk ResponsePack) *SipHeaders {
	hdrs := NewSHsPointer(true)
	sc := rspnspk.StatusCode
	sipmsg := trans.RequestMessage

	// Add Contact header
	if rspnspk.ContactHeader == "" {
		localsocket := GetUDPAddrFromConn(session.UDPListenser())
		hdrs.AddHeader(Contact, GenerateContact(localsocket))
	} else {
		hdrs.AddHeader(Contact, rspnspk.ContactHeader)
	}

	// Add Expires header (for registration responses)
	if trans.Method == REGISTER {
		if sipmsg.Headers.ValueHeader(Expires) != "" {
			hdrs.AddHeader(Expires, sipmsg.Headers.ValueHeader(Expires))
		}
	}

	// Add Call-ID header
	hdrs.AddHeader(Call_ID, session.CallID)

	// Add custom headers if present
	if hmap := rspnspk.CustomHeaders.InternalMap(); hmap != nil {
		for k, vs := range hmap {
			for _, v := range vs {
				hdrs.Add(k, v)
			}
		}
	}

	// Add mandatory headers
	hdrs.AddHeaderValues(Via, sipmsg.Headers.HeaderValues(Via))
	hdrs.AddHeader(From, sipmsg.Headers.ValueHeader(From))
	hdrs.AddHeader(To, sipmsg.Headers.ValueHeader(To))
	hdrs.AddHeader(CSeq, sipmsg.Headers.ValueHeader(CSeq))
	hdrs.AddHeader(Date, time.Now().UTC().Format(DicTFs[Signaling]))

	// Handle Reason header if session is linked and response code >= 400
	// if !rspnspk.IsCancelled && session.LinkedSession != nil && sc >= 400 && !hdrs.HeaderExists("Reason") {
	// 	reason := session.LinkedSession.GetLastMessageHeaderValueSYNC("Reason")
	// 	if reason == "" {
	// 		reason = "Q.850;cause=16"
	// 	}
	// 	hdrs.Add("Reason", reason)
	// }

	// Add tags and PRACK headers for responses > 100
	if sc > 100 {
		if !hdrs.ContainsToTag() && session.Direction == INBOUND {
			if session.ToTag == "" {
				if Is18xOrPositive(sc) {
					session.ToTag = guid.NewTag()
					session.ToHeader = fmt.Sprintf("%s;tag=%s", hdrs.ValueHeader(To), session.ToTag)
					trans.To = session.ToHeader
				}
			}
			hdrs.SetHeader(To, session.ToHeader)
		}

		hdrs.AddHeaderValues(Record_Route, session.RecordRoutes)
		hdrs.AddHeader(Refer_Sub, sipmsg.Headers.ValueHeader(Refer_Sub))

		// remoteses := session.LinkedSession
		// prackRequested := remoteses != nil && remoteses.AreTherePendingOutgoingPRACK()
		prackRequested := rspnspk.PRACKRequested || rspnspk.LinkedPRACKST != nil

		// Add PRACK support for provisional responses if applicable
		if IsProvisional18x(sc) && session.IsPRACKSupported && session.Direction == INBOUND && prackRequested {
			hdrs.SetHeader(RSeq, session.GenerateRSeqCreatePRACKSTSYNC(rspnspk.LinkedPRACKST))
			hdrs.SetHeader(Require, "100rel")
		}
	}

	// Ensure any options in "Require" header are copied to "Supported"
	// if requireOptions, ok := hdrs.TryGetField("Require"); ok {
	// 	hvalues := strings.Split(requireOptions, ",;")
	// 	for _, hv := range hvalues {
	// 		hdrs.AddOrMergeField("Supported", strings.ToLower(strings.TrimSpace(hv)))
	// 	}
	// }

	return hdrs
}
