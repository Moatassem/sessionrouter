package sip

import (
	. "SRGo/global"
	"SRGo/guid"
	"SRGo/sip/mode"
	"fmt"
	"maps"
	"time"
)

func (session *SipSession) CreateSARequest(rqstpk RequestPack, body *MessageBody) *Transaction {
	switch rqstpk.Method {
	case OPTIONS:
		session.FwdCSeq = 911
		session.Mymode = mode.KeepAlive
	case INVITE:
		session.Mymode = mode.Multimedia
		fallthrough
	default: // Any other
		session.FwdCSeq = RandomNum(1, 500)
	}
	st := NewSIPTransaction_CRL(session.FwdCSeq, rqstpk.Method, nil)
	session.prepareSARequestHeaders(st, rqstpk, body)

	session.TransLock.Lock()
	session.AddTransaction(st)
	session.TransLock.Unlock()
	return st
}

func (session *SipSession) prepareSARequestHeaders(st *Transaction, rqstpk RequestPack, msgbody *MessageBody) {
	st.RequestMessage = NewRequestMessage(rqstpk.Method, rqstpk.RUriUP)
	session.buildSARequestHeaders(st, rqstpk, st.RequestMessage)
	st.RequestMessage.Body = msgbody
	st.SentMessage = st.RequestMessage
}

func (session *SipSession) buildSARequestHeaders(st *Transaction, rqstpk RequestPack, sipmsg *SipMessage) {
	localsocket := GetUDPAddrFromConn(session.UDPListenser())
	localIP := localsocket.IP
	remoteIP := session.RemoteUDP().IP

	// Set Start line
	sl := sipmsg.StartLine
	sl.HostPart = session.RemoteUDP().String()
	switch rqstpk.Method {
	case INVITE:
		sl.UriParameters = map[string]string{"user": "phone"}
	}
	sl.BuildRURI(false)
	session.RemoteURI = sl.RUri
	session.RemoteContactURI = sl.RUri

	// Set headers

	hdrs := NewSHsPointer(true)

	// Set Call-ID
	session.CallID = guid.NewCallID()
	hdrs.AddHeader(Call_ID, session.CallID)

	// Set Via and its branch
	hdrs.AddHeader(Via, fmt.Sprintf("%s;branch=%s", GenerateViaWithoutBranch(session.UDPListenser()), st.ViaBranch))

	// Set From and its tag
	session.FromTag = guid.NewTag()
	session.FromHeader = fmt.Sprintf("<sip:%s@%s;user=phone>;tag=%s", rqstpk.FromUP, localIP, session.FromTag)
	st.From = session.FromHeader
	hdrs.AddHeader(From, session.FromHeader)

	// Add custom headers if any
	if hmap := rqstpk.CustomHeaders.InternalMap(); hmap != nil {
		for k, vs := range hmap {
			for _, v := range vs {
				hdrs.Add(k, v)
			}
		}
	}

	// Set To
	session.ToHeader = fmt.Sprintf("<sip:%s@%s;user=phone>", rqstpk.RUriUP, remoteIP)
	st.To = session.ToHeader
	hdrs.SetHeader(To, session.ToHeader)

	// Set CSeq
	st.CSeq = session.FwdCSeq
	hdrs.AddHeader(CSeq, fmt.Sprintf("%s %s", Uint32ToStr(session.FwdCSeq), rqstpk.Method.String()))

	// Set Contact
	hdrs.SetHeader(Contact, GenerateContact(localsocket))

	// Set Max-Forwards
	maxFwds := 70
	sipmsg.MaxFwds = maxFwds
	hdrs.SetHeader(Max_Forwards, Int2Str(maxFwds))

	// Set Date
	hdrs.AddHeader(Date, time.Now().UTC().Format(DicTFs[Signaling]))

	sipmsg.Headers = hdrs
}

// ======================================

func (session *SipSession) CreateLinkedINVITE(userpart string, body *MessageBody) (*Transaction, *SipMessage) {
	trans := session.addOutgoingRequest(INVITE, nil)
	sipmsg := NewRequestMessage(INVITE, userpart)
	sipmsg.Headers = NewSHsPointer(true)
	session.Mymode = mode.Multimedia
	session.proxifyRequestHeaders(sipmsg, trans)
	session.processRequestHeaders(trans, sipmsg, RequestPack{Method: INVITE}, body)
	return trans, sipmsg
}

func (session *SipSession) SendCreatedRequest(m Method, trans *Transaction, body *MessageBody) {
	session.SendCreatedRequestDetailed(RequestPack{Method: m}, trans, body)
}

func (session *SipSession) SendCreatedRequestDetailed(rqstpk RequestPack, trans *Transaction, body *MessageBody) {
	newtrans := session.addOutgoingRequest(rqstpk.Method, trans)
	if newtrans == nil {
		return
	}
	sipmsg := NewRequestMessage(rqstpk.Method, "")
	session.prepareRequestHeaders(newtrans, rqstpk, sipmsg)
	session.processRequestHeaders(newtrans, sipmsg, rqstpk, body)

	newtrans.IsProbing = rqstpk.IsProbing // set by probing SIP OPTIONS
	newtrans.RequestMessage = sipmsg
	newtrans.SentMessage = sipmsg

	session.SendSTMessage(newtrans)
}

// helper functions
//
//nolint:cyclop
func (session *SipSession) proxifyRequestHeaders(sipmsg *SipMessage, trans *Transaction) {
	lnkdsipmsg := session.LinkedSession.CurrentRequestMessage()
	sipHdrs := sipmsg.Headers

	localsocket := GetUDPAddrFromConn(session.UDPListenser())
	localIP := localsocket.IP
	remoteIP := session.RemoteUDP().IP

	lnkdsl := lnkdsipmsg.StartLine

	sl := sipmsg.StartLine
	sl.HostPart = session.RoutingData.RemoteUDPSocket.String()
	sl.OriginalUP = lnkdsl.OriginalUP
	sl.UserParameters = maps.Clone(lnkdsl.UserParameters)
	sl.Password = lnkdsl.Password
	sl.UriParameters = maps.Clone(lnkdsl.UriParameters)
	sl.UriHeaders = lnkdsl.UriHeaders
	sl.BuildRURI(!session.RoutingData.IsDB)

	var nm, nmbr string

	// From Header
	var frmHeader string
	if lnkdsipmsg.Headers.DoesValueExistInHeader("Privacy", "user") {
		frmHeader = `"Anonymous" <sip:anonymous@anonymous.invalid>`
	} else {
		if mtch := RMatch(lnkdsipmsg.Headers.ValueHeader(From), NameAndNumber); len(mtch) > 0 {
			nm = TrimWithSuffix(mtch[1], " ")
			nmbr = DropVisualSeparators(mtch[2])
			frmHeader = fmt.Sprintf("%s<sip:%s@%s;user=phone>", nm, nmbr, localIP)
		} else {
			frmHeader = fmt.Sprintf("<sip:Invalid@%s;user=phone>", localIP)
		}
	}

	session.FromTag = guid.NewTag()
	trans.From = fmt.Sprintf("%s;tag=%s", frmHeader, session.FromTag)
	sipHdrs.SetHeader(From, trans.From)
	session.FromHeader = trans.From

	// Set From & To headers received in the ingress leg
	sipHdrs.Set("X-FromHeader", lnkdsipmsg.Headers.ValueHeader(From))
	sipHdrs.Set("X-ToHeader", lnkdsipmsg.Headers.ValueHeader(To))

	// To Header
	if mtch := RMatch(lnkdsipmsg.Headers.ValueHeader(To), NameAndNumber); len(mtch) > 0 {
		nm = TrimWithSuffix(mtch[1], " ")
		nmbr = DropVisualSeparators(mtch[2])
		trans.To = fmt.Sprintf("%s<sip:%s@%s;user=phone>", nm, nmbr, remoteIP)
	}
	sipHdrs.SetHeader(To, trans.To)
	session.ToHeader = trans.To

	// Call-ID Header
	session.CallID = guid.NewCallID()
	sipHdrs.SetHeader(Call_ID, session.CallID)

	// Supported 100rel
	if session.IsPRACKSupported {
		sipHdrs.AddHeader(Supported, "100rel")
	}

	// Via Header
	sipHdrs.AddHeader(Via, fmt.Sprintf("%s;branch=%s", GenerateViaWithoutBranch(session.UDPListenser()), trans.ViaBranch))

	// Contact Header
	sipHdrs.SetHeader(Contact, GenerateContact(localsocket))

	// Content-Disposition
	sipHdrs.AddHeader(Content_Disposition, lnkdsipmsg.Headers.ValueHeader(Content_Disposition))

	// Forward Diversion headers as per RFC 5806
	if ok, values := lnkdsipmsg.Headers.ValuesHeader(Diversion); ok {
		sipHdrs.AddHeaderValues(Diversion, values)
	}

	// Route
	sipHdrs.AddHeader(Route, lnkdsipmsg.Headers.ValueHeader(Route))

	// Privacy Header
	sipHdrs.AddHeader(Privacy, lnkdsipmsg.Headers.ValueHeader(Privacy))

	// History-Info Headers
	if ok, values := lnkdsipmsg.Headers.ValuesHeader(History_Info); ok {
		sipHdrs.AddHeaderValues(History_Info, values)
	}

	// P-Headers
	pHeaders := lnkdsipmsg.Headers.ValuesWithHeaderPrefix("P-")
	for k, vs := range pHeaders {
		for _, v := range vs {
			sipHdrs.Add(k, v)
		}
	}

	// Set INVITE message extra headers
	// for _, header := range SIPConfig.ExtraINVITEHeaders {
	// 	sipHdrs.Add(header, sipMsg.Headers.Value(header))
	// }

	// P-Asserted-Identity Header
	if !lnkdsipmsg.Headers.HeaderNameExists(P_Asserted_Identity) {
		if mtch := RMatch(lnkdsipmsg.Headers.ValueHeader(P_Asserted_Identity), NameAndNumber); len(mtch) > 0 {
			nm = TrimWithSuffix(mtch[1], " ")
			nmbr = DropVisualSeparators(mtch[2])
			sipHdrs.AddHeader(P_Asserted_Identity, fmt.Sprintf("%s<sip:%s@%s;transport=udp>", nm, nmbr, localsocket))
		}
	}

	// Max-Forwards Header
	var maxForwards int
	if trans.ResetMF {
		maxForwards = 70
		trans.ResetMF = false
	} else {
		maxForwards = lnkdsipmsg.MaxFwds - 1
	}
	sipmsg.MaxFwds = maxForwards
	sipHdrs.SetHeader(Max_Forwards, Int2Str(maxForwards))
}

//nolint:cyclop
func (session *SipSession) prepareRequestHeaders(trans *Transaction, rqstpk RequestPack, sipmsg *SipMessage) {
	hdrs := NewSHsPointer(true)
	sipmsg.Headers = hdrs

	localsocket := GetUDPAddrFromConn(session.UDPListenser())

	sl := sipmsg.StartLine
	if trans.UseRemoteURI {
		sl.RUri = session.RemoteURI
	} else {
		sl.RUri = session.RemoteContactURI
	}

	// Set To and From headers depending on session direction
	if session.Direction == OUTBOUND {
		hdrs.SetHeader(To, session.ToHeader)
		hdrs.SetHeader(From, session.FromHeader)
	} else {
		hdrs.SetHeader(To, session.FromHeader)
		hdrs.SetHeader(From, session.ToHeader)
	}

	// Add RAck header if the request type is PRACK
	if rqstpk.Method == PRACK {
		hdrs.SetHeader(RAck, trans.RAck)
	}

	// Max-Forwards
	var maxFwds int
	if rqstpk.Max70 || session.LinkedSession == nil || trans.ResetMF {
		maxFwds = 70
	} else {
		if trans.LinkedTransaction == nil {
			maxFwds = 70
		} else {
			if rqstpk.Method == ACK || rqstpk.Method == CANCEL {
				maxFwds = trans.LinkedTransaction.RequestMessage.MaxFwds
			} else {
				maxFwds = trans.LinkedTransaction.RequestMessage.MaxFwds - 1
			}
		}
	}
	hdrs.SetHeader(Max_Forwards, Int2Str(maxFwds))

	if rqstpk.Method == ReINVITE {
		sipmsg.MaxFwds = maxFwds
	}

	if session.Direction == INBOUND {
		hdrs.AddHeaderValues(Route, session.RecordRoutes)
	} else {
		hdrs.AddHeaderValues(Route, Reverse(session.RecordRoutes))
	}

	// Add Contact, Call-ID, and Via headers
	hdrs.SetHeader(Contact, GenerateContact(localsocket))
	hdrs.SetHeader(Call_ID, session.CallID)
	hdrs.AddHeader(Via, fmt.Sprintf("%s;branch=%s", GenerateViaWithoutBranch(session.UDPListenser()), trans.ViaBranch))
}

// shared between subsequent requests and linked INVITE
//
//nolint:cyclop
func (session *SipSession) processRequestHeaders(trans *Transaction, sipmsg *SipMessage, rqstpk RequestPack, msgbody *MessageBody) {
	hdrs := sipmsg.Headers

	// Add Date header
	hdrs.SetHeader(Date, time.Now().UTC().Format(DicTFs[Signaling]))

	// CSeq header
	hdrs.SetHeader(CSeq, fmt.Sprintf("%s %s", Uint32ToStr(trans.CSeq), sipmsg.StartLine.Method.String()))

	// Add custom headers if any
	if hmap := rqstpk.CustomHeaders.InternalMap(); hmap != nil {
		for k, vs := range hmap {
			for _, v := range vs {
				hdrs.Add(k, v)
			}
		}
	}

	// Set msgbody
	sipmsg.Body = msgbody
	sipmsg.ParseNPrepareSDP(session)

	if sl := sipmsg.StartLine; sl.Method == INVITE {
		trans.RequestMessage = sipmsg
		trans.SentMessage = sipmsg
		session.RemoteURI = sl.RUri
		session.RemoteContactURI = sl.RUri
	} else {
		if trans.UseRemoteURI {
			sl.RUri = session.RemoteURI
		} else {
			sl.RUri = session.RemoteContactURI
		}
		// Add Reason header for CANCEL or BYE requests
		if (sipmsg.StartLine.Method == CANCEL || sipmsg.StartLine.Method == BYE) && !hdrs.HeaderExists("Reason") {
			if session.LinkedSession == nil || trans.LinkedTransaction == nil {
				hdrs.AddHeader(Reason, "Q.850;cause=16")
			} else if reason := trans.LinkedTransaction.RequestMessage.Headers.ValueHeader(Reason); reason != "" {
				hdrs.AddHeader(Reason, reason)
			} else {
				hdrs.AddHeader(Reason, "Q.850;cause=16")
			}
		}
	}

	// NOTIFY specific headers
	// if rqstpk.RequestType == NOTIFY {
	// 	if msgBody.MyBodyType == SIPFragment {
	// 		hdrs.Add("Event", session.Transactions.GenerateReferHeaderForNotifyFromLastREFERCSeqSYNC())
	// 		if msgBody.NotifyResponse < 200 {
	// 			hdrs.Add("Subscription-State", "pending")
	// 		} else {
	// 			hdrs.Add("Subscription-State", "terminated;reason=noresource")
	// 		}
	// 	} else if msgBody.BodyType == SimpleMsgSummary {
	// 		hdrs.Add("Event", session.InitialRequestMessage.Headers.ValueHeader(Event))
	// 		if msgBody.SubscriptionStatusReason == SubsStateReasonNone {
	// 			hdrs.Add("Subscription-State", "active")
	// 			hdrs.Add("Subscription-Expires", fmt.Sprintf("%d", session.MyVoiceMailBox.SubscriptionExpires.Format(DicTFs[TimeFormatSignaling])))
	// 		} else {
	// 			hdrs.Add("Subscription-State", fmt.Sprintf("terminated;reason=%s", msgBody.SubscriptionStatusReason))
	// 		}
	// 		hdrs.Add("Contact", fmt.Sprintf("<%s>", session.MyVoiceMailBox.URI))
	// 	} else if msgBody.BodyType == DTMFRelay {
	// 		hdrs.Add("Event", "telephone-event")
	// 	}
	// }

	// PRACK specific headers
	if sipmsg.StartLine.Method == PRACK && !session.IsPRACKSupported {
		LogWarning(LTSIPStack, fmt.Sprintf("UAS requesting 100rel although not offered - Call ID [%s]", session.CallID))
		hdrs.AddHeader(Warning, `399 SRGo "100rel was not offered, yet it was requested"`)
	}

	// ReINVITE specific headers
	// if sipmsg.StartLine.Method == ReINVITE {
	// 	hdrs.Add("P-Early-Media", "")
	// 	hdrs.Add("Subject", "")
	// 	sipmsg.StartLine.Method = INVITE
	// }

	// OPTIONS specific headers
	// if sipmsg.StartLine.Method == OPTIONS {
	// 	hdrs.Add("Accept", "")
	// }
}
