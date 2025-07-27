package sip

import (
	"cmp"
	"fmt"
	"net"
	"time"

	. "SRGo/global"
	"SRGo/phone"
	"SRGo/q850"
	"SRGo/sip/state"
	"SRGo/sip/status"

	"github.com/Moatassem/sdp"
)

func (ss1 *SipSession) RouteRequestExternal(trans1 *Transaction, sipmsg1 *SipMessage) {
	defer LogCallStack()

	if ss1.RoutingData == nil { // first invocation
		ss1.RoutingData = &RoutingRecord{NoAnswerTimeout: 180, No18xTimeout: 60, MaxCallDuration: 0, OutRuriUserpart: sipmsg1.StartLine.UserPart}

		asskt := ASUserAgent.GetUDPAddr()
		if AreUdpAddrsEqual(ss1.RemoteUDP(), asskt) { // incoming from SIP Layer
			if phone, ok := phone.Phones.Get(ss1.RoutingData.OutRuriUserpart); ok {
				ua := phone.GetUA()
				ss1.RoutingData.RemoteUDPSocket = ua.GetUDPSocket()
				if !phone.IsRegistered {
					ss1.RejectMe(trans1, status.TemporarilyUnavailable, q850.NoAnswerFromUser, "target not registered")
					return
				}
				if !phone.IsReachable {
					ss1.RejectMe(trans1, status.DoesNotExistAnywhere, q850.NoRouteToDestination, "target not reachable")
					return
				}
				// if !ua.IsAlive() {
				// 	ss1.RejectMe(trans1, status.TemporarilyUnavailable, q850.NetworkOutOfOrder, "target not alive")
				// 	return
				// }
				if !sipmsg1.KeepOnlyBodyPart(SDP) {
					ss1.RejectMe(trans1, status.NotAcceptableHere, q850.BearerCapabilityNotAvailable, "no remaining body")
					return
				}
			} else {
				ss1.RejectMe(trans1, status.NotFound, q850.UnallocatedNumber, "No target found")
				return
			}
		} else {
			ss1.RoutingData.RemoteUDPSocket = ASUserAgent.GetUDPSocket()
			sipmsg1.AddRequestedBodyParts()
		}
		// isCallerPhone := phone.Phones.IsPhoneExt(getURIUsername(sipmsg1.FromHeader))
	}

	rd := ss1.RoutingData

	// if isMRF && ss1.IsBeingEstablished() && ss1.IsDelayedOfferCall && !trans1.RequestMessage.IsMethodAllowed(UPDATE) {
	// 	ss1.RejectMe(trans1, status.ServiceUnavailable, q850.InterworkingUnspecified, "Delayed offer with no UPDATE support for MRF")
	// 	return
	// }

	ss2 := NewSS(OUTBOUND)
	ss2.SetRemoteUDP(rd.RemoteUDPSocket.UDPAddr())
	ss2.SetUDPListenser(ss1.UDPListenser())
	ss2.RoutingData = rd
	ss2.IsDelayedOfferCall = ss1.IsDelayedOfferCall

	ss2.LinkedSession = ss1
	ss1.LinkedSession = ss2

	trans2, _ := ss2.CreateLinkedINVITE(rd.OutRuriUserpart, sipmsg1.Body)

	ss2.IsPRACKSupported = ss1.IsPRACKSupported
	// TODO - return target and prefix .. ex. cdpn:+201223309859, prefix: 042544154
	// To header to contain cdpn & ruri-userpart to contain "+" + prefix + cdpn
	// sipmsg2.TranslateRM(ss2, trans2, numtype.CalledRURI, rd.RURIUsername)

	if !ss1.IsBeingEstablished() {
		return
	}

	ss2.SetState(state.BeingEstablished)
	ss2.AddMe()
	ss2.SendSTMessage(trans2)
}

//nolint:cyclop
func (ss1 *SipSession) RouteRequestInternal(trans1 *Transaction, sipmsg1 *SipMessage) {
	defer LogCallStack()

	upart := sipmsg1.StartLine.UserPart

	var upart2 string

	if phone, ok := phone.Phones.Get(upart); ok {
		ss1.RoutingData = &RoutingRecord{NoAnswerTimeout: 60, No18xTimeout: 30, MaxCallDuration: 7200, OutRuriUserpart: upart}
		upart2 = upart
		ua := phone.GetUA()
		ss1.RoutingData.RemoteUDPSocket = ua.GetUDPSocket()
		if !phone.IsRegistered {
			ss1.RejectMe(trans1, status.TemporarilyUnavailable, q850.NoAnswerFromUser, "target not registered")
			return
		}
		if !phone.IsReachable {
			ss1.RejectMe(trans1, status.DoesNotExistAnywhere, q850.NoRouteToDestination, "target not reachable")
			return
		}
		// if !ua.IsAlive() {
		// 	ss1.RejectMe(trans1, status.TemporarilyUnavailable, q850.NetworkOutOfOrder, "target not alive")
		// 	return
		// }
		if !sipmsg1.KeepOnlyBodyPart(SDP) {
			ss1.RejectMe(trans1, status.NotAcceptableHere, q850.BearerCapabilityNotAvailable, "no remaining body")
			return
		}

		goto routeCall
	}

	ss1.RoutingData, upart2 = RoutingEngineDB.Get(upart)
	if ss1.RoutingData != nil {
		switch ss1.RoutingData.OutCallFlow {
		case EchoResponder:
			if ss1.IsDelayedOfferCall {
				ss1.RejectMe(trans1, status.NotAcceptableHere, q850.BearerCapabilityNotAvailable, "Delayed offer not supported")
				return
			} else if !sipmsg1.Body.ContainsSDP() {
				ss1.RejectMe(trans1, status.NotAcceptableHere, q850.BearerCapabilityNotAvailable, "No SDP in echo call")
				return
			}
			ss1.answerEchoCall(trans1, sipmsg1)
			return
		case Transparent:
		case TransformEarlyToFinal:
			if ss1.IsDelayedOfferCall {
				ss1.RejectMe(trans1, status.NotAcceptableHere, q850.BearerCapabilityNotAvailable, "Delayed offer not supported")
				return
			}
		}

		if ss1.RoutingData.No18xTimeout <= 0 && ss1.RoutingData.NoAnswerTimeout <= 0 {
			ss1.RejectMe(trans1, status.ServiceUnavailable, q850.NormalUnspecified, "Answer and 18x Timeouts cannot be both disabled")
			return
		}

		goto routeCall
	}

	// if !sipmsg1.Body.ContainsSDP() {
	// 	ss1.RejectMe(trans1, status.NotAcceptableHere, q850.BearerCapabilityNotImplemented, "Not supported SDP or delay offer")
	// 	return
	// }

	ss1.RejectMe(trans1, status.NotFound, q850.UnallocatedNumber, "No target found")
	return

routeCall:
	rd := ss1.RoutingData

	if rd.SteerMedia {
		ss1.MediaConn = MediaPortPool.ReserveSocket()
		if ss1.MediaConn == nil {
			ss1.RejectMe(trans1, status.ServiceUnavailable, q850.ResourceUnavailableUnspecified, "No media port available for ingress")
			return
		}
		go ss1.HandleNSteerMedia()
	}

	ss2 := NewSS(OUTBOUND)
	ss2.EgressProxy = ProxyUdpServer

	ss2.SetRemoteUDP(cmp.Or(rd.RemoteUDPSocket.UDPAddr(), ss1.RemoteUDP()))

	ss2.SetUDPListenser(ss1.UDPListenser())
	ss2.RoutingData = rd
	ss2.IsDelayedOfferCall = ss1.IsDelayedOfferCall
	ss2.IsPRACKSupported = rd.OutCallFlow == Transparent && ss1.IsPRACKSupported

	ss2.LinkedSession = ss1
	ss1.LinkedSession = ss2

	if rd.SteerMedia {
		ss2.MediaConn = MediaPortPool.ReserveSocket()
		if ss2.MediaConn == nil {
			ss2.DropMe()
			ss1.RejectMe(trans1, status.ServiceUnavailable, q850.ResourceUnavailableUnspecified, "No media port available for egress")
			return
		}
		go ss2.HandleNSteerMedia()
	}

	trans2, _ := ss2.CreateLinkedINVITE(upart2, sipmsg1.Body)

	ss2.TransformEarlyToFinal = rd.OutCallFlow == TransformEarlyToFinal

	if !ss1.IsBeingEstablished() {
		return
	}

	ss2.SetState(state.BeingEstablished)
	ss2.AddMe()
	ss2.SendSTMessage(trans2)
}

func (ss1 *SipSession) RerouteRequest(rspnspk ResponsePack) {
	defer LogCallStack()

	if ss1 == nil {
		return
	}
	var reason string
	switch rspnspk.StatusCode {
	case 487:
		reason = "NOANSWER"
	case 408:
		reason = "UNREACHABLE"
	default:
		reason = "REJECTED"
	}
	trans1 := ss1.GetLastUnACKedInvSYNC(INBOUND)
	if trans1 == nil {
		return
	}
	if ss1.IsBeingEstablished() {
		ss1.LinkedSession = nil
		ss1.RejectMe(trans1, rspnspk.StatusCode, q850.NormalUnspecified, reason)
		return
	}
	// rcv18x := trans1.StatusCodeExistsSYNC(180)
	// if err := failure(reason, rcv18x, ss1.RoutingData); err != nil {
	// 	LogError(LTConfiguration, err.Error())
	// 	if ss1.IsBeingEstablished() {
	// 		ss1.LinkedSession = nil
	// 		ss1.RejectMe(trans1, status.ServiceUnavailable, q850.ExchangeRoutingError, "Rerouting failure")
	// 		return
	// 	}
	// }
	// ss1.RouteRequest(trans1, nil)
}

// ============================================================================

func (ss *SipSession) HandleRefer(trans *Transaction, sipmsg *SipMessage) {
	referRuri, errmsg := sipmsg.GetReferToRUIR()
	if errmsg != "" {
		ss.SendCreatedResponseDetailed(trans, NewResponsePackRFWarning(status.BadRequest, "", errmsg), ZeroBody())
		return
	}

	ss.ReferSubscription = !sipmsg.WithNoReferSubscription()
	if ss.ReferSubscription {
		ss.Relayed18xNotify = nil
	}

	fmt.Println(referRuri)
	ss.SendCreatedResponse(trans, status.OK, ZeroBody())
}

// ============================================================================

func ProbeUA(conn *net.UDPConn, ua *SipUdpUserAgent) {
	if conn == nil || ua == nil {
		return
	}
	ss := NewSS(OUTBOUND)
	ss.SetRemoteUDP(ua.GetUDPAddr())
	ss.SetUDPListenser(conn)
	ss.RemoteUserAgent = ua

	hdrs := NewSipHeaders()
	hdrs.AddHeader(Subject, "Out-of-dialogue keep-alive")
	hdrs.AddHeader(Accept, "application/sdp")

	trans := ss.CreateSARequest(RequestPack{Method: OPTIONS, Max70: true, CustomHeaders: hdrs, RUriUP: "ping", FromUP: "ping", IsProbing: true}, ZeroBody())

	ss.SetState(state.BeingProbed)
	ss.AddMe()
	ss.SendSTMessage(trans)
}

func (ss *SipSession) HandleNSteerMediaWithPool() {
	if ss.MediaConn == nil {
		return
	}

	for {
		buf, _ := RTPRXBufferPool.Get().(*[]byte)
		n, _, err := ss.MediaConn.ReadFromUDP(*buf)
		if err != nil {
			RTPRXBufferPool.Put(buf)
			break
		}
		go func() {
			lnkdss := ss.LinkedSession
			if lnkdss != nil && lnkdss.MediaConn != nil {
				if remoteAddr := lnkdss.RemoteMediaUdpAddr(); remoteAddr != nil {
					lnkdss.MediaConn.WriteToUDP((*buf)[:n], remoteAddr) // data race but not critical
				}
			}
			RTPRXBufferPool.Put(buf)
		}()
	}
}

func (ss *SipSession) HandleNSteerMedia() {
	defer func() {
		if LogCallStack() {
			ss.HandleNSteerMedia()
		}
	}()
	if ss.MediaConn == nil {
		return
	}
	buf := make([]byte, RTPMaxSize)
	for {
		n, _, err := ss.MediaConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		lnkdss := ss.LinkedSession
		if lnkdss != nil && lnkdss.MediaConn != nil {
			if remoteAddr := lnkdss.RemoteMediaUdpAddr(); remoteAddr != nil {
				lnkdss.MediaConn.WriteToUDP(buf[:n], remoteAddr)
			}
		}
	}
}

func (ss *SipSession) HandleEchoResponderMedia() {
	defer func() {
		if LogCallStack() {
			ss.HandleEchoResponderMedia()
		}
	}()
	if ss.MediaConn == nil {
		return
	}
	buf := make([]byte, RTPMaxSize)
	for {
		n, addr, err := ss.MediaConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if ss.isHeld {
			continue
		}
		if _, err := ss.MediaConn.WriteToUDP(buf[:n], addr); err != nil {
			break
		}
	}
}

func (ss *SipSession) answerEchoCall(trans *Transaction, sipmsg *SipMessage) {
	if ss == nil || trans == nil || sipmsg == nil {
		return
	}

	content, _ := sipmsg.GetBodyPart(SDP)

	sdp1, err := sdp.Parse(content.Bytes)
	if err != nil {
		LogError(LTSDPStack, fmt.Sprintf("Failed to parse SDP: %v", err))
		ss.RejectMe(trans, status.NotAcceptableHere, q850.FacilityRejected, "Bad SDP in echo call")
		return
	}

	if ss.MediaConn = MediaPortPool.ReserveSocket(); ss.MediaConn == nil {
		ss.RejectMe(trans, status.ServiceUnavailable, q850.ResourceUnavailableUnspecified, "No media port available for ingress")
		return
	}

	sdp2, _, err := sdp1.BuildEchoResponderAnswer(sdp.SupportedCodecsStringList...)
	if err != nil {
		ss.RejectMe(trans, status.ServerInternalError, q850.NormalUnspecified, err.Error())
		return
	}

	ss.SendCreatedResponse(trans, 180, ZeroBody())

	time.Sleep(EchoAnswerDelaySec * time.Second)

	if !ss.IsBeingEstablished() {
		return
	}

	msgbody := sipmsg.Body
	msgbody.SdpSession = sdp2

	ss.SendCreatedResponse(trans, 200, msgbody)
	ss.isHeld = sdp1.IsCallHeld()

	go ss.HandleEchoResponderMedia()
}
