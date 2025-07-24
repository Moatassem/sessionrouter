package sip

import (
	"errors"
	"fmt"
	"strings"

	. "SRGo/global"
	"SRGo/phone"
	"SRGo/q850"
	"SRGo/sip/mode"
	"SRGo/sip/state"
	"SRGo/sip/status"
)

func processPDU(payload []byte) (*SipMessage, []byte, error) {
	defer func() {
		// check if pdu is rqst >> send 400 with Warning header indicating what was wrong or unable to parse
		// or discard rqst if totally wrong
		// if pdu is rsps >> discard
		// in any case, log this pdu by saving its hex stream and why it was wrong
		LogCallStack()
	}()

	var msgType MessageType
	var startLine StartLine

	sipmsg := new(SipMessage)
	msgmap := NewSHsPointer(false)

	var idx int
	var _dblCrLfIdx, _bodyStartIdx, lnIdx, cntntLength int

	_dblCrLfIdxInt := GetNextIndex(payload, "\r\n\r\n")

	if _dblCrLfIdxInt == -1 {
		// empty sip message
		return nil, nil, nil
	}

	_dblCrLfIdx = _dblCrLfIdxInt

	msglines := strings.Split(string(payload[:_dblCrLfIdx]), "\r\n")

	lnIdx = 0

	// start line parsing
	if matches := RMatch(msglines[lnIdx], RequestStartLinePattern); len(matches) > 0 {
		msgType = REQUEST
		startLine.StatusCode = 0
		startLine.Method = MethodFromName(ASCIIToUpper(matches[1]))
		if startLine.Method == UNKNOWN {
			return sipmsg, nil, errors.New("invalid method for Request message")
		}
		startLine.RUri = matches[2]
		// startLine.StartLine = msglines[0]
		if startLine.Method == INVITE {
			if matches := RMatch(startLine.RUri, INVITERURI); len(matches) > 0 {
				startLine.UriScheme = ASCIIToLower(matches[1])
				startLine.OriginalUP = matches[2]
				startLine.UserPart = DropVisualSeparators(startLine.OriginalUP)
				startLine.UserParameters = ExtractParameters(matches[3], false)
				startLine.Password = matches[4]
				startLine.HostPart = matches[5]
				startLine.UriParameters = ExtractParameters(matches[6], false)
				startLine.UriHeaders = matches[7]
			}
		}
	} else {
		if matches := RMatch(msglines[lnIdx], ResponseStartLinePattern); len(matches) > 0 {
			msgType = RESPONSE
			code := Str2Int[int](matches[2])
			if code < 100 || code > 699 {
				return nil, nil, errors.New("invalid code for Response message")
			}
			startLine.StatusCode = code
			startLine.ReasonPhrase = matches[3]
			startLine.UriParameters = ParseParameters(matches[4])
			// startLine.StartLine = msglines[0]
		} else {
			sipmsg.MsgType = INVALID
			return sipmsg, nil, errors.New("invalid message")
		}
	}
	sipmsg.MsgType = msgType
	sipmsg.StartLine = &startLine

	lnIdx++

	// headers parsing

	isViaTried := false // to signal the processing of the first encountered Via header

	for i := lnIdx; i < len(msglines) && msglines[i] != ""; i++ {
		matches := DicFieldRegExp[FullHeader].FindStringSubmatch(msglines[i])
		if matches != nil {
			headerLC := ASCIIToLower(matches[1])
			value := matches[2]
			switch headerLC {
			case From.LowerCaseString():
				tag := DicFieldRegExp[Tag].FindStringSubmatch(value)
				if tag != nil {
					sipmsg.FromTag = tag[1]
				}
				sipmsg.FromHeader = value
			case To.LowerCaseString():
				tag := DicFieldRegExp[Tag].FindStringSubmatch(value)
				if tag != nil && tag[1] != "" {
					sipmsg.ToTag = tag[1]
					if startLine.Method == INVITE {
						startLine.Method = ReINVITE
					}
				}
				sipmsg.ToHeader = value
			case P_Asserted_Identity.LowerCaseString():
				sipmsg.PAIHeaders = append(sipmsg.PAIHeaders, value)
			case Diversion.LowerCaseString():
				sipmsg.DivHeaders = append(sipmsg.DivHeaders, value)
			case Call_ID.LowerCaseString():
				sipmsg.CallID = value
			case Max_Forwards.LowerCaseString():
				maxf, ok := Str2IntCheck[int](value)
				if !ok {
					LogError(LTSIPStack, "Invalid Max-Forwards header - "+value)
				} else if maxf > 255 {
					LogError(LTSIPStack, "Invalid Max-Forwards header - Too big")
				} else {
					sipmsg.MaxFwds = maxf
				}
			case Contact.LowerCaseString():
				rc := DicFieldRegExp[URIFull].FindStringSubmatch(value)
				if rc != nil {
					sipmsg.RCURI = rc[1]
				}
			case CSeq.LowerCaseString():
				cseq := DicFieldRegExp[CSeqHeader].FindStringSubmatch(value)
				if cseq == nil {
					LogError(LTSIPStack, "Invalid CSeq header")
					return nil, nil, errors.New("invalid CSeq header")
				}
				sipmsg.CSeqNum = Str2Uint[uint32](cseq[1])
				sipmsg.CSeqMethod = MethodFromName(cseq[2])
				if startLine.StatusCode == 0 {
					r1 := startLine.Method.String()
					r2 := ASCIIToUpper(cseq[2])
					if r1 != r2 {
						LogError(LTSIPStack, fmt.Sprintf("Invalid Request Method: %s vs CSeq Method: %s", r1, r2))
						return nil, nil, errors.New("invalid CSeq header")
					}
				}
			case Via.LowerCaseString():
				if !isViaTried {
					isViaTried = true
					via := DicFieldRegExp[ViaBranchPattern].FindStringSubmatch(value)
					if via == nil {
						break
					}
					skt := DicFieldRegExp[ViaIPv4Socket].FindStringSubmatch(value)
					if len(skt) > 0 {
						sipmsg.ViaUdpAddr, _ = BuildUdpAddr(skt[2]+":"+skt[3], SipPort)
					}
					sipmsg.ViaBranch = via[1]
					if !strings.HasPrefix(via[1], MagicCookie) {
						LogWarning(LTSIPStack, fmt.Sprintf("Received message [%s] having non-RFC3261 Via branch [%s]", startLine.Method.String(), via[1]))
					}
					if len(via[1]) <= len(MagicCookie) {
						LogWarning(LTSIPStack, fmt.Sprintf("Received message [%s] having too short Via branch [%s]", startLine.Method.String(), via[1]))
					}
				}
			}
			msgmap.Add(headerLC, value)
		}
	}

	if ko, hdr := msgmap.AnyMandatoryHeadersMissing(startLine.Method); ko {
		LogError(LTBadSIPMessage, fmt.Sprintf("Missing mandatory header [%s]", hdr))
		return nil, nil, errors.New("missing mandatory header")
	}

	if msgmap.HeaderCount("CSeq") > 1 {
		LogError(LTBadSIPMessage, "Duplicate CSeq header")
		return nil, nil, errors.New("duplicate CSeq header")
	}

	if msgmap.HeaderCount("Content-Length") > 1 {
		LogError(LTBadSIPMessage, "Duplicate Content-Length header")
		return nil, nil, errors.New("duplicate Content-Length header")
	}

	_bodyStartIdx = _dblCrLfIdx + 4 // CrLf x 2

	// automatic deducing of content-length
	cntntLength = len(payload) - _bodyStartIdx
	sipmsg.ContentLength = cntntLength

	if ok, values := msgmap.ValuesHeader(Content_Length); ok {
		cntntLength = Str2Int[int](values[0])
	} else {
		if ok, _ := msgmap.ValuesHeader(Content_Type); ok {
			msgmap.AddHeader(Content_Length, Int2Str(cntntLength))
		} else {
			msgmap.AddHeader(Content_Length, "0")
		}
	}
	sipmsg.Headers = msgmap

	// body parsing
	if cntntLength == 0 {
		payload = payload[_bodyStartIdx:]
		return sipmsg, payload, nil
	}

	if len(payload) < _bodyStartIdx+cntntLength {
		LogError(LTBadSIPMessage, "bad content-length or fragmented pdu")
		return nil, nil, errors.New("bad content-length or fragmented pdu")
	}
	// ---------------------------------
	MB := NewBody()

	var cntntTypeSections map[string]string
	ok, v := msgmap.ValuesHeader(Content_Type)
	if !ok {
		return nil, nil, errors.New("bad message - invalid body")
	}
	cntntTypeSections = ExtractParameters(v[0], true)
	if cntntTypeSections == nil {
		LogWarning(LTSIPStack, "Content-Type header is missing while Content-Length is non-zero - Message skipped")
		return nil, nil, errors.New("bad message - invalid body")
	}

	cntntType := ASCIIToLower(cntntTypeSections["!headerValue"])

	if !strings.Contains(cntntType, "multipart") {
		bt := GetBodyType(cntntType)
		if bt == Unknown {
			LogError(LTBadSIPMessage, "Unknown Content-Type value")
		} else {
			MB.PartsContents[bt] = ContentPart{Bytes: payload[_bodyStartIdx : _bodyStartIdx+cntntLength]}
		}
		payload = payload[_bodyStartIdx+cntntLength:]
	} else {
		payload = payload[_bodyStartIdx:]
		boundary := cntntTypeSections["boundary"]
		markBoundary := "--" + boundary
		endBoundary := "--" + boundary + "--\r\n"
		var idxEnd, partsCount int
		for {
			idx = GetNextIndex(payload, markBoundary)
			if idx == -1 || string(payload) == endBoundary {
				break
			}
			payload = payload[idx+len(markBoundary)+2:]
			idx = GetNextIndex(payload, "\r\n\r\n")
			idxEnd = GetNextIndex(payload, markBoundary)
			bt := None
			partHeaders := NewSipHeaders()
			for ln := range strings.SplitSeq(string(payload[:idx]), "\r\n") {
				if matches := DicFieldRegExp[FullHeader].FindStringSubmatch(ln); len(matches) > 0 {
					h := matches[1]
					partHeaders.Add(h, matches[2])
					if Content_Type.Equals(h) {
						cntntType = matches[2]
						bt = GetBodyType(cntntType)
					}
				}
			}
			//nolint:exhaustive
			switch bt {
			case None:
				LogError(LTBadSIPMessage, "Missing body part Content-Type - skipped")
			case Unknown:
				LogError(LTBadSIPMessage, "Unknown Content-Type value - skipped")
			default:
				MB.PartsContents[bt] = ContentPart{
					Headers: partHeaders,
					Bytes:   payload[idx+4 : idxEnd-2], // start_after \r\n\r\n (body_start) = +4 and end_before \r\n = -2 (boundary_edge)
				}
			}
			payload = payload[idxEnd:]
			partsCount++
		}
		if len(MB.PartsContents) < partsCount {
			LogError(LTBadSIPMessage, "One or more body parts have been skipped")
		}
	}

	sipmsg.Body = MB

	return sipmsg, payload, nil
}

//nolint:cyclop
func sessionGetter(sipmsg *SipMessage) (*SipSession, NewSessionType) {
	defer LogCallStack()

	callID := sipmsg.CallID
	if sipses, ok := Sessions.Load(callID); ok {
		if sipses.IsDuplicateMessage(sipmsg) || sipmsg.GetMethod() == INVITE {
			return sipses, DuplicateMessage
		}

		return sipses, ValidRequest
	}

	if sipmsg.IsResponse() {
		return nil, Response
	}

	sipses := NewSIPSession(sipmsg)
	exceededRate := Sessions.Store(callID, sipses)
	if sipmsg.ToTag != "" {
		return sipses, CallLegTransactionNotExist
	}
	switch sipmsg.GetMethod() {
	case INVITE:
		sipses.Mymode = mode.Multimedia
		sipses.IsPRACKSupported = sipmsg.IsOptionSupported("100rel")
		sipses.IsDelayedOfferCall = !sipmsg.ContainsSDP()
		sipses.SetState(state.BeingEstablished)
		if !sipmsg.IsKnownRURIScheme() {
			return sipses, UnsupportedURIScheme
		}
		if sipmsg.WithUnknownBodyPart() {
			return sipses, UnsupportedBody
		}
		if sipmsg.Headers.HeaderExists("Require") {
			return sipses, WithRequireHeader
		}
		if sipmsg.MaxFwds <= MinMaxFwds {
			return sipses, TooLowMaxForwards
		}
		if exceededRate {
			return sipses, ExceededCallRate
		}
		return sipses, ValidRequest
	case MESSAGE:
		sipses.Mymode = mode.Messaging
		return sipses, ValidRequest
	case SUBSCRIBE:
		sipses.Mymode = mode.Subscription
		return sipses, ValidRequest
	case OPTIONS:
		sipses.Mymode = mode.KeepAlive
		return sipses, ValidRequest
	case REGISTER:
		sipses.Mymode = mode.Registration
		return sipses, ValidRequest
	case REFER, NOTIFY, UPDATE, PRACK, INFO, PUBLISH, NEGOTIATE:
		return sipses, InvalidRequest
	case ACK:
		return sipses, UnExpectedMessage
	default:
		return sipses, CallLegTransactionNotExist
	}
}

func sipStack(sipmsg *SipMessage, ss *SipSession, newSesType NewSessionType) {
	defer LogCallStack()

	if ss == nil || newSesType == DuplicateMessage {
		return
	}
	ss.UpdateContactRecordRouteBody(sipmsg) // update -- split headers logic

	var trans *Transaction
	if sipmsg.IsRequest() {
		trans = ss.addIncomingRequest(sipmsg, nil)
	} else {
		trans = ss.addIncomingResponse(sipmsg)
	}

	if trans == nil {
		LogWarning(LTSIPStack, fmt.Sprintf("Received message [%s] in Call-ID [%s] has been discarded due to transaction violation", sipmsg.String(), ss.CallID))
		if ss.HasNoTransactions() {
			ss.DropMe()
		}
		return
	}

	switch newSesType {
	case Response:
		return
	case UnExpectedMessage:
		ss.DropMe()
		return
	case TooLowMaxForwards:
		ss.RejectMe(trans, status.TooManyHops, q850.NoRCProvided, "INVITE with too low MF")
		return
	case WithRequireHeader:
		ss.RejectMe(trans, status.BadExtension, q850.NoRCProvided, "INVITE with Require header")
		return
	case UnsupportedURIScheme:
		ss.RejectMe(trans, status.UnsupportedURIScheme, q850.NoRCProvided, "URI scheme unsupported")
		return
	case UnsupportedBody:
		ss.RejectMe(trans, status.UnsupportedMediaType, q850.NoRCProvided, "Message body unsupported")
		return
	case ExceededCallRate:
		ss.RejectMe(trans, status.ServiceUnavailable, q850.NoCircuitChannelAvailable, "Call rate exceeded")
		return
	case InvalidRequest:
		ss.SetState(state.BeingFailed)
		ss.SendCreatedResponse(trans, 503, ZeroBody())
		ss.DropMe()
		return
	case CallLegTransactionNotExist:
		if sipmsg.StartLine.Method != ACK {
			ss.SetState(state.Dropped)
			ss.SendCreatedResponse(trans, 481, ZeroBody())
		}
		ss.DropMe()
		return
	}

	if sipmsg.IsRequest() {
		if sipmsg.WithUnknownBodyPart() {
			ss.SendCreatedResponse(trans, status.UnsupportedMediaType, ZeroBody())
			return
		}
		//nolint:exhaustive
		switch sipmsg.GetMethod() {
		case INVITE:
			ss.SendCreatedResponse(trans, status.Trying, ZeroBody())
			if sippTesting {
				ss.SendCreatedResponse(trans, status.Ringing, ZeroBody())
				ss.SendCreatedResponse(trans, status.OK, ZeroBody())
				return
			}
			if SkipAS {
				ss.RouteRequestInternal(trans, sipmsg) // use internal AS
				return
			}
			ss.RouteRequestExternal(trans, sipmsg) // use external AS
		case ReINVITE:
			ss.SendCreatedResponse(trans, 100, ZeroBody())
			lnkdss := ss.LinkedSession
			if lnkdss == nil {
				if sipmsg.ContainsSDP() {
					if sts, warn, callheld := sipmsg.ParseSDPPartAndBuildAnswer(); sts == 200 {
						ss.SendCreatedResponse(trans, sts, sipmsg.Body)
						ss.isHeld = callheld
					} else {
						ss.SendCreatedResponseDetailed(trans, NewResponsePackWarning(sts, warn), ZeroBody())
					}
				} else {
					ss.SendCreatedResponseDetailed(trans, NewResponsePackWarning(488, "Delayed-offer ReINVITE not supported"), ZeroBody())
				}
				return
			}
			if !ss.ChecknSetDialogueChanging(true) || lnkdss.IsDialogueChanging() {
				ss.SendCreatedResponseDetailed(trans, NewResponsePackRFWarning(status.RequestPending, "", "Competing ReINVITE rejected"), ZeroBody())
				return
			}
			if lnkdss.TransformEarlyToFinal {
				if sipmsg.ContainsSDP() {
					lnkdss.SendCreatedRequest(UPDATE, trans, sipmsg.Body)
				} else {
					ss.SendCreatedResponse(trans, 488, ZeroBody())
				}
				return
			}
			lnkdss.SendCreatedRequest(ReINVITE, trans, sipmsg.Body)
		case ACK:
			if trans.Method == INVITE {
				ss.FinalizeState()
				if !ss.IsEstablished() { // call cleared - no need to propagate ACK, since clearing is handled locally per session
					ss.DropMe()
					return
				}
				ss.StartMaxCallDuration()
				ss.StartInDialogueProbing()
				if lnkdss := ss.LinkedSession; lnkdss != nil && !lnkdss.TransformEarlyToFinal { // call answered - need to propagate ACK
					lnkdss.FinalizeState()
					lnkdss.SendCreatedRequest(ACK, nil, sipmsg.Body)
				}
			} else { // ReINVITE
				if lnkdss := ss.LinkedSession; lnkdss != nil && trans.LinkedTransaction != nil {
					if trans.LinkedTransaction.IsFinalResponsePositiveSYNC() {
						ss.ChecknSetDialogueChanging(false)
						lnkdss.ChecknSetDialogueChanging(false)
					}
					if !lnkdss.TransformEarlyToFinal {
						lnkdss.SendCreatedRequest(ACK, trans.LinkedTransaction, sipmsg.Body)
					}
				}
			}
		case CANCEL:
			if !ss.IsBeingEstablished() {
				ss.SendCreatedResponseDetailed(trans, ResponsePack{StatusCode: 400, ReasonPhrase: "Incompatible Method With Session State"}, ZeroBody())
				return
			}
			ss.SetState(state.BeingCancelled)
			ss.SendCreatedResponse(trans, 200, ZeroBody())
			if lnkdss := ss.LinkedSession; lnkdss != nil {
				lnkdss.StopAllOutTransactions()
				if lnkdss.ReleaseMe("Caller cleared the call", nil) {
					return
				}
				lnkdss.CancelMe(-1, "")
			}
			ss.SendCreatedResponseDetailed(nil, ResponsePack{StatusCode: 487, CustomHeaders: NewSHQ850OrSIP(487, "", "")}, ZeroBody())
		case BYE:
			if !ss.IsEstablished() {
				ss.SendCreatedResponseDetailed(trans, ResponsePack{StatusCode: 400, ReasonPhrase: "Incompatible Method With Session State"}, ZeroBody())
				return
			}
			ss.SetState(state.Cleared)
			ss.SendCreatedResponse(trans, status.OK, ZeroBody())
			ss.DropMe()
			if lnkdss := ss.LinkedSession; lnkdss != nil {
				lnkdss.StopAllOutTransactions()
				if lnkdss.ReleaseMe("Caller cleared the call", trans) {
					return
				}
				lnkdss.CancelMe(16, "Caller cleared the call")
			}
		case OPTIONS:
			if sipmsg.IsOutOfDialgoue() { // incoming probing
				ss.SetState(state.Probed)
				ss.SendCreatedResponse(trans, 200, ZeroBody())
				ss.DropMe()
				return
			}
			// TODO pass it on or handle locally
			ss.SendCreatedResponse(trans, 200, ZeroBody()) // handle in-dialogue locally
		case UPDATE:
			if sipmsg.WithNoBody() {
				ss.SendCreatedResponse(trans, 200, ZeroBody()) // handle in-dialogue locally
				return
			}
			lnkdss := ss.LinkedSession
			if lnkdss == nil {
				if sipmsg.ContainsSDP() {
					if sts, warn, callheld := sipmsg.ParseSDPPartAndBuildAnswer(); sts == 200 {
						ss.SendCreatedResponse(trans, sts, sipmsg.Body)
						ss.isHeld = callheld
					} else {
						ss.SendCreatedResponseDetailed(trans, NewResponsePackWarning(sts, warn), ZeroBody())
					}
				} else {
					ss.SendCreatedResponseDetailed(trans, NewResponsePackWarning(488, "Not Supported"), ZeroBody())
				}
				return
			}
			if !ss.ChecknSetDialogueChanging(true) || lnkdss.IsDialogueChanging() {
				ss.SendCreatedResponseDetailed(trans, NewResponsePackRFWarning(status.RequestPending, "", "Competing Update rejected"), ZeroBody())
				return
			}
			lnkdss.SendCreatedRequest(UPDATE, trans, sipmsg.Body)
		case PRACK:
			if trans.PrackStatus != PRACKExpected {
				ss.SendCreatedResponseDetailed(trans, NewResponsePackRFWarning(status.BadRequest, "", "Bad or missing RAck header"), ZeroBody())
				return
			}
			ss.SendCreatedResponse(trans, status.OK, ZeroBody())
			if lnkdss := ss.LinkedSession; lnkdss != nil {
				lnkdss.SendCreatedRequest(PRACK, trans.LinkedTransaction, sipmsg.Body)
			}
		case REFER:
			lnkdss := ss.LinkedSession
			if !ss.IsEstablished() || !lnkdss.IsEstablished() {
				ss.SendCreatedResponseDetailed(trans, NewResponsePackRFWarning(status.TemporarilyUnavailable, "", "REFER received during early dialogue"), ZeroBody())
				return
			}
			ss.HandleRefer(trans, sipmsg) // process Refer-To RURI and route the call
		case NOTIFY:
			ss.SendCreatedResponse(trans, status.MethodNotAllowed, ZeroBody())
		case INFO:
			if lnkdss := ss.LinkedSession; lnkdss != nil {
				lnkdss.SendCreatedRequest(INFO, trans, sipmsg.Body)
			}
		case REGISTER:
			contact, ext, ruri, ipport, expires := sipmsg.GetRegistrationData()
			defer ss.DropMe()
			if expires < 0 {
				ss.SetState(state.Dropped)
				ss.SendCreatedResponseDetailed(trans, NewResponsePackRFWarning(400, "", "Bad Contact header"), ZeroBody())
				return
			}
			ss.SetState(phone.Phones.AddOrUpdate(ext, ruri, ipport, expires))
			ss.SendCreatedResponseDetailed(trans, ResponsePack{StatusCode: 200, ContactHeader: contact}, ZeroBody())
		default: // SUBSCRIBE, MESSAGE, PUBLISH, NEGOTIATE
			ss.SetState(state.Dropped)
			ss.SendCreatedResponse(trans, status.MethodNotAllowed, ZeroBody())
			ss.DropMe()
		}
	} else {
		stsCode := sipmsg.StartLine.StatusCode
		if stsCode <= 199 && trans.Method != INVITE {
			return
		}
		if lnkdss := ss.LinkedSession; lnkdss != nil {
			switch {
			case 180 <= stsCode && stsCode <= 189:
				if !ss.IsBeingEstablished() {
					return
				}
				ss.StopTimer(No18x)
				if ss.TransformEarlyToFinal {
					if sipmsg.ContainsSDP() {
						if !ss.Received18xSDP() {
							ss.SetReceived18xSDP()
							lnkdss.SendCreatedResponse(nil, 200, sipmsg.Body)
						}
					} else {
						if !ss.Received18xSDP() {
							lnkdss.SendCreatedResponse(nil, stsCode, ZeroBody())
						}
					}
					return
				}
				rspspk := ResponsePack{StatusCode: stsCode}
				if sipmsg.IsOptionRequired("100rel") {
					rspspk.LinkedPRACKST = ss.GenerateOutgoingPRACKST(sipmsg)
				}
				if lnkdss.IsBeingEstablished() {
					lnkdss.SendCreatedResponseDetailed(nil, rspspk, sipmsg.Body)
				}
			case stsCode <= 199:
				if ss.IsBeingEstablished() {
					ss.StartTimer(No18x)
					ss.StartTimer(NoAnswer)
				}
			case stsCode <= 299:
				switch trans.Method {
				case INVITE:
					if !ss.IsBeingEstablished() {
						ss.StopAllOutTransactions()
						ss.SendCreatedRequest(ACK, nil, ZeroBody())
						ss.WaitMS(100)
						ss.SendCreatedRequestDetailed(RequestPack{Method: BYE, CustomHeaders: NewSHQ850OrSIP(487, "Call cancelled already", "")}, nil, ZeroBody())
						return
					}
					ss.StopNoTimers()
					if ss.TransformEarlyToFinal {
						ss.TransformEarlyToFinal = false
						if ss.Received18xSDP() {
							ss.FinalizeState()
							ss.SendCreatedRequest(ACK, nil, ZeroBody())
							return
						}
					}
					lnkdss.SendCreatedResponse(nil, stsCode, sipmsg.Body)
				case CANCEL:
				case OPTIONS: // probing or keepalive
				case UPDATE:
					ss.ChecknSetDialogueChanging(false)
					lnkdss.ChecknSetDialogueChanging(false)
					lnkdss.SendCreatedResponse(trans.LinkedTransaction, stsCode, sipmsg.Body)
				case ReINVITE:
					lnkdss.SendCreatedResponse(trans.LinkedTransaction, stsCode, sipmsg.Body)
				case BYE:
					ss.StopAllOutTransactions()
					ss.FinalizeState()
					ss.DropMe()
				case INFO:
				}
			case stsCode <= 399:
				switch trans.Method {
				case INVITE:
					ss.StopNoTimers()
					ss.Ack3xxTo6xx(state.Redirected)
					lnkdss.RerouteRequest(NewResponsePackSRW(stsCode, "Call redirected but forbidden", ""))
				default:
					LogWarning(LTSIPStack, "Received 3xx response on non-INVITE message")
					if trans.Method == CANCEL || trans.Method == BYE {
						ss.DropMe()
						return
					}
					ss.FinalizeState()
					ss.ReleaseCall("Exotic 3xx response received on non-INVITE")
				}
			default: // 400-699
				switch trans.Method {
				case INVITE:
					switch ss.GetState() {
					case state.BeingEstablished:
						ss.StopNoTimers()
						ss.Ack3xxTo6xx(state.Rejected)
						if ss.TransformEarlyToFinal {
							ss.TransformEarlyToFinal = false
							if lnkdss.ReleaseMe("Called rejected the call", nil) {
								return
							}
							lnkdss.RejectMe(nil, stsCode, 31, "Called rejected the call")
							return
						}
						lnkdss.RerouteRequest(NewResponsePackSRW(stsCode, "Call failed or rejected", sipmsg.Headers.ValueHeader(Reason)))
					case state.BeingCancelled:
						ss.Ack3xxTo6xxFinalize()
					}
				case ReINVITE, UPDATE:
					lnkdss.SendCreatedResponse(trans.LinkedTransaction, stsCode, sipmsg.Body)
				case BYE:
					ss.StopAllOutTransactions()
					ss.FinalizeState()
					ss.DropMe()
				case OPTIONS: // probing or keepalive
					if trans.IsProbing && (stsCode == 408 || stsCode == 481) {
						ss.ReleaseCall("Probing rejected but unexpectedly")
					}
				}
			}
		} else {
			switch {
			case 180 <= stsCode && stsCode <= 189:
			case stsCode <= 199:
			case stsCode <= 299:
				switch trans.Method {
				case INFO:
				case OPTIONS: // probing or keepalive
					if ss.Mymode == mode.KeepAlive {
						ss.FinalizeState()
						ss.RemoteUserAgent.SetAlive(true)
						ss.DropMe()
					}
				case BYE:
					ss.StopAllOutTransactions()
					ss.FinalizeState()
					ss.DropMe()
				}
			case stsCode <= 399:
			default: // 400-699
				//nolint:exhaustive
				switch trans.Method {
				case OPTIONS: // probing or keepalive
					if ss.Mymode == mode.KeepAlive {
						ss.FinalizeState()
						ss.RemoteUserAgent.SetAlive(true)
						ss.DropMe()
					}
				}
			}
		}
	}
}
