package sip

import (
	. "SRGo/global"
	"cmp"
	"fmt"
	"log"
)

func (session *SipSession) addIncomingRequest(requestMsg *SipMessage, lt *Transaction) *Transaction {
	session.TransLock.Lock()
	defer session.TransLock.Unlock()

	rType := requestMsg.StartLine.Method

	// Stop retransmitting any pending outgoing requests after receiving BYE
	if rType == BYE {
		for _, pendingST := range session.GetPendingOutgoingTransactions() {
			pendingST.StopTransTimer(true)
		}
		for _, pendingST := range session.GetPendingIncomingTransactions() {
			if pendingST.Method == INVITE && pendingST.IsFinalized && !pendingST.IsACKed {
				pendingST.StopTransTimer(true)
				CheckPendingTransaction(session, pendingST)
			}
		}
	}

	//nolint:exhaustive
	switch rType {
	case ACK:
		reInviteST := session.GetReOrInviteTransaction(requestMsg.CSeqNum, true)
		if reInviteST == nil {
			return nil
		}
		if reInviteST.IsACKed {
			LogWarning(LTSIPStack, fmt.Sprintf("Received duplicate ACK for %s – Call-ID [%s]", reInviteST.RequestMessage.StartLine.Method.String(), requestMsg.CallID))
			return nil
		}
		if reInviteST.RequireSameViaBranch() == (reInviteST.ViaBranch == requestMsg.ViaBranch) {
			reInviteST.IsACKed = true
			reInviteST.StopTransTimer(true)
			return reInviteST
		}
		LogError(LTSIPStack, fmt.Sprintf("Received ACK with improper Via-Branch for %s – Call-ID [%s]", reInviteST.RequestMessage.StartLine.Method.String(), requestMsg.CallID))
		return nil
	case CANCEL:
		inviteST := session.GetReOrInviteTransaction(requestMsg.CSeqNum, false)
		if inviteST == nil {
			st := NewSIPTransaction_RT(requestMsg, lt, session)
			session.AddTransaction(st)
			return st
		}
		if inviteST.ViaBranch == requestMsg.ViaBranch {
			st := NewSIPTransaction_RT(requestMsg, inviteST, session)
			session.AddTransaction(st)
			return st
		}
		log.Printf("Received CANCEL with improper Via-Branch for INVITE – Call-ID [%s]", requestMsg.CallID)
		return nil
	case PRACK:
		var prackST *Transaction
		if rSeq, cSeq, ok := requestMsg.GetRSeqFromRAck(); ok {
			prackST = session.GetPRACKTransaction(rSeq, cSeq)
			if prackST == nil {
				prackST = NewSIPTransaction_RP(0, PRACKUnexpected)
				session.AddTransaction(prackST)
				LogError(LTSIPStack, fmt.Sprintf("Cannot find unPRACKed 1xx response for the incoming PRACK – Call-ID [%s]", requestMsg.CallID))
			}
		} else {
			prackST = NewSIPTransaction_RP(0, PRACKMissingBadRAck)
			session.AddTransaction(prackST)
			LogError(LTSIPStack, fmt.Sprintf("Cannot parse RAck header or it is missing for the incoming PRACK – Call-ID [%s]", requestMsg.CallID))
		}
		prackST.RequestMessage = requestMsg
		prackST.CSeq = requestMsg.CSeqNum
		prackST.ViaBranch = requestMsg.ViaBranch
		return prackST
	default:
		if rType == INVITE && session.IsDuplicateINVITE(requestMsg) {
			return nil
		}
		st := NewSIPTransaction_RT(requestMsg, lt, session)
		// lastST := session.LastTransaction()
		// if lastST != nil && SIPConfig.BlockFastTransactions {
		// 	st.IsFastTrans = time.Since(lastST.TimeStamp).Milliseconds() <= SIPConfig.FastTransDeltaTime
		// }
		if rType.IsDialogueCreating() && session.Direction == INBOUND {
			session.FromHeader = requestMsg.FromHeader
			session.ToHeader = requestMsg.ToHeader
			session.FromTag = requestMsg.FromTag
			st.From = session.FromHeader
			st.To = requestMsg.ToHeader
			st.RequestMessage = requestMsg
		}
		session.AddTransaction(st)
		return st
	}
}

func (session *SipSession) addIncomingResponse(responseMsg *SipMessage) *Transaction {
	st := session.GetTransactionSYNC(responseMsg)
	if st != nil {
		st.Lock.Lock()
		rc := responseMsg.StartLine.StatusCode
		st.StopTransTimer(false)
		st.Responses = append(st.Responses, rc)
		st.IsFinalized = cmp.Or(st.IsFinalized, rc >= 200)
		if st.IsFinalized {
			switch st.Method {
			case CANCEL:
				st.LinkedTransaction.StartCancelTimer(session)
			case INVITE:
				st.StopCancelTimerSYNC()
			}
		}
		st.Lock.Unlock()

		// Handle ToTag assignment if the session direction is outbound
		if responseMsg.ToTag != "" && session.Direction == OUTBOUND && session.ToTag == "" {
			session.ToTag = responseMsg.ToTag
			session.ToHeader = responseMsg.Headers.ValueHeader(To)
			st.To = session.ToHeader
		}
	}
	return st
}

//nolint:cyclop
func (session *SipSession) addOutgoingRequest(rt Method, lt *Transaction) *Transaction {
	// Reject any pending incoming requests before sending BYE
	if rt == BYE {
		for _, pendingST := range session.GetPendingIncomingTransactionsSYNC() {
			session.SendCreatedResponseDetailed(pendingST, ResponsePack{StatusCode: 503, CustomHeaders: NewSHQ850OrSIP(31, "Session being cleared", "")}, ZeroBody())
		}
	}

	session.TransLock.Lock()
	defer session.TransLock.Unlock()

	var st *Transaction

	if session.Direction == OUTBOUND {
		//nolint:exhaustive
		switch rt {
		case ACK:
			if lt == nil {
				lt = session.GetUnACKedINVorReINV()
			}
			if lt == nil {
				LogError(LTSIPStack, fmt.Sprintf("Unable to find applicable (Re)INVITE transaction for Call-ID [%s]", session.CallID))
				return nil
			}
			lt.IsACKed = true
			st = lt.CreateACKST()
		case CANCEL:
			if lt == nil {
				lt = session.GetLastUnACKedINV(OUTBOUND)
			}
			if lt == nil {
				LogError(LTSIPStack, fmt.Sprintf("Unable to find applicable INVITE transaction for Call-ID [%s]", session.CallID))
				return nil
			}
			st = lt.CreateCANCELST()
			session.AddTransaction(st)
		default:
			// Increment forward CSeq
			if session.FwdCSeq == 0 {
				session.FwdCSeq = RandomNum(0, 500)
			} else {
				session.FwdCSeq++
			}
			if rt == PRACK {
				st = lt // LT is already created using GenerateOutgoingPRACKST
				st.CSeq = session.FwdCSeq
			} else {
				st = NewSIPTransaction_CRL(session.FwdCSeq, rt, lt)
				session.AddTransaction(st)
			}
		}
	} else {
		if rt == ACK {
			if lt == nil {
				lt = session.GetUnACKedINVorReINV()
			}
			lt.IsACKed = true
			st = lt.CreateACKST()
		} else {
			// Increment backward CSeq
			if session.BwdCSeq == 0 {
				session.BwdCSeq = RandomNum(600, 1000)
			} else {
				session.BwdCSeq++
			}
			st = NewSIPTransaction_CRL(session.BwdCSeq, rt, lt)
			session.AddTransaction(st)
		}
	}
	return st
}
