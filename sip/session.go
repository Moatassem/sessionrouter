package sip

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	. "SRGo/global"
	"SRGo/q850"
	"SRGo/sip/mode"
	"SRGo/sip/state"
	"SRGo/sip/status"

	"github.com/Moatassem/sdp"
)

type SipSession struct {
	remoteMediaUdpAddr    atomic.Value // *net.UDPAddr
	SDPSession            *sdp.Session
	no18xSTimer           *time.Timer
	MediaConn             *net.UDPConn
	udpListenser          *net.UDPConn
	RemoteUserAgent       *SipUdpUserAgent
	LinkedSession         *SipSession
	RoutingData           *RoutingRecord
	probDoneChan          chan struct{} // used to send kill signal to probingTicker handler
	noAnsSTimer           *time.Timer
	maxDurationTimer      *time.Timer // used on inbound sessions only
	remoteUDP             *net.UDPAddr
	RemoteContactUDP      *net.UDPAddr
	probingTicker         *time.Ticker // used on inbound sessions only
	EgressProxy           *net.UDPAddr
	RemoteContactURI      string
	RemoteURI             string
	ToTag                 string
	FromTag               string
	ToHeader              string
	FromHeader            string
	CallID                string
	Mymode                mode.SessionMode
	RecordRoutes          []string
	Transactions          []*Transaction
	Relayed18xNotify      []int
	Direction             Direction
	state                 state.SessionState
	SDPSessionVersion     int64
	SDPSessionID          int64
	dscmutex              sync.RWMutex
	TransLock             sync.RWMutex
	rmtmutex              sync.RWMutex // used to synchronize remote addresses and local connection
	stateLock             sync.RWMutex
	multiUseMutex         sync.Mutex // used for synchronizing no18x & noAns timers, probing & max duration, dropping session
	RSeq                  uint32
	FwdCSeq               uint32
	BwdCSeq               uint32
	IsDisposed            bool
	dialogueChanging      bool
	TransformEarlyToFinal bool
	isHeld                bool
	ReferSubscription     bool
	IsDelayedOfferCall    bool
	received18xSDP        bool
	IsPRACKSupported      bool
}

func NewSS(dir Direction) *SipSession {
	ss := &SipSession{
		Direction:    dir,
		probDoneChan: make(chan struct{}),
	}
	return ss
}

// used in inbound sessions
func NewSIPSession(sipmsg *SipMessage) *SipSession {
	ss := NewSS(INBOUND)
	ss.CallID = sipmsg.CallID
	ss.RecordRoutes = sipmsg.Headers.HeaderValues(Record_Route)
	return ss
}

func (session *SipSession) String() string {
	return fmt.Sprintf("Call-ID: %s, State: %s, Direction: %s, Mode: %s", session.CallID, session.state.String(), session.Direction.String(), session.Mymode)
}

func (session *SipSession) ExceedCondition() bool {
	return session.Direction == INBOUND && !CallLimiter.AcceptNewCall()
}

//============================================================

func (session *SipSession) RemoteMediaUdpAddr() *net.UDPAddr {
	return session.remoteMediaUdpAddr.Load().(*net.UDPAddr)
}

func (session *SipSession) SetRemoteMediaUdpAddr(rmt *net.UDPAddr) {
	if rmt == nil {
		return
	}
	session.remoteMediaUdpAddr.Store(rmt)
}

func (session *SipSession) SetRemoteUDPnListenser(rmt *net.UDPAddr, cn *net.UDPConn) {
	session.rmtmutex.Lock()
	defer session.rmtmutex.Unlock()

	session.remoteUDP = rmt
	session.udpListenser = cn
}

func (session *SipSession) SetRemoteUDP(rmt *net.UDPAddr) {
	session.rmtmutex.Lock()
	defer session.rmtmutex.Unlock()

	session.remoteUDP = rmt
}

func (session *SipSession) RemoteUDP() *net.UDPAddr {
	session.rmtmutex.RLock()
	defer session.rmtmutex.RUnlock()

	return session.remoteUDP
}

func (session *SipSession) SetUDPListenser(cn *net.UDPConn) {
	session.rmtmutex.Lock()
	defer session.rmtmutex.Unlock()

	session.udpListenser = cn
}

func (session *SipSession) UDPListenser() *net.UDPConn {
	session.rmtmutex.RLock()
	defer session.rmtmutex.RUnlock()

	return session.udpListenser
}

// =============================================================

//nolint:cyclop
func (session *SipSession) GetTransactionSYNC(sipmsg *SipMessage) *Transaction {
	session.TransLock.RLock()
	defer session.TransLock.RUnlock()

	var CSeqRT Method
	CSeqNum := sipmsg.CSeqNum
	if sipmsg.IsRequest() {
		CSeqRT = sipmsg.GetMethod()
		return Find(session.Transactions, func(x *Transaction) bool {
			return x.Direction == INBOUND && x.CSeq == CSeqNum &&
				((x.Method == CSeqRT && x.ViaBranch == sipmsg.ViaBranch) ||
					(CSeqRT == ACK && x.Method.RequiresACK() && x.IsACKed && session.FromTag == sipmsg.FromTag &&
						(session.ToTag == "" || session.ToTag == sipmsg.ToTag)))
		})
	}
	CSeqRT = sipmsg.CSeqMethod
	return Find(session.Transactions, func(x *Transaction) bool {
		return x.Direction == OUTBOUND && x.ViaBranch == sipmsg.ViaBranch && x.CSeq == CSeqNum &&
			(x.Method == CSeqRT || (CSeqRT == INVITE && x.Method == ReINVITE))
	})
}

func (session *SipSession) IsDuplicateMessage(msg *SipMessage) bool {
	sc := msg.StartLine.StatusCode
	if sc == 0 {
		tx := session.GetTransactionSYNC(msg)
		return tx != nil
	}
	if sc <= 199 {
		return false
	}
	trans := session.GetTransactionSYNC(msg)
	if trans == nil {
		return true
	}
	if trans.StatusCodeExistsSYNC(sc) {
		if trans.Method.RequiresACK() && trans.ACKTransaction != nil {
			session.SendSTMessage(trans.ACKTransaction)
		}
		return true
	}
	return false
}

func (session *SipSession) IsDuplicateINVITE(incINVITE *SipMessage) bool {
	trans := Find(session.Transactions, func(tx *Transaction) bool {
		return tx.Direction == INBOUND && tx.Method == INVITE &&
			tx.RequestMessage.FromTag == incINVITE.FromTag &&
			tx.ViaBranch == incINVITE.ViaBranch && tx.CSeq == incINVITE.CSeqNum
	})
	return trans != nil
}

func (session *SipSession) GenerateOutgoingPRACKST(responseMsg *SipMessage) *Transaction {
	// Parse RSeq from the headers and handle the error
	rSeq := Str2Uint[uint32](responseMsg.Headers.ValueHeader(RSeq))
	cseqHeaderValue := responseMsg.Headers.ValueHeader(CSeq)
	newST := NewSIPTransaction_RC(rSeq, cseqHeaderValue)

	session.TransLock.Lock()
	session.Transactions = append(session.Transactions, newST)
	session.TransLock.Unlock()

	return newST
}

func (session *SipSession) AddTransaction(tx *Transaction) {
	// Add the transaction to the session
	session.Transactions = append(session.Transactions, tx)
}

func (session *SipSession) GetReOrInviteTransaction(cSeqNum uint32, isFinalized bool) *Transaction {
	return Find(session.Transactions, func(tx *Transaction) bool {
		return tx.Direction == INBOUND &&
			tx.CSeq == cSeqNum &&
			tx.Method.RequiresACK() &&
			tx.IsFinalized == isFinalized
	})
}

func (session *SipSession) GetPendingOutgoingTransactions() []*Transaction {
	return Filter(session.Transactions, func(tx *Transaction) bool {
		return tx.Direction == OUTBOUND && !tx.IsFinalized
	})
}

func (session *SipSession) GetPendingIncomingTransactions() []*Transaction {
	return Filter(session.Transactions, func(tx *Transaction) bool {
		return tx.Direction == INBOUND // && !tx.IsFinalized
	})
}

func (session *SipSession) GetPRACKTransaction(rSeqNum, cSeqNum uint32) *Transaction {
	// Retrieve the re-INVITE transaction that matches the CSeq number
	reInvite := session.GetReOrInviteTransaction(cSeqNum, false)
	if reInvite != nil {
		reInvite.StopTransTimer(true)
	}
	return Find(session.Transactions, func(tx *Transaction) bool {
		return tx.Direction == INBOUND && tx.RSeq == rSeqNum && tx.Method == PRACK
	})
}

func (session *SipSession) AreTherePendingOutgoingPRACK() bool {
	session.TransLock.Lock()
	defer session.TransLock.Unlock()
	return Any(session.Transactions, func(tx *Transaction) bool {
		return tx.Direction == OUTBOUND && tx.Method == PRACK && !tx.IsFinalized
	})
}

func (session *SipSession) UnPRACKed18xCountSYNC() int {
	session.TransLock.RLock()
	defer session.TransLock.RUnlock()
	lst := Filter(session.Transactions, func(x *Transaction) bool {
		return x.Direction == INBOUND && x.Method == PRACK && x.RequestMessage == nil
	})
	return len(lst)
}

func (session *SipSession) GenerateRSeqCreatePRACKSTSYNC(linkedPRACKST *Transaction) string {
	session.TransLock.Lock()
	defer session.TransLock.Unlock()
	if session.RSeq == 0 {
		session.RSeq = RandomNum(1, 999)
	} else {
		session.RSeq++
	}
	pst := NewSIPTransaction_RP(session.RSeq, PRACKExpected)
	if linkedPRACKST != nil {
		pst.LinkedTransaction = linkedPRACKST
		linkedPRACKST.LinkedTransaction = pst
	}
	session.AddTransaction(pst)
	return Uint32ToStr(session.RSeq)
}

func (session *SipSession) GetLastMessageHeaderValueSYNC(headerName string) string {
	session.TransLock.RLock()
	defer session.TransLock.RUnlock()

	for i := len(session.Transactions) - 1; i >= 0; i-- {
		trans := (session.Transactions)[i]
		if trans.RequestMessage == nil {
			continue
		}
		if (trans.Method == CANCEL || trans.Method == BYE) && trans.RequestMessage != nil && trans.RequestMessage.Headers.HeaderExists(headerName) {
			return trans.RequestMessage.Headers.Value(headerName)
		}
	}

	// for _, t := range session.Transactions {
	// 	if t.Method != INVITE {
	// 		continue
	// 	}
	// 	for j := len(t.ResponseMsgs) - 1; j >= 0; j-- {
	// 		msg := t.ResponseMsgs[j]
	// 		if msg.StartLine.ResponseCode >= 400 && msg.Headers.FieldExist(sh) {
	// 			return msg.Headers.Field(sh)
	// 		}
	// 	}
	// }
	return ""
}

func (session *SipSession) GetUnACKedINVorReINV() *Transaction {
	// Find the first outgoing transaction that requires an ACK and is not ACKed
	for _, tx := range session.Transactions {
		if tx.Direction == OUTBOUND && tx.Method.RequiresACK() && !tx.IsACKed {
			return tx
		}
	}
	return nil
}

func (session *SipSession) GetPendingIncomingTransactionsSYNC() []*Transaction {
	session.TransLock.Lock()
	defer session.TransLock.Unlock()
	var pendingTransactions []*Transaction

	// Find all incoming transactions that are not finalized
	for _, tx := range session.Transactions {
		if tx.Direction == INBOUND && !tx.IsFinalized {
			pendingTransactions = append(pendingTransactions, tx)
		}
	}

	return pendingTransactions
}

func (session *SipSession) GetLastUnACKedINV(dir Direction) *Transaction {
	// Find the last outgoing INVITE transaction that is not ACKed
	for i := len(session.Transactions) - 1; i >= 0; i-- {
		tx := (session.Transactions)[i]
		if tx.Direction == dir && tx.Method == INVITE && !tx.IsACKed {
			return tx
		}
	}
	return nil
}

func (session *SipSession) GetLastUnACKedInvSYNC(dir Direction) *Transaction {
	session.TransLock.Lock()
	defer session.TransLock.Unlock()
	return session.GetLastUnACKedINV(dir)
}

func (session *SipSession) Received1xx() bool {
	trans := session.GetFirstTransaction()
	return trans != nil && trans.Any1xxSYNC()
}

func (session *SipSession) Received200() bool {
	trans := session.GetFirstTransaction()
	return trans != nil && trans.IsFinalResponsePositiveSYNC()
}

func (session *SipSession) StopAllOutTransactions() {
	session.TransLock.RLock()
	defer session.TransLock.RUnlock()
	for _, tx := range session.Transactions {
		tx.StopTransTimer(true)
	}
}

func (session *SipSession) HasNoTransactions() bool {
	session.TransLock.RLock()
	defer session.TransLock.RUnlock()

	return len(session.Transactions) == 0
}

func (session *SipSession) GetFirstTransaction() *Transaction {
	session.TransLock.RLock()
	defer session.TransLock.RUnlock()
	Ts := session.Transactions
	return Ts[0]
}

func (session *SipSession) GetLastTransaction() *Transaction {
	if len(session.Transactions) == 0 {
		return nil
	}
	return (session.Transactions)[len(session.Transactions)-1]
}

func (session *SipSession) CurrentRequestMessage() *SipMessage {
	trans := session.GetFirstTransaction()
	if trans == nil {
		return nil
	}
	return trans.RequestMessage
}

func (session *SipSession) UpdateContactRecordRouteBody(sipmsg *SipMessage) {
	rcrdrts := sipmsg.Headers.HeaderValues(Record_Route)
	if len(session.RecordRoutes) == 0 && len(rcrdrts) > 0 {
		session.RecordRoutes = rcrdrts
	}

	extractHostpart := func(hv string) string {
		if mtch := RMatch(hv, FQDNPort); len(mtch) > 0 {
			return mtch[1]
		}
		return ""
	}

	if RCUDP, ok := BuildUdpAddr(extractHostpart(sipmsg.RCURI), SipPort); ok {
		session.RemoteContactURI = sipmsg.RCURI
		if len(session.RecordRoutes) == 0 {
			session.RemoteContactUDP = RCUDP
		}
	}
}

func (session *SipSession) SendSTMessage(st *Transaction) {
	st.Lock.Lock()
	defer st.Lock.Unlock()
	var createTimer bool
	if st.Direction == OUTBOUND {
		createTimer = st.Method != ACK
	} else {
		if st.IsFinalized {
			createTimer = st.Method.RequiresACK()
		} else {
			createTimer = session.UnPRACKed18xCountSYNC() > 0
		}
	}
	session.Send(st)
	if createTimer {
		st.StartTransTimer(session)
	}
}

func (session *SipSession) Send(tx *Transaction) {
	if len(tx.SentMessage.Bytes) == 0 {
		tx.SentMessage.PrepareMessageBytes(session)
	}

	// response
	if tx.SentMessage.IsResponse() {
		if tx.ViaUdpAddr != nil {
			session.sendmessage(tx.SentMessage, tx.ViaUdpAddr)
		} else {
			session.sendmessage(tx.SentMessage, session.RemoteUDP())
		}
		return
	}

	// request
	if !tx.UseRemoteURI && session.RemoteContactUDP != nil {
		session.sendmessage(tx.SentMessage, session.RemoteContactUDP)
		return
	}
	if session.EgressProxy != nil {
		session.sendmessage(tx.SentMessage, session.EgressProxy)
		return
	}
	session.sendmessage(tx.SentMessage, session.RemoteUDP())
}

func (session *SipSession) sendmessage(msg *SipMessage, rmt *net.UDPAddr) {
	_, err := session.UDPListenser().WriteToUDP(msg.Bytes, rmt)
	if err != nil {
		LogError(LTSystem, "Failed to send message: "+err.Error())
	}
}

//nolint:cyclop,exhaustive
func CheckPendingTransaction(ss *SipSession, tx *Transaction) {
	// TODO: incomplete!!!
	switch tx.Method {
	case OPTIONS:
		if ss.Mymode == mode.KeepAlive {
			ss.SetState(state.TimedOut)
			ss.DropMe()
			return
		}
		if ss.Mymode == mode.Multimedia && ss.Direction == INBOUND && tx.Direction == OUTBOUND && tx.IsProbing { // means my in-dialogue probing OPTIONS
			ss.ReleaseCall("Probing timed-out")
		}
	case INVITE:
		if ss.IsPending() {
			ss.SetState(state.TimedOut)
			ss.DropMe()
		}
		if lnkdss := ss.LinkedSession; lnkdss != nil {
			if tx.Direction == INBOUND {
				if lnkdss.Direction == OUTBOUND {
					if lnkdss.IsBeingEstablished() && lnkdss.Received200() {
						lnkdss.SendCreatedRequest(ACK, nil, ZeroBody())
						lnkdss.WaitMS(100)
						lnkdss.SetState(state.BeingDropped)
						lnkdss.SendCreatedRequestDetailed(RequestPack{Method: BYE, CustomHeaders: NewSHQ850OrSIP(487, "Inbound INVITE timed-out", "")}, nil, ZeroBody())
						return
					}
					lnkdss.CancelMe(31, "Caller timed-out")
				}
			} else {
				lnkdss.RerouteRequest(NewResponsePackSRW(408, "Outbound INVITE timed-out", ""))
			}
		}
	case CANCEL, BYE:
		ss.FinalizeState()
		ss.DropMe()
	case PRACK:
		ss.StopNoTimers()
		lnkdss := ss.LinkedSession
		lnkdss.RerouteRequest(NewResponsePackSRW(408, "Outbound PRACK timed-out", ""))
		ss.SetState(state.Failed)
		ss.DropMe()
	default:
		lnkdss := ss.LinkedSession
		s1, s2 := ss.ReleaseCall(fmt.Sprintf("In-dialogue %s timed-out", tx.Method.String()))
		if !s1 {
			ss.DropMe()
		}
		if !s2 && lnkdss != nil {
			lnkdss.DropMe()
		}
	}
}

// ==================================================================
// for indialogue change

func (ss *SipSession) IsDialogueChanging() bool {
	ss.dscmutex.RLock()
	defer ss.dscmutex.RUnlock()
	return ss.dialogueChanging
}

func (ss *SipSession) ChecknSetDialogueChanging(newflag bool) bool {
	ss.dscmutex.Lock()
	defer ss.dscmutex.Unlock()
	if newflag != ss.dialogueChanging {
		ss.dialogueChanging = newflag
		return true
	}
	return false
}

func (ss *SipSession) SetReceived18xSDP() {
	ss.dscmutex.Lock()
	defer ss.dscmutex.Unlock()

	ss.received18xSDP = true
}

func (ss *SipSession) Received18xSDP() bool {
	ss.dscmutex.RLock()
	defer ss.dscmutex.RUnlock()

	return ss.received18xSDP
}

// ==================================================================

// Unsafe
func (ss *SipSession) setTimerPointer(tt TimerType, tmr *time.Timer) {
	if tt == NoAnswer {
		ss.noAnsSTimer = tmr
	} else {
		ss.no18xSTimer = tmr
	}
}

// Unsafe
func (ss *SipSession) getTimerPointer(tt TimerType) *time.Timer {
	if tt == NoAnswer {
		return ss.noAnsSTimer
	}
	return ss.no18xSTimer
}

func (ss *SipSession) StartTimer(tt TimerType) {
	ss.multiUseMutex.Lock()
	defer ss.multiUseMutex.Unlock()
	if (tt == NoAnswer && ss.noAnsSTimer != nil) || (tt == No18x && ss.no18xSTimer != nil) {
		return
	}
	var delay int
	if tt == NoAnswer {
		delay = ss.RoutingData.NoAnswerTimeout
	} else {
		delay = ss.RoutingData.No18xTimeout
	}
	if delay <= 0 {
		return
	}
	tmr := time.AfterFunc(time.Duration(delay)*time.Second, func() { ss.timerHandler(tt) })
	ss.setTimerPointer(tt, tmr)
}

func (ss *SipSession) StopTimer(tt TimerType) {
	ss.multiUseMutex.Lock()
	defer ss.multiUseMutex.Unlock()
	siptmr := ss.getTimerPointer(tt)
	if siptmr == nil {
		return
	}
	siptmr.Stop()
}

func (ss *SipSession) StopNoTimers() {
	ss.StopTimer(No18x)
	ss.StopTimer(NoAnswer)
}

func (ss *SipSession) timerHandler(tt TimerType) {
	ss.multiUseMutex.Lock()
	ss.setTimerPointer(tt, nil)
	ss.multiUseMutex.Unlock()

	lnkdss := ss.LinkedSession
	ss.CancelMe(q850.NoAnswerFromUser, tt.Details())
	lnkdss.RerouteRequest(NewResponsePackSRW(487, "No response from far end", ""))
}

// ------------------------------------------------------------------------------

func (ss *SipSession) StartInDialogueProbing() {
	if IndialogueProbingInterval <= 0 {
		LogWarning(LTConfiguration, "Indialogue Probing duration is set to ZERO/NEGATIVE - Disabled")
		return
	}
	ss.multiUseMutex.Lock()
	defer ss.multiUseMutex.Unlock()
	ss.probingTicker = time.NewTicker(time.Duration(IndialogueProbingInterval) * time.Second)
	go ss.probingTickerHandler(ss.probDoneChan, ss.probingTicker.C)
}

func (ss *SipSession) StartMaxCallDuration() {
	if ss.RoutingData == nil {
		if !sippTesting {
			LogWarning(LTSystem, "Max Call duration not started - missing RoutingData")
		}
		return
	}
	mxD := ss.RoutingData.MaxCallDuration
	if mxD <= 0 {
		if !sippTesting {
			LogWarning(LTConfiguration, "Max Call duration is set to ZERO/NEGATIVE - Disabled")
		}
		return
	}
	ss.multiUseMutex.Lock()
	defer ss.multiUseMutex.Unlock()
	ss.maxDurationTimer = time.AfterFunc(time.Duration(mxD)*time.Second, func() { ss.ReleaseCall("Max call duration reached") })
}

func (ss *SipSession) probingTickerHandler(doneChan chan struct{}, tkChan <-chan time.Time) {
	for {
		select {
		case <-doneChan:
			return
		case <-tkChan:
			if ss.IsEstablished() {
				ss.SendCreatedRequestDetailed(RequestPack{Method: OPTIONS, Max70: true, IsProbing: true}, nil, ZeroBody())
			}
		}
	}
}

// ==============================================================================

func (session *SipSession) GetState() state.SessionState {
	session.stateLock.RLock()
	defer session.stateLock.RUnlock()
	return session.state
}

// Returns the original state
func (session *SipSession) SetState(ss state.SessionState) state.SessionState {
	session.stateLock.Lock()
	defer session.stateLock.Unlock()
	st := session.state
	session.state = ss
	return st
}

// Returns the finalized state
func (session *SipSession) FinalizeState() state.SessionState {
	session.stateLock.Lock()
	defer session.stateLock.Unlock()
	session.state = session.state.FinalizeMe()
	return session.state
}

func (session *SipSession) IsFinalized() bool {
	session.stateLock.RLock()
	defer session.stateLock.RUnlock()
	return session.state.IsFinalized()
}

func (session *SipSession) IsEstablished() bool {
	session.stateLock.RLock()
	defer session.stateLock.RUnlock()
	return session.state == state.Established
}

func (session *SipSession) IsBeingEstablished() bool {
	session.stateLock.RLock()
	defer session.stateLock.RUnlock()
	return session.state == state.BeingEstablished
}

func (session *SipSession) IsPending() bool {
	session.stateLock.RLock()
	defer session.stateLock.RUnlock()
	return session.state.IsPending()
}

func (session *SipSession) IsLinked() bool {
	return session.LinkedSession != nil
}

// ==============================================================================

func (ss *SipSession) ReleaseCall(details string) (s1 bool, s2 bool) {
	if ss.IsEstablished() {
		ss.SetState(state.BeingDropped)
		ss.SendCreatedRequestDetailed(RequestPack{Method: BYE, Max70: true, CustomHeaders: NewSHQ850OrSIP(0, details, "")}, nil, ZeroBody())
		s1 = true
	}
	if lnkss := ss.LinkedSession; lnkss != nil && lnkss.IsEstablished() {
		lnkss.SetState(state.BeingDropped)
		lnkss.SendCreatedRequestDetailed(RequestPack{Method: BYE, Max70: true, CustomHeaders: NewSHQ850OrSIP(0, details, "")}, nil, ZeroBody())
		s2 = true
	}
	return
}

func (ss *SipSession) ReleaseEarlyFinalCall(details string) (s1 bool, s2 bool) {
	if ss.IsBeingEstablished() {
		ss.SetState(state.BeingFailed)
		ss.SendCreatedResponseDetailed(nil, ResponsePack{StatusCode: status.NotAcceptable, CustomHeaders: NewSHQ850OrSIP(0, details, "")}, ZeroBody())
		s1 = true
	}
	if lnkss := ss.LinkedSession; lnkss != nil && lnkss.IsEstablished() {
		lnkss.SetState(state.BeingDropped)
		lnkss.SendCreatedRequestDetailed(RequestPack{Method: BYE, Max70: true, CustomHeaders: NewSHQ850OrSIP(0, details, "")}, nil, ZeroBody())
		s2 = true
	}
	return
}

func (ss *SipSession) ReleaseMe(details string, linkedTrans *Transaction) bool {
	if ss.IsEstablished() {
		ss.SetState(state.BeingCleared)
		ss.SendCreatedRequestDetailed(RequestPack{Method: BYE, Max70: true, CustomHeaders: NewSHQ850OrSIP(0, details, "")}, linkedTrans, ZeroBody())
		return true
	}
	return false
}

// Cancel outgoing INVITE
func (session *SipSession) CancelMe(q850 int, details string) bool {
	if session.Direction != OUTBOUND {
		return false
	}
	if session.IsBeingEstablished() {
		session.StopNoTimers()
		session.SetState(state.BeingCancelled)
		if q850 == -1 || details == "" {
			session.SendCreatedRequest(CANCEL, nil, ZeroBody())
		} else {
			session.SendCreatedRequestDetailed(RequestPack{Method: CANCEL, CustomHeaders: NewSHQ850OrSIP(q850, details, "")}, nil, ZeroBody())
		}
		return true
	}
	return false
}

// Reject incoming INVITE
func (session *SipSession) RejectMe(trans *Transaction, stsCode int, q850 int, details string) bool {
	if session.Direction != INBOUND {
		return false
	}
	if session.IsBeingEstablished() {
		session.SetState(state.BeingFailed)
		session.SendCreatedResponseDetailed(trans, ResponsePack{StatusCode: stsCode, CustomHeaders: NewSHQ850OrSIP(q850, details, "")}, ZeroBody())
		return true
	}
	return false
}

// ACK redirected/rejected outgoing INVITE
func (session *SipSession) Ack3xxTo6xx(finalstate state.SessionState) {
	if session.Direction != OUTBOUND {
		return
	}
	session.SetState(finalstate)
	session.SendCreatedRequest(ACK, nil, ZeroBody())
	session.DropMeTimed()
}

func (session *SipSession) Ack3xxTo6xxFinalize() {
	if session.Direction != OUTBOUND {
		return
	}
	session.FinalizeState()
	session.SendCreatedRequest(ACK, nil, ZeroBody())
	session.DropMeTimed()
}

func (session *SipSession) AddMe() {
	Sessions.Store(session.CallID, session)
}

func (session *SipSession) DropMe() {
	session.multiUseMutex.Lock()
	defer session.multiUseMutex.Unlock()
	if session.IsDisposed {
		fmt.Print("Already Disposed Session: ", session.CallID, " State: ", session.state.String())
		pc, f, l, ok := runtime.Caller(1) // pc, _, _, ok := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		if ok && details != nil { // f, l := details.FileLine(pc)
			fmt.Printf(" >> [func (%s) - file (%s) - line (%d)]\n", details.Name(), f, l)
		}
		return
	}
	close(session.probDoneChan)
	if session.maxDurationTimer != nil {
		session.maxDurationTimer.Stop()
	}
	if session.probingTicker != nil {
		session.probingTicker.Stop()
	}
	MediaPortPool.ReleaseSocket(session.MediaConn)

	// Create CDR
	// sesCDR := cdr.New()
	// sesCDR.Set(cdr.CallDirection, session.Direction.String())
	// sesCDR.Flush()

	session.IsDisposed = true
	Sessions.Delete(session.CallID)
}

func (ss *SipSession) DropMeTimed() {
	go func() {
		time.Sleep(time.Second * time.Duration(SessionDropDelaySec))
		ss.DropMe()
	}()
}

func (ss *SipSession) WaitMS(ms int) {
	time.Sleep(time.Millisecond * time.Duration(ms))
}
