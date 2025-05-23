package sip

import (
	"fmt"
	"net"
	"sync"
	"time"

	. "SRGo/global"
	"SRGo/guid"
	"slices"
)

type Transaction struct {
	Key       string
	Direction Direction
	Method    Method
	CSeq      uint32
	RSeq      uint32

	To        string
	From      string
	ViaBranch string
	RAck      string

	PrackStatus PRACKStatus

	IsACKed     bool
	IsFinalized bool

	IsProbing bool
	ResetMF   bool // to be used or removed

	UseRemoteURI bool // to keep using the original RURI & socket for CANCEL and ACK on non-2xx
	ViaUdpAddr   *net.UDPAddr

	RequestMessage *SipMessage

	LinkedTransaction *Transaction
	ACKTransaction    *Transaction

	CallID      string
	Responses   []int
	Lock        sync.RWMutex
	SentMessage *SipMessage

	TransTime      time.Time
	Timer          *SipTimer
	CANCELAuxTimer *SipTimer

	// retransmission
	ReTXCount    int
	TransTimeOut time.Duration
}

func NewST() *Transaction {
	trans := &Transaction{
		Key:       guid.NewKey(),
		TransTime: time.Now(),
	}
	return trans
}

func NewSIPTransaction_RT(RM *SipMessage, LT *Transaction, ss *SipSession) *Transaction {
	trans := NewST()
	trans.Method = RM.StartLine.Method
	trans.RequestMessage = RM
	trans.Direction = INBOUND
	trans.ViaUdpAddr = RM.ViaUdpAddr
	trans.CSeq = RM.CSeqNum
	trans.ViaBranch = RM.ViaBranch
	trans.LinkedTransaction = LT

	ss.FromTag = RM.FromTag
	ss.ToTag = RM.ToTag
	return trans
}

func NewSIPTransaction_RP(rseq uint32, prksts PRACKStatus) *Transaction {
	trans := NewST()
	trans.Direction = INBOUND
	trans.Method = PRACK
	trans.RSeq = rseq
	trans.PrackStatus = prksts
	return trans
}

func NewSIPTransaction_RC(rseq uint32, cseq string) *Transaction {
	trans := NewST()
	trans.RSeq = rseq
	trans.Direction = OUTBOUND
	trans.Method = PRACK
	trans.ViaBranch = guid.NewViaBranch()
	trans.RAck = fmt.Sprintf("%s %s", Uint32ToStr(rseq), cseq)
	return trans
}

func NewSIPTransaction_CRL(cq uint32, method Method, LT *Transaction) *Transaction {
	trans := NewST()
	trans.Direction = OUTBOUND
	trans.Method = method
	trans.CSeq = cq
	trans.LinkedTransaction = LT
	trans.ViaBranch = guid.NewViaBranch()
	if LT != nil && method != ACK && method != CANCEL {
		LT.LinkedTransaction = trans
	}
	return trans
}

// ==================================================================
// Transaction response methods

func (transaction *Transaction) AnyResponseSYNC(fltr func(sc int) bool) bool {
	transaction.Lock.RLock()
	defer transaction.Lock.RUnlock()
	return slices.ContainsFunc(transaction.Responses, fltr)
}

func (transaction *Transaction) RequireSameViaBranch() bool {
	return transaction.AnyResponseSYNC(IsNegative)
}

func (transaction *Transaction) StatusCodeExistsSYNC(sc int) bool {
	return transaction.AnyResponseSYNC(func(sc1 int) bool { return sc1 == sc })
}

func (transaction *Transaction) Any1xxSYNC() bool {
	return transaction.AnyResponseSYNC(IsProvisional)
}

func (transaction *Transaction) IsFinalResponsePositiveSYNC() bool {
	return transaction.AnyResponseSYNC(IsPositive)
}

// ==================================================================
// Transaction methods

func (transaction *Transaction) CreateCANCELST() *Transaction {
	// Create a new SIPTransaction for the CANCEL request
	st := &Transaction{
		Direction:         OUTBOUND,
		Method:            CANCEL,
		CSeq:              transaction.CSeq,
		LinkedTransaction: transaction,
		To:                transaction.To,
		From:              transaction.From,
		ViaBranch:         transaction.ViaBranch,
		UseRemoteURI:      true,
	}
	// Link the INVITE transaction to the its CANCEL transaction
	transaction.LinkedTransaction = st
	return st
}

func (transaction *Transaction) CreateACKST() *Transaction {
	// Create a new SIPTransaction for the ACK
	st := &Transaction{
		Method:            ACK,
		Direction:         OUTBOUND,
		CSeq:              transaction.CSeq,
		LinkedTransaction: transaction,
	}

	// Set the ViaBranch for the ACK transaction
	if st.UseRemoteURI = transaction.RequireSameViaBranch(); st.UseRemoteURI {
		st.ViaBranch = transaction.ViaBranch
	} else {
		st.ViaBranch = guid.NewViaBranch()
	}

	// Link the ACK transaction with the INVITE transaction
	transaction.ACKTransaction = st

	return st
}

// ================================================================================

func (transaction *Transaction) StartTransTimer(sipSes *SipSession) {
	if transaction.Timer == nil {
		transaction.ReTXCount = 0
		transaction.TransTimeOut = time.Duration(T1Timer) * time.Millisecond
		transaction.Timer = &SipTimer{
			DoneCh: make(chan any),
			Tmr:    time.NewTimer(transaction.TransTimeOut),
		}
		go transaction.TransTimerHandler(sipSes)
	}
}

func (transaction *Transaction) restartTransTimer(sipSes *SipSession) {
	transaction.Timer.Tmr.Reset(transaction.TransTimeOut)
	go transaction.TransTimerHandler(sipSes)
}

func (transaction *Transaction) StopTransTimer(useLock bool) {
	if useLock {
		transaction.Lock.Lock()
		defer transaction.Lock.Unlock()
	}
	if transaction.Timer != nil && transaction.Timer.Tmr.Stop() {
		close(transaction.Timer.DoneCh)
	}
}

func (transaction *Transaction) TransTimerHandler(sipSes *SipSession) {
	select {
	case <-transaction.Timer.DoneCh:
		transaction.Lock.Lock()
		defer transaction.Lock.Unlock()
		transaction.Timer = nil
		return
	case <-transaction.Timer.Tmr.C:
	}
	transaction.Lock.Lock()
	defer transaction.Lock.Unlock()
	if transaction.ReTXCount >= ReTXCount {
		close(transaction.Timer.DoneCh)
		transaction.Timer = nil
		CheckPendingTransaction(sipSes, transaction)
		return
	}
	sipSes.Send(transaction)
	transaction.ReTXCount++
	transaction.TransTimeOut *= 2 // doubling retransmission interval
	transaction.restartTransTimer(sipSes)
}

// ==============================================================================
func (transaction *Transaction) StartCancelTimer(sipSes *SipSession) {
	if transaction.CANCELAuxTimer == nil {
		transaction.CANCELAuxTimer = &SipTimer{
			DoneCh: make(chan any),
			Tmr:    time.NewTimer(20 * time.Duration(T1Timer) * time.Millisecond),
		}
		go transaction.CancelTimerHandler(sipSes)
	}
}

func (transaction *Transaction) StopCancelTimer() {
	if transaction.CANCELAuxTimer != nil && transaction.CANCELAuxTimer.Tmr.Stop() {
		close(transaction.CANCELAuxTimer.DoneCh)
	}
}

func (transaction *Transaction) CancelTimerHandler(sipSes *SipSession) {
	select {
	case <-transaction.CANCELAuxTimer.DoneCh:
		transaction.Lock.Lock()
		transaction.CANCELAuxTimer = nil
		transaction.Lock.Unlock()
		return
	case <-transaction.CANCELAuxTimer.Tmr.C:
	}
	transaction.Lock.Lock()
	defer transaction.Lock.Unlock()
	if transaction.CANCELAuxTimer == nil {
		return
	}
	close(transaction.CANCELAuxTimer.DoneCh)
	transaction.CANCELAuxTimer = nil
	if sipSes.IsFinalized() {
		return
	}
	sipSes.FinalizeState()
	sipSes.DropMe()
}
