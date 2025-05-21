package state

import (
	"strings"

	"SRGo/global"
)

type SessionState int

const (
	NotSet SessionState = iota
	BeingEstablished
	Established
	BeingCleared
	Cleared
	BeingRejected
	Rejected
	BeingCancelled
	Cancelled

	BeingFailed
	Failed
	BeingDenied
	Denied
	BeingDropped
	Dropped

	BeingRedirected
	Redirected
	BeingReferred
	Referred

	BeingNeglected
	Neglected

	BeingProbed
	Probed

	TimedOut

	BeingRestored
	BeingConnected

	BeingUpdated   // for Update
	BeingReinvited // for ReInvite

	Registered
	Unregistered
)

var dicNames = map[SessionState]string{
	NotSet:           "NotSet",
	BeingEstablished: "BeingEstablished",
	Established:      "Established",
	BeingCleared:     "BeingCleared",
	Cleared:          "Cleared",
	BeingRejected:    "BeingRejected",
	Rejected:         "Rejected",
	BeingCancelled:   "BeingCancelled",
	Cancelled:        "Cancelled",
	BeingFailed:      "BeingFailed",
	Failed:           "Failed",
	BeingDenied:      "BeingDenied",
	Denied:           "Denied",
	BeingDropped:     "BeingDropped",
	Dropped:          "Dropped",
	BeingRedirected:  "BeingRedirected",
	Redirected:       "Redirected",
	BeingReferred:    "BeingReferred",
	Referred:         "Referred",
	BeingNeglected:   "BeingNeglected",
	Neglected:        "Neglected",
	BeingRestored:    "BeingRestored",
	BeingConnected:   "BeingConnected",
	BeingProbed:      "BeingProbed",
	Probed:           "Probed",
	BeingUpdated:     "BeingUpdated",
	BeingReinvited:   "BeingReinvited",
	TimedOut:         "TimedOut",
	Registered:       "Registered",
	Unregistered:     "Unregistered",
}

func (ss SessionState) String() string {
	return dicNames[ss]
}

func (ss SessionState) StartsWith(prfx string) bool {
	return strings.HasPrefix(ss.String(), prfx)
}

func (ss SessionState) FinalizeMe() SessionState {
	ssnm := strings.TrimPrefix(ss.String(), "Being")
	return global.GetEnum(dicNames, ssnm)
}

func (ss SessionState) IsPending() bool {
	return strings.HasPrefix(ss.String(), "Being")
}

func (ss SessionState) IsFinalized() bool {
	return !ss.IsPending()
}
