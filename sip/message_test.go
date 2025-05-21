package sip_test

import (
	"SRGo/global"
	"SRGo/sip"
	"testing"

	"github.com/stretchr/testify/require"
)

type data struct {
	contact string
	ext     string
	ruri    string
	ipport  string
	expires int
}

func TestGetRegistrationData(t *testing.T) {
	t.Parallel()

	sipmsg := new(sip.SipMessage)
	sipmsg.Headers = sip.NewSHsPointer(false)
	contact := `<sip:123445-0x559d0c268930@172.20.40.132:46466>;expires=3600;+sip.instance="<urn:uuid:da213fce-693c-3403-8455-a548a10ef970>"`
	sipmsg.Headers.AddHeader(global.Contact, contact)
	contact, ext, ruri, ipport, expires := sipmsg.GetRegistrationData()
	expected := data{contact, "123445", "sip:123445;0x559d0c268930@172.20.40.132:46466", "172.20.40.132:46466", 3600}
	actual := data{contact, ext, ruri, ipport, expires}
	require.Equal(t, expected, actual, "With a username and dash")

	sipmsg = new(sip.SipMessage)
	sipmsg.Headers = sip.NewSHsPointer(false)
	contact = `<sip:172.20.40.132:45076>;transport=UDP`
	sipmsg.Headers.AddHeader(global.Contact, contact)
	contact, ext, ruri, ipport, expires = sipmsg.GetRegistrationData()
	expected = data{contact, "", "", "", -100}
	actual = data{contact, ext, ruri, ipport, expires}
	require.Equal(t, expected, actual, "With no username")

	sipmsg = new(sip.SipMessage)
	sipmsg.Headers = sip.NewSHsPointer(false)
	contact = `<sip:123445@172.20.40.132:46466>;expires=200;+sip.instance="<urn:uuid:da213fce-693c-3403-8455-a548a10ef970>"`
	sipmsg.Headers.AddHeader(global.Contact, contact)
	contact, ext, ruri, ipport, expires = sipmsg.GetRegistrationData()
	expected = data{contact, "123445", "sip:123445@172.20.40.132:46466", "172.20.40.132:46466", 200}
	actual = data{contact, ext, ruri, ipport, expires}
	require.Equal(t, expected, actual, "With proper username")
}
