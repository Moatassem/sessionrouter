package mode

type SessionMode string

const (
	None         SessionMode = "None"
	Multimedia               = "Multimedia"
	Registration             = "Registration"
	Subscription             = "Subscription"
	KeepAlive                = "KeepAlive"
	Messaging                = "Messaging"
	AllTypes                 = "AllTypes"
)
