package mode

type SessionMode string

const (
	None         SessionMode = "None"
	Multimedia   SessionMode = "Multimedia"
	Registration SessionMode = "Registration"
	Subscription SessionMode = "Subscription"
	KeepAlive    SessionMode = "KeepAlive"
	Messaging    SessionMode = "Messaging"
	AllTypes     SessionMode = "AllTypes"
)
