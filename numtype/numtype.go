package numtype

type NumberType int

const (
	CalledRURI NumberType = iota
	CalledTo
	CalledBoth
	CallingFrom
	CallingPAI
	CallingBoth
)
