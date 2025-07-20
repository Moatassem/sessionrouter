package guid

import (
	"SRGo/global"

	"github.com/google/uuid"
)

func newUUID() *uuid.UUID {
	u, _ := uuid.NewV7()
	return &u
}

func NewCallID() string {
	uid := newUUID()
	return uid.String()
}

func NewViaBranch() string {
	uid := newUUID()
	return global.MagicCookie + uid.String()[24:]
}

func NewTag() string {
	uid := newUUID()
	return uid.String()[24:]
}

func NewKey() string {
	uid := newUUID()
	return uid.String()[24:]
}
