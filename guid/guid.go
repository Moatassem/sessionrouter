package guid

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	. "SRGo/global"
)

// Guid is a globally unique 16 byte identifier
type Guid [16]byte

// ErrInvalid is returned when parsing a string that is not formatted
// as a valid guid.
// var ErrInvalid = errors.New("guid: invalid format")

// New generates a random RFC 4122-conformant version 4 Guid.
func guidNew() *Guid {
	g := new(Guid)
	if _, err := rand.Read(g[:]); err != nil {
		panic(err)
	}
	g[6] = (g[6] & 0x0f) | 0x40 // version = 4
	g[8] = (g[8] & 0x3f) | 0x80 // variant = RFC 4122
	return g
}

// String returns a standard hexadecimal string version of the Guid.
// Lowercase characters are used.
func (g *Guid) toString(isfull bool, prfx string) string {
	if isfull {
		if prfx == "" {
			return fmt.Sprintf("%x-%x-%x-%x-%x", g[0:4], g[4:6], g[6:8], g[8:10], g[10:16])
		}
		// used for Call-ID
		n := len(prfx) / 2
		return fmt.Sprintf("%s-%s-%x-%x-%x-%x-%x", prfx[:n], prfx[n:], g[0:4], g[4:6], g[6:8], g[8:10], g[10:16])
	}
	if prfx == "" {
		return hex.EncodeToString(g[8:14])
	}
	return fmt.Sprintf("%s%s", prfx, hex.EncodeToString(g[8:16]))
}

func generateRandomHex(n int) string {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return LowerDash(EntityName)
	}
	return hex.EncodeToString(bytes)
}

// NewString is a helper function that returns a random RFC 4122-comformant
// version 4 Guid as a string.
func GetKey() string {
	return guidNew().toString(true, "")
}

func NewCallID() string {
	return guidNew().toString(true, generateRandomHex(7)) // LowerDash(EntityName)
}

func NewViaBranch() string {
	return guidNew().toString(false, MagicCookie)
}

func NewTag() string {
	return guidNew().toString(false, "")
}

func Md5Hash(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// StringUpper returns a standard hexadecimal string version of the Guid.
// Uppercase characters are used.
// func (g *Guid) StringUpper() string {
// 	return fmt.Sprintf("%X-%X-%X-%X-%X",
// 		g[0:4], g[4:6], g[6:8], g[8:10], g[10:16])
// }
