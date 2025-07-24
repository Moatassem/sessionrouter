package global

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/ipv4"
)

// ============================================================
func LogCallStack() {
	r := recover()
	if r == nil {
		return
	}
	log.Printf("Panic Recovered! Error:\n%v", r)
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	log.Printf("Stack trace:\n%s\n", buf[:n])
}

// GetNTPTimestamp returns the current time as a 64-bit NTP timestamp
func GetNTPTimestamp() uint64 {
	now := time.Now().UTC()
	secs := uint64(now.Unix()) + ntpEpochOffset
	return secs << 32
}

func GetAbsolutePath(relativePath string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return wd + string(os.PathSeparator) + relativePath, nil
}

func GetLocalIPs() ([]net.IP, error) {
	var IPs []net.IP
	var ip net.IP
	ifaces, _ := net.Interfaces()
outer:
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagRunning == 0 { //|| i.Flags&net.FlagBroadcast == 0
			continue
		}
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if v, ok := addr.(*net.IPNet); ok {
				ip = v.IP
				if ip.To4() != nil && ip.IsPrivate() {
					IPs = append(IPs, ip)
					continue outer
				}
			}
		}
	}
	if len(IPs) == 0 {
		return nil, errors.New("no valid IPv4 found")
	}
	return IPs, nil
}

func StartListening(ip net.IP, prt int, dscp int) (*net.UDPConn, error) {
	if ip == nil {
		return nil, errors.New("nil IP address")
	}
	var socket net.UDPAddr
	socket.IP = ip
	socket.Port = prt
	conn, err := net.ListenUDP("udp", &socket)

	if err != nil {
		return nil, err
	}

	if err = ipv4.NewConn(conn).SetTOS(dscp); err != nil {
		log.Printf("Failed to set IPv4 TOS: %v (may need CAP_NET_ADMIN)", err)
	}

	return conn, nil
}

func GetUDPAddrFromConn(conn *net.UDPConn) *net.UDPAddr {
	return conn.LocalAddr().(*net.UDPAddr)
}

func GetUDPortFromConn(conn *net.UDPConn) int {
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func GetUDPIPPortFromConn(conn *net.UDPConn) (string, int) {
	addr := conn.LocalAddr().(*net.UDPAddr)
	if addr == nil {
		return "", 0
	}
	return addr.IP.String(), addr.Port
}

func BuildUdpAddr(ipsocket string, defaultport int) (*net.UDPAddr, bool) {
	part1, part2, ok := strings.Cut(ipsocket, ":")
	var prt int
	if ok {
		prt = Str2Int[int](part2)
		if prt <= 0 || prt > MaxPort {
			return nil, false
		}
	}
	prt = cmp.Or(prt, defaultport)

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", part1, prt))
	if err != nil {
		log.Printf("Error resolving UDP address [%s]: %v", ipsocket, err)
		return nil, false
	}

	return addr, true
}

func AreUdpAddrsEqual(addr1, addr2 *net.UDPAddr) bool {
	if addr1 == nil || addr2 == nil {
		return addr1 == addr2
	}
	return addr1.IP.Equal(addr2.IP) && addr1.Port == addr2.Port && addr1.Zone == addr2.Zone
}

// ============================================================

func GenerateViaWithoutBranch(conn *net.UDPConn) string {
	udpsocket := GetUDPAddrFromConn(conn)
	return fmt.Sprintf("SIP/2.0/UDP %s", udpsocket)
}

func GenerateContact(skt *net.UDPAddr) string {
	return fmt.Sprintf("<sip:%s;transport=udp>", skt)
}

func GetURIUsername(uri string) string {
	if mtch := RMatch(uri, NumberOnly); len(mtch) > 0 {
		return mtch[1]
	}
	return ""
}

// =============================================================

func TrimWithSuffix(s string, sfx string) string {
	s = strings.Trim(s, " ")
	if s == "" {
		return s
	}
	return fmt.Sprintf("%s%s", s, sfx)
}

func GetNextIndex(pdu []byte, markstrng string) int {
	return bytes.Index(pdu, []byte(markstrng))
}

func GetUsedSize(pdu []byte) int {
	sz := len(pdu)
	for i := range sz {
		if pdu[i] == 0 {
			return i
		}
	}
	return sz
}

//nolint:cyclop
func CleanAndSplitHeader(HeaderValue string, DropParameterValueDQ ...bool) map[string]string {
	if HeaderValue == "" {
		return nil
	}

	NVC := make(map[string]string)
	splitChar := ';'

	splitCharFirstIndex := strings.IndexRune(HeaderValue, splitChar)
	if splitCharFirstIndex == -1 {
		NVC["!headerValue"] = HeaderValue
		return NVC
	}

	NVC["!headerValue"] = HeaderValue[:splitCharFirstIndex]

	chrlst := []rune(HeaderValue[splitCharFirstIndex:])
	var sb strings.Builder

	var fn, fv string
	DQO := false
	dropDQ := len(DropParameterValueDQ) > 0 && DropParameterValueDQ[0]

	for i := 0; i < len(chrlst); {
		switch chrlst[i] {
		case ' ':
			if DQO {
				sb.WriteRune(chrlst[i])
			}
		case '=':
			if DQO {
				sb.WriteRune(chrlst[i])
			} else {
				fn = sb.String()
				sb.Reset()
			}
		case splitChar:
			if DQO {
				sb.WriteRune(chrlst[i])
			} else {
				if sb.Len() == 0 {
					break
				}
				fv = sb.String()
				NVC[fn] = DropConcatenationChars(fv, dropDQ)
				fn, fv = "", ""
				sb.Reset()
			}
		case '"':
			if DQO {
				fv = sb.String()
				NVC[fn] = DropConcatenationChars(fv, dropDQ)
				fn, fv = "", ""
				sb.Reset()
				DQO = false
			} else {
				DQO = true
			}
		default:
			sb.WriteRune(chrlst[i])
		}
		// chrlst = append(chrlst[:i], chrlst[i+1:]...)
		chrlst = slices.Delete(chrlst, i, i+1)
	}

	if fn != "" && sb.Len() > 0 {
		fv = sb.String()
		NVC[fn] = DropConcatenationChars(fv, dropDQ)
	}

	return NVC
}

// Extracts Parameters in URI (semi-colon delimited) - keepFirst = true, gives the first match with key = "!headerValue"
func ExtractParameters(headerValue string, keepFirst bool) map[string]string {
	if headerValue == "" {
		return nil
	}

	matches := DicFieldRegExp[Parameters].FindAllStringSubmatch(headerValue, -1)
	parameters := make(map[string]string, len(matches))

	for i, match := range matches {
		if i == 0 && keepFirst {
			parameters["!headerValue"] = match[1]
			continue
		}
		parameters[match[1]] = match[2] + match[3]
	}

	return parameters
}

func DropConcatenationChars(s string, dropDQ bool) string {
	if dropDQ {
		s = strings.ReplaceAll(s, "'", "")
		return strings.ReplaceAll(s, `"`, "")
	}
	return s
}

func ParseParameters(parsline string) map[string]string {
	parsline = strings.Trim(parsline, ";")
	parsline = strings.Trim(parsline, ",")
	parsMap := make(map[string]string)
	if parsline == "" {
		return parsMap
	}
	for tpl := range strings.SplitSeq(parsline, ";") {
		tmp := strings.SplitN(tpl, "=", 2)
		switch len(tmp) {
		case 1:
			if _, ok := parsMap[tmp[0]]; !ok {
				parsMap[tmp[0]] = ""
			} else {
				LogError(LTSIPStack, fmt.Sprintf("duplicate parameter: [%s] - in line: [%s]", tmp[0], parsline))
			}
		case 2:
			if _, ok := parsMap[tmp[0]]; !ok {
				parsMap[tmp[0]] = tmp[1]
			} else {
				LogError(LTSIPStack, fmt.Sprintf("duplicate parameter: [%s] - in line: [%s]", tmp[0], parsline))
			}
		default:
			LogError(LTSIPStack, fmt.Sprintf("badly formatted parameter line: [%s] - skipped", parsline))
		}
	}
	return parsMap
}

func GenerateParameters(pars map[string]string) string {
	if pars == nil {
		return ""
	}
	var sb strings.Builder
	for k, v := range pars {
		if v == "" {
			sb.WriteString(fmt.Sprintf(";%s", k))
		} else {
			sb.WriteString(fmt.Sprintf(";%s=%s", k, v))
		}
	}
	return sb.String()
}

func RandomNum(minlmt, maxlmt uint32) uint32 {
	//#nosec G404: Ignoring gosec error - crypto is not required
	return rand.Uint32N(maxlmt-minlmt+1) + minlmt
}

func GetBodyType(contentType string) BodyType {
	contentType = ASCIIToLower(contentType)
	for k, v := range DicBodyContentType {
		if v == contentType {
			return k
		}
	}
	if strings.Contains(contentType, "xml") {
		return AnyXML
	}
	return Unknown
}

// ==========================================================================================

// Convert string to int with default value with included minimum or maximum
func Str2IntDefaultMinMax[T int | int8 | int16 | int32 | int64](s string, d, minlmt, maxlmt T) (T, bool) {
	out, ok := Str2IntCheck[T](s)
	if ok {
		if out < minlmt || out > maxlmt {
			return d, false
		}
		return out, true
	}
	return d, false
}

func Str2IntCheck[T int | int8 | int16 | int32 | int64](s string) (T, bool) {
	var out T
	if len(s) == 0 {
		return out, false
	}
	idx := 0
	isN := s[idx] == '-'
	if isN {
		idx++
		if len(s) == 1 {
			return out, false
		}
	} else if s[idx] == '+' {
		idx++
	}
	for i := idx; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return out, false
		}
		out = out*10 + T(s[i]-'0')
	}
	if isN {
		out = -out
	}
	return out, true
}

func Str2UintCheck[T uint | uint8 | uint16 | uint32 | uint64](s string) (T, bool) {
	var out T
	if len(s) == 0 {
		return out, false
	}
	idx := 0
	if s[idx] == '+' {
		idx++
		if len(s) == 1 {
			return out, false
		}
	}
	for i := idx; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return out, false
		}
		out = out*10 + T(s[i]-'0')
	}
	return out, true
}

func Str2Int[T int | int8 | int16 | int32 | int64](s string) T {
	var out T
	if len(s) == 0 {
		return out
	}
	idx := 0
	isN := s[idx] == '-'
	if isN {
		idx++
	}
	for i := idx; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return out
		}
		out = out*10 + T(s[i]-'0')
	}
	if isN {
		return -out
	}
	return out
}

func Str2Uint[T uint | uint8 | uint16 | uint32 | uint64](s string) T {
	var out T
	if len(s) == 0 {
		return out
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return out
		}
		out = out*10 + T(s[i]-'0')
	}
	return out
}

func Int2Str(val int) string {
	if val == 0 {
		return "0"
	}
	buf := make([]byte, 10)
	return int2str(buf, val)
}

func Uint16ToStr(val uint16) string {
	if val == 0 {
		return "0"
	}
	buf := make([]byte, 5)
	return uint2str(buf, val)
}

// Uint32ToStr converts a uint32 to its string representation.
func Uint32ToStr(val uint32) string {
	if val == 0 {
		return "0"
	}
	buf := make([]byte, 10)
	return uint2str(buf, val)
}

// Uint64ToStr converts a uint64 to its string representation.
func Uint64ToStr(val uint64) string {
	if val == 0 {
		return "0"
	}
	buf := make([]byte, 20)
	return uint2str(buf, val)
}

func uint2str[T uint16 | uint32 | uint64](buf []byte, val T) string {
	i := len(buf)
	for val >= 10 {
		i--
		buf[i] = '0' + byte(val%10)
		val /= 10
	}
	i--
	buf[i] = '0' + byte(val)

	return string(buf[i:])
}

func int2str[T int | int8 | int16 | int32 | int64](buf []byte, val T) string {
	isNeg := val < 0
	if isNeg {
		val *= -1
	}
	i := len(buf)
	for val >= 10 {
		i--
		buf[i] = '0' + byte(val%10)
		val /= 10
	}
	i--
	buf[i] = '0' + byte(val)

	if isNeg {
		return "-" + string(buf[i:])
	}
	return string(buf[i:])
}

//====================================================

func GetEnumString[T comparable](m map[T]string, s string, keepCase bool) T {
	if !keepCase {
		s = ASCIIToLower(s)
	}
	var rslt T
	for k, v := range m {
		if v == s {
			return k
		}
	}
	return rslt
}

//==================================================

func DropVisualSeparators(strng string) string {
	var sb strings.Builder
	for _, r := range strng {
		switch r {
		case '.', '-', '(', ')':
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func KeepOnlyNumerics(strng string) string {
	var sb strings.Builder
	for _, r := range strng {
		if r < '0' || r > '9' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func ASCIIToLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += byte(DeltaRune)
		}
		b.WriteByte(c)
	}
	return b.String()
}

func ASCIIToUpper(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if 'a' <= c && c <= 'z' {
			c -= byte(DeltaRune)
		}
		b.WriteByte(c)
	}
	return b.String()
}

func LowerDash(s string) string {
	return strings.ReplaceAll(ASCIIToLower(s), " ", "-")
}

func ASCIIPascal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		if 'a' <= c && c <= 'z' && (i == 0 || s[i-1] == '-') {
			c -= byte(DeltaRune)
		}
		b.WriteByte(c)
	}
	return b.String()
}

func HeaderCase(h string) string {
	h = ASCIIToLower(h)
	for k := range HeaderStringtoEnum {
		if ASCIIToLower(k) == h {
			return k
		}
	}
	return ASCIIPascal(h)
}

func ASCIIToLowerInPlace(s []byte) {
	for i := range s {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		s[i] = c
	}
}

//==================================================

func Any[T any](items []*T, predicate func(*T) bool) bool {
	return slices.ContainsFunc(items, predicate)
}

func Find[T any](items []*T, predicate func(*T) bool) *T {
	for _, item := range items {
		if predicate(item) {
			return item
		}
	}
	return nil
}

func Filter[T any](items []*T, predicate func(*T) bool) []*T {
	var result []*T
	for _, item := range items {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

func FirstKeyValue[T1 comparable, T2 any](m map[T1]T2) (T1, T2) {
	var key T1
	var value T2
	for k, v := range m {
		return k, v
	}
	return key, value
}

func Keys[T1 comparable, T2 any](m map[T1]T2) []T1 {
	rslt := make([]T1, 0, len(m))
	for k := range m {
		rslt = append(rslt, k)
	}
	return rslt
}

func OnlyKey[T1 comparable, T2 any](m map[T1]T2) T1 {
	k, _ := FirstKeyValue(m)
	return k
}

func FirstValue[T1 comparable, T2 any](m map[T1]T2) T2 {
	_, v := FirstKeyValue(m)
	return v
}

func GetEnum[T1 comparable, T2 comparable](m map[T1]T2, i T2) T1 {
	var rslt T1
	for k, v := range m {
		if v == i {
			return k
		}
	}
	return rslt
}

func Map[T1, T2 any](data []T1, mapper func(T1) T2) []T2 {
	o := make([]T2, len(data))

	for i, datum := range data {
		o[i] = mapper(datum)
	}

	return o
}

func RemoveAt[T any](slice []T, i int) []T {
	slice[i] = slice[len(slice)-1] // Overwrite element at index 1 with last element
	return slice[:len(slice)-1]    // Trim last element
}

func Reverse[T any](s []T) []T {
	out := make([]T, len(s))
	for i := len(s) - 1; i >= 0; i-- {
		out = append(out, s[i])
	}
	return out
}

// ===================================================================

func StringToHexString(input string) string {
	return BytesToHexString(StringToBytes(input))
}

func StringToBytes(input string) []byte {
	return []byte(input)
}

func BytesToHexString(data []byte) string {
	return hex.EncodeToString(data)
}

func BytesToBase64String(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func HashSDPBytes(bytes []byte) string {
	// hash := sha256.New()
	// return bytesToHexString(hash.Sum(bytes))
	hash := sha256.Sum256(bytes)
	return BytesToHexString(hash[:])
}

//===================================================================

func LogInfo(lt LogTitle, msg string) {
	LogHandler(LLInformation, lt, msg)
}

func LogWarning(lt LogTitle, msg string) {
	// LogHandler(LLWarning, lt, msg)
}

func LogError(lt LogTitle, msg string) {
	// LogHandler(LLError, lt, msg)
}

func LogHandler(ll LogLevel, lt LogTitle, msg string) {
	log.Printf("\t%s\t%s\t%s\n", ll.String(), lt.String(), msg)
}

//===================================================================

func RMatch(s string, rgxfp FieldPattern) []string {
	if s == "" {
		return nil
	}
	return DicFieldRegExp[rgxfp].FindStringSubmatch(s)
}

func RReplace(input string, rgxfp FieldPattern, replacement string) string {
	return DicFieldRegExp[rgxfp].ReplaceAllString(input, replacement)
}

func RReplaceNumberOnly(input string, replacement string) string {
	return DicFieldRegExp[ReplaceNumberOnly].ReplaceAllString(input, replacement)
}

func TranslateInternal(input string, matches []string) (string, error) {
	if input == "" {
		return "", nil
	}
	if matches == nil {
		return "", fmt.Errorf("empty matches slice")
	}
	sbToInt := func(sb strings.Builder) uint32 {
		return Str2Uint[uint32](sb.String())
	}

	item := func(idx uint32, dblbrkt bool) string {
		if idx >= uint32(len(matches)) {
			if dblbrkt {
				return fmt.Sprintf("${%s}", Uint32ToStr(idx))
			}
			return Uint32ToStr(idx)
		}
		return matches[idx]
	}

	var b strings.Builder
outerloop:
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == '$' {
			i++
			if i == len(input) {
				b.WriteByte(c)
				return b.String(), nil
			}
			c = input[i]
			if c == '$' {
				b.WriteByte(c)
				continue outerloop
			}
			var grpsb strings.Builder
			for {
				if '0' <= c && c <= '9' {
					grpsb.WriteByte(c)
					i++
					if i == len(input) {
						v := item(sbToInt(grpsb), false)
						b.WriteString(v)
						return b.String(), nil
					}
					c = input[i]
				} else if c == '{' {
					if grpsb.Len() == 0 {
						break
					}
					b.WriteByte(c)
					v := item(sbToInt(grpsb), false)
					b.WriteString(v)
					continue outerloop
				} else {
					if grpsb.Len() == 0 {
						b.WriteByte('$')
						b.WriteByte(c)
					} else {
						v := item(sbToInt(grpsb), false)
						b.WriteString(v)
					}
					continue outerloop
				}
			}
			for {
				i++
				if i == len(input) {
					return "", fmt.Errorf("bracket unclosed")
				}
				c = input[i]
				if '0' <= c && c <= '9' {
					grpsb.WriteByte(c)
				} else if c == '}' {
					if grpsb.Len() == 0 {
						return "", fmt.Errorf("bracket closed without group index")
					}
					v := item(sbToInt(grpsb), true)
					b.WriteString(v)
					continue outerloop
				} else if c == '{' {
					b.WriteByte(c)
					continue outerloop
				} else {
					return "", fmt.Errorf("invalid character within bracket")
				}
			}
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}

func TranslateExternal(input string, rgxstring string, trans string) (string, bool) {
	rgx, err := regexp.Compile(rgxstring)
	if err != nil {
		return "", false
	}
	var result []byte

	matches := rgx.FindStringSubmatchIndex(input)
	if len(matches) == 0 {
		return "", false
	}

	result = rgx.ExpandString(result, trans, input, matches)
	return string(result), true
}

// Use rgx.FindStringSubmatchIndex(input) to get matches
func TranslateResult(rgx *regexp.Regexp, input string, trans string, matches []int) string {
	var result []byte
	result = rgx.ExpandString(result, trans, input, matches)
	return string(result)
}

func TranslatePattern(input string, rgx *regexp.Regexp, trans string) (string, bool) {
	var (
		result    []byte
		resultStr string
	)

	matches := rgx.FindStringSubmatchIndex(input)
	if len(matches) == 0 {
		return "", false
	}

	result = rgx.ExpandString(result, trans, input, matches)
	resultStr = string(result)

	return resultStr, (resultStr != "" && trans != "") || (resultStr == "" && trans == "")
}

// Make sure to check if returned string is empty
func DropOptionTag(input, optionTag string) string {
	if rgx, err := regexp.Compile(fmt.Sprintf(`(^\s*%s\s*,?\s*|\s*,\s*%s)`, optionTag, optionTag)); err == nil {
		return rgx.ReplaceAllString(input, "")
	}

	return input
}

//===================================================================

func Stringlen(s string) int {
	return utf8.RuneCountInString(s)
}

//nolint:exhaustive
func (m Method) IsDialogueCreating() bool {
	switch m {
	case OPTIONS, REGISTER, SUBSCRIBE, MESSAGE, INVITE: // NEGOTIATE
		return true
	}
	return false
}

//nolint:exhaustive
func (m Method) RequiresACK() bool {
	switch m {
	case INVITE, ReINVITE:
		return true
	}
	return false
}

// =====================================================

func (he HeaderEnum) LowerCaseString() string {
	h := HeaderEnumToString[he]
	return ASCIIToLower(h)
}

func (he HeaderEnum) String() string {
	return HeaderEnumToString[he]
}

// case insensitive equality with string header name
func (he HeaderEnum) Equals(h string) bool {
	return he.LowerCaseString() == ASCIIToLower(h)
}

// ====================================================

func IsProvisional(sc int) bool {
	return 100 <= sc && sc <= 199
}

func IsProvisional18x(sc int) bool {
	return 180 <= sc && sc <= 189
}

func Is18xOrPositive(sc int) bool {
	return (180 <= sc && sc <= 189) || (200 <= sc && sc <= 299)
}

func IsFinal(sc int) bool {
	return 200 <= sc && sc <= 699
}

func IsPositive(sc int) bool {
	return 200 <= sc && sc <= 299
}

func IsNegative(sc int) bool {
	return 300 <= sc && sc <= 699
}

func IsRedirection(sc int) bool {
	return 300 <= sc && sc <= 399
}

func IsNegativeClient(sc int) bool {
	return 400 <= sc && sc <= 499
}

func IsNegativeServer(sc int) bool {
	return 500 <= sc && sc <= 599
}

func IsNegativeGlobal(sc int) bool {
	return 600 <= sc && sc <= 699
}

//===================================================================
