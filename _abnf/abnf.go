//go:build ignore
// +build ignore

package abnf

import (
	"fmt"
	"regexp"
)

// Precompiled regex map
var CompiledRegexMap = make(map[string]*regexp.Regexp)

func InitializeABNF() {
	// Core components
	// TODO : Replace ALL [0-9] to \d
	regexMap := map[string]string{
		"SP":                 `\s`,       // Space
		"HTAB":               `\t`,       // Horizontal tab
		"CR":                 `\r`,       // Carriage return
		"LF":                 `\n`,       // Line feed
		"ALPHA":              `[A-Za-z]`, // A-Z or a-z
		"DIGIT":              `[0-9]`,    // 0-9
		"DQOUTE":             `"`,
		"quoted-pair":        `\\(?:[\x00-\x09\x0B\x0C\x0E-\x7F])`,
		"UTF8-CONT":          `[\x80-\xBF]`,
		"port":               `[0-9]+`,                                           // Port
		"dec-octet":          `([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])`, // Decimal octet
		"HEXDIG":             `[0-9A-Fa-f]`,                                      // HEXDIG
		"h16":                `[0-9A-Fa-f]{1,4}`,
		"npdi":               `;npdi`,
		"isub-encoding-tag":  `isub-encoding`,
		"enum-dip-indicator": `;enumdi`,
		"premrate-tag":       `;premrate-rate`,
		"premrate-value":     `information|entertainment`,
		"verstat-tag":        `verstat`,
		"INVITEm":            `INVITE`,
		"ACKm":               `ACK`,
		"OPTIONSm":           `OPTIONS`,
		"BYEm":               `BYE`,
		"CANCELm":            `CANCEL`,
		"REGISTERm":          `REGISTER`,
		"INFOm":              `INFO`,
		"PRACKm":             `PRACK`,
		"SUBSCRIBEm":         `SUBSCRIBE`,
		"NOTIFYm":            `NOTIFY`,
		"UPDATEm":            `UPDATE`,
		"MESSAGEm":           `MESSAGE`,
		"REFERm":             `REFER`,
		"PUBLISHm":           `PUBLISH`,
		"lr-param":           `lr`,
		"sip-ind":            `sip:|sips:`,
		"annc-ind":           `annc`,
		"dialog-ind":         `dialog`,
		"Infromational":      `100|180|181|182|183|199`,
		"Success":            `200|202|204`,
		"Redirection":        `300|301|302|305|380`,
		"Client-Error":       `400|401|402|403|404|405|406|407|408|410|412|413|414|415|416|417|420|421|422|423|424|425|428|429|430|433|436|437|438|439|440|469|470|480|481|482|483|484|485|486|487|488|489|491|493|494`,
		"Server-Error":       `500|501|502|503|504|505|513|555|580`,
		"Global-Failure":     `600|603|604|606|607|608`,
		"method-param":       `method=(get|post)`,
		"json-value":         `false|null|true|object|array|number|string`,
		"ob-param":           `ob`,
		`bnc-param`:          `bnc`,
		`sg-param`:           `sg`,
		`m-param`:            `m=(BS|NR|NL)`,
		"iotl-tag":           `iotl`,
		"orig":               `orig`,
		"sos-param":          `sos`,
		"delta-sconds":       `[0-9]+`,
		"boolean":            `TRUE|FALSE`,
		"number":             `^[+-]?[0-9]+(\.[0-9]*)?$`,
		"base-tags":          `audio|automata|class|duplex|data|control|mobility|description|events|priority|methods|schemes|application|video|language|type|isfocus|actor|text|extensions`,
	}

	// Larger components
	regexMap["WSP"] = fmt.Sprintf(`(%s|%s)`, regexMap["SP"], regexMap["HTAB"]) // White space
	regexMap["CRLF"] = fmt.Sprintf(`(%s%s)`, regexMap["CR"], regexMap["LF"])   // Carriage Return and Line Feed
	regexMap["WSP"] = fmt.Sprintf(`(%s|%s)`, regexMap["SP"], regexMap["HTAB"]) // White space
	regexMap["LWS"] = fmt.Sprintf(`(?:%s)?%s+`, regexMap["CRLF"], regexMap["WSP"])
	regexMap["SWS"] = regexMap["LWS"]
	regexMap["SEMI"] = fmt.Sprintf(`%s;%s`, regexMap["SWS"], regexMap["SWS"])
	regexMap["COMMA"] = fmt.Sprintf(`%s,%s`, regexMap["SWS"], regexMap["SWS"])
	regexMap["HCOLON"] = fmt.Sprintf(`(?:%s)*:%s`, regexMap["WSP"], regexMap["SWS"])
	regexMap["number"] = fmt.Sprintf(`(?:\+|\-)?%s(?:\.(?:%s)*)?`,
		regexMap["DIGIT"],
		regexMap["DIGIT"])
	regexMap["alphanum"] = fmt.Sprintf(`%s|%s`, regexMap["ALPHA"], regexMap["DIGIT"])
	regexMap["token"] = `[a-zA-Z0-9\-\.!%*_+` + "`" + `'~]+`
	regexMap["EQUAL"] = fmt.Sprintf(`%s=%s`, regexMap["SWS"], regexMap["SWS"])
	regexMap["index-val"] = fmt.Sprintf(`%s(?:\.%s)*`, regexMap["number"], regexMap["number"])
	regexMap["UTF8-NONASCII"] = fmt.Sprintf(
		`(?:[\xC0-\xDF][%s]+|[\xE0-\xEF][%s]{2,}|[\xF0-\xF7][%s]{3,}|[\xF8-\xFB][%s]{4,}|[\xFC-\xFD][%s]{5,})`,
		regexMap["UTF8-CONT"], regexMap["UTF8-CONT"], regexMap["UTF8-CONT"], regexMap["UTF8-CONT"], regexMap["UTF8-CONT"],
	)
	regexMap["qdtext"] = fmt.Sprintf(
		`(?:%s|[\x21]|[\x23-\x5B]|[\x5D-\x7E]|%s)`,
		regexMap["LWS"],
		regexMap["UTF8-NONASCII"],
	)
	regexMap["quoted-string"] = fmt.Sprintf(
		`(?:%s)?\"(?:%s|%s)*\"`,
		regexMap["SWS"],    // Optional leading whitespace
		regexMap["qdtext"], // Valid quoted string text (e.g., !, # to [, ] to ~, non-ASCII)
		regexMap["quoted-pair"],
	)
	regexMap["IPv4address"] = fmt.Sprintf(
		`(?:%s)\.(?:%s)\.(?:%s)\.(?:%s)`,
		regexMap["dec-octet"], // First octet
		regexMap["dec-octet"], // Second octet
		regexMap["dec-octet"], // Third octet
		regexMap["dec-octet"], // Fourth octet
	)
	regexMap["ls32"] = fmt.Sprintf(
		`(?:%s:%s|%s)`,
		regexMap["h16"],         // First h16
		regexMap["h16"],         // Second h16
		regexMap["IPv4address"], // IPv4 address
	)
	regexMap["IPv6address"] = fmt.Sprintf(
		`(?:%s:){6}%s`,
		regexMap["h16"],  // 6 h16 blocks
		regexMap["ls32"], // ls32 part (either h16:h16 or IPv4address)
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|::(?:%s:){5}%s`,
		regexMap["h16"],  // 5 h16 blocks
		regexMap["ls32"], // ls32 part
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|(?:%s)?::(?:%s:){4}%s`,
		regexMap["h16"],  // Optional h16 block
		regexMap["h16"],  // 4 h16 blocks
		regexMap["ls32"], // ls32 part
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|(?:%s:){0,1}%s::(?:%s:){3}%s`,
		regexMap["h16"],  // 1 optional h16 block
		regexMap["h16"],  // 1 more h16 block
		regexMap["h16"],  // 3 h16 blocks
		regexMap["ls32"], // ls32 part
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|(?:%s:){0,2}%s::(?:%s:){2}%s`,
		regexMap["h16"],  // 2 optional h16 blocks
		regexMap["h16"],  // 1 more h16 block
		regexMap["h16"],  // 2 h16 blocks
		regexMap["ls32"], // ls32 part
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|(?:%s:){0,3}%s::%s:%s`,
		regexMap["h16"],  // 3 optional h16 blocks
		regexMap["h16"],  // 1 more h16 block
		regexMap["h16"],  // 1 more h16 block
		regexMap["ls32"], // ls32 part
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|(?:%s:){0,4}%s::%s`,
		regexMap["h16"],  // 4 optional h16 blocks
		regexMap["h16"],  // 1 more h16 block
		regexMap["ls32"], // ls32 part
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|(?:%s:){0,5}%s::%s`,
		regexMap["h16"], // 5 optional h16 blocks
		regexMap["h16"], // 1 more h16 block
		regexMap["h16"], // 1 more h16 block
	)
	regexMap["IPv6address"] += fmt.Sprintf(
		`|(?:%s:){0,6}%s::`,
		regexMap["h16"], // 6 optional h16 blocks
		regexMap["h16"], // 1 more h16 block
	)
	regexMap["IPv6reference"] = fmt.Sprintf(
		`\[%s\]`,
		regexMap["IPv6address"], // Use the previously defined IPv6 address regex
	)
	regexMap["domainlabel"] = fmt.Sprintf(
		`(%s|%s(?:%s|-)*)%s`,
		regexMap["alphanum"],  // First alphanum
		regexMap["alphanum"],  // First alphanum in the middle
		regexMap["alphanum"],  // Allowed alphanum after hyphen
		regexMap["alpha num"], // Last alphanum
	)
	regexMap["toplabel"] = fmt.Sprintf(
		`(%s|%s(?:%s|\-)*)%s`,
		regexMap["ALPHA"],     // First alphanum
		regexMap["ALPHA"],     // First alphanum in the middle
		regexMap["alphanum"],  // Allowed alphanum after hyphen
		regexMap["alpha num"], // Last alphanum
	)
	regexMap["hostname"] = fmt.Sprintf(
		`^((%s)\.)*%s\.?$`,
		regexMap["domainlabel"], // Domainlabel + dot
		regexMap["toplabel"],    // Toplabel
	)
	regexMap["host"] = fmt.Sprintf(
		`^(%s|%s|%s)$`,
		regexMap["hostname"],      // Hostname
		regexMap["IPv4address"],   // IPv4 Address
		regexMap["IPv6reference"], // IPv6 Reference
	)
	regexMap["hostport"] = fmt.Sprintf(
		`^%s(:%s)?$`,
		regexMap["host"], // Host regex
		regexMap["port"], // Port regex
	)
	regexMap["gen-value"] = fmt.Sprintf(
		`^(%s|%s|%s)$`, regexMap["token"], regexMap["host"], regexMap["quoted-string"],
	)
	regexMap["generic-param"] = fmt.Sprintf(
		`(%s)(%s%s)?`,
		regexMap["token"],     // Matches the token
		regexMap["EQUAL"],     // Matches the "=" with optional spaces
		regexMap["gen-value"], // Matches the gen-value
	)
	regexMap["LAQUOT"] = fmt.Sprintf(`%s<`, regexMap["SWS"]) // Left angle quote
	regexMap["RAQUOT"] = fmt.Sprintf(`>%s`, regexMap["SWS"]) // Right angle quote
	regexMap["escaped"] = fmt.Sprintf("%%%s%s", regexMap["HEXDIG"], regexMap["HEXDIG"])
	regexMap["pct-encoded"] = regexMap["escaped"]
	regexMap["mark"] = `[-_\.!~\*'\(\)]`
	regexMap["alphanum"] = fmt.Sprintf(`^(%s|%s)$`, regexMap["ALPHA"], regexMap["DIGIT"])
	regexMap["unreserved"] = fmt.Sprintf(
		`^(%s|%s)$`, regexMap["alphanum"], regexMap["mark"],
	)
	regexMap["uric-no-slash"] = fmt.Sprintf(`(%s|%s|[;\?@&=\+\$,])`, regexMap["unreserved"], regexMap["escaped"])
	regexMap["reserved"] = `[;\/\?@&=\+\$,]`
	regexMap["uric"] = fmt.Sprintf(`(%s|%s|%s)`, regexMap["reserved"], regexMap["unreserved"], regexMap["escaped"])
	regexMap["opaque-part"] = fmt.Sprintf(`%s(%s)*`, regexMap["uric-no-slash"], regexMap["uric"])
	regexMap["query"] = fmt.Sprintf(`(%s)*`, regexMap["uric"])
	regexMap["pchar"] = fmt.Sprintf(`(%s|%s|[:@&=\+\$,])`, regexMap["unreserved"], regexMap["escaped"])
	regexMap["param"] = fmt.Sprintf(`%s*`, regexMap["pchar"])
	regexMap["segment"] = fmt.Sprintf(`%s*(;%s)*`, regexMap["pchar"], regexMap["param"])
	regexMap["path-segments"] = fmt.Sprintf(`%s(/%s)*`, regexMap["segment"], regexMap["segment"])
	regexMap["abs-path"] = fmt.Sprintf(`/%s`, regexMap["path-segments"])
	regexMap["reg-name"] = fmt.Sprintf(`(%s|%s|[\$,;:@&=\+])+`, regexMap["unreserved"], regexMap["escaped"])
	regexMap["password"] = fmt.Sprintf(`(%s|%s|[&=\+\$,])*`, regexMap["unreserved"], regexMap["escaped"])
	regexMap["user-unreserved"] = `[&=\+\$,;\?\/]`
	regexMap["user"] = fmt.Sprintf(`(?:%s|%s|%s)+`, regexMap["unreserved"], regexMap["escaped"], regexMap["user-unreserved"])
	regexMap["pname"] = fmt.Sprintf(`(?:%s|-)`, regexMap["alphanum"]) + "+"
	regexMap["param-unreserved"] = `[\[\]\/:&\+\$]`
	regexMap["paramchar"] = fmt.Sprintf(`(?:%s|%s|%s)`, regexMap["param-unreserved"], regexMap["unreserved"], regexMap["pct-encoded"])
	regexMap["pvalue"] = fmt.Sprintf(`%s+`, regexMap["paramchar"])
	regexMap["parameter"] = fmt.Sprintf(`;%s(?:=%s)?`, regexMap["pname"], regexMap["pvalue"])
	regexMap["visual-separator"] = `[-\.\(\)]`
	regexMap["phonedigit"] = fmt.Sprintf(`%s|[%s]`, regexMap["DIGIT"], regexMap["visual-separator"])
	regexMap["extension"] = fmt.Sprintf(`;ext=%s+`, regexMap["phonedigit"])
	regexMap["isdn-subaddress"] = fmt.Sprintf(`;isub=%s+`, regexMap["uric"])
	regexMap["hex-phonedigit"] = fmt.Sprintf(`%s|%s`, regexMap["HEXDIG"], regexMap["visual-separator"])
	regexMap["global-hex-digits"] = fmt.Sprintf(`\+%s{1,3}%s*`, regexMap["DIGIT"], regexMap["hex-phonedigit"])
	regexMap["global-rn"] = regexMap["global-hex-digits"]
	regexMap["domainname"] = fmt.Sprintf(`(%s\.)*%s\.?`, regexMap["domainlabel"], regexMap["toplabel"])
	regexMap["rn-descriptor"] = fmt.Sprintf(`%s|%s`, regexMap["domainname"], regexMap["global-hex-digits"])
	regexMap["rn-context"] = fmt.Sprintf(`;rn-context=%s`, regexMap["rn-descriptor"])
	regexMap["local-rn"] = fmt.Sprintf(`(%s)+%s`, regexMap["hex-phonedigit"], regexMap["rn-context"])
	regexMap["rn"] = fmt.Sprintf(`;rn=(%s|%s)`, regexMap["global-rn"], regexMap["local-rn"])
	regexMap["global-cic"] = regexMap["global-hex-digits"]
	regexMap["cic-context"] = fmt.Sprintf(`;cic-context=%s`, regexMap["rn-descriptor"])
	regexMap["local-cic"] = fmt.Sprintf(`(%s)+%s`, regexMap["hex-phonedigit"], regexMap["cic-context"])
	regexMap["cic"] = fmt.Sprintf(`;cic=(%s|%s)`, regexMap["global-cic"], regexMap["local-cic"])
	regexMap["isub-encoding-value"] = fmt.Sprintf(`(?:nsap-ia5|nsap-bcd|nsap|%s)`, regexMap["token"])
	regexMap["isub-encoding"] = fmt.Sprintf(`%s=%s`, regexMap["isub-encoding-tag"], regexMap["isub-encoding-value"])
	regexMap["trunk-group-unreserved"] = `[\/&\+\$]`
	regexMap["trunk-group-label"] = fmt.Sprintf(`(?:%s|%s|%s)+`, regexMap["unreserved"], regexMap["escaped"], regexMap["trunk-group-unreserved"])
	regexMap["trunk-group"] = fmt.Sprintf(`;tgrp=%s`, regexMap["trunk-group-label"])
	regexMap["global-number-digits"] = fmt.Sprintf(`\+%s*%s%s*`, regexMap["phonedigit"], regexMap["DIGIT"], regexMap["phonedigit"])
	regexMap["descriptor"] = fmt.Sprintf(`%s|%s`, regexMap["domainname"], regexMap["global-number-digits"])
	regexMap["trunk-context"] = fmt.Sprintf(`;trunk-context=%s`, regexMap["descriptor"])
	regexMap["premrate"] = fmt.Sprintf(`%s=%s`, regexMap["premrate-tag"], regexMap["premrate-value"])
	regexMap["other-value"] = regexMap["token"]
	regexMap["other-transport"] = regexMap["token"]
	regexMap["other-user"] = regexMap["token"]
	regexMap["extension-method"] = regexMap["token"]
	regexMap["other-compression"] = regexMap["token"]
	regexMap["vxml-keyword"] = regexMap["token"]
	regexMap["vxml-value"] = regexMap["token"]
	regexMap["extension-code"] = fmt.Sprintf("%s{3}", regexMap["DIGIT"])

	regexMap["verstat-value"] = fmt.Sprintf(`TN-Validation-Passed|TN-Validation-Failed|No-TN-Validation|%s`, regexMap["other-value"])
	regexMap["verstat"] = fmt.Sprintf(`%s=%s`, regexMap["verstat-tag"], regexMap["verstat-value"])
	regexMap["par"] = fmt.Sprintf(`(?:%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s)`,
		regexMap["parameter"],
		regexMap["extension"],
		regexMap["isdn-subaddress"],
		regexMap["rn"],
		regexMap["cic"],
		regexMap["npdi"],
		regexMap["isub-encoding"],
		regexMap["enum-dip-indicator"],
		regexMap["trunk-group"],
		regexMap["trunk-context"],
		regexMap["premrate"],
		regexMap["verstat"])

	regexMap["global-number"] = fmt.Sprintf(`%s%s*`, regexMap["global-number-digits"], regexMap["par"])
	regexMap["phonedigit-hex"] = fmt.Sprintf(
		`%s|\*|#|[%s]`,
		regexMap["HEXDIG"],
		regexMap["visual-separator"],
	)
	regexMap["local-number-digits"] = fmt.Sprintf(
		`*%s(%s|\*|#)*%s`,
		regexMap["phonedigit-hex"],
		regexMap["HEXDIG"],
		regexMap["phonedigit-hex"],
	)
	regexMap["context"] = fmt.Sprintf(`;phone-context=%s`, regexMap["descriptor"])
	regexMap["local-number"] = fmt.Sprintf(
		`%s%s*%s%s*`,
		regexMap["local-number-digits"],
		regexMap["par"],
		regexMap["context"],
		regexMap["par"],
	)
	regexMap["telephone-subscriber"] = fmt.Sprintf(`%s|%s`, regexMap["global-number"], regexMap["local-number"])
	regexMap["hnv-unreserved"] = `[\[\]\/\?:\+\$]`
	regexMap["hvalue"] = fmt.Sprintf(
		`(%s|%s|%s)*`,
		regexMap["hnv-unreserved"],
		regexMap["unreserved"],
		regexMap["escaped"],
	)
	regexMap["hname"] = fmt.Sprintf(
		`(%s|%s|%s)+`,
		regexMap["hnv-unreserved"],
		regexMap["unreserved"],
		regexMap["escaped"],
	)
	regexMap["header"] = fmt.Sprintf(`%s=%s`, regexMap["hname"], regexMap["hvalue"])
	regexMap["headers"] = fmt.Sprintf(
		`\?%s(\&%s)*`,
		regexMap["header"],
		regexMap["header"],
	)
	regexMap["transport-param"] = fmt.Sprintf( // check this regex
		`transport=(udp|tcp|sctp|tls|ws|%s)`,
		regexMap["other-transport"],
	)
	regexMap["user-param"] = fmt.Sprintf(
		`user=(phone|ip|dialstring|%s)`,
		regexMap["other-user"],
	)
	regexMap["Method"] = fmt.Sprintf(`%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s`,
		regexMap["INVITEm"],
		regexMap["ACKm"],
		regexMap["OPTIONSm"],
		regexMap["BYEm"],
		regexMap["CANCELm"],
		regexMap["REGISTERm"],
		regexMap["INFOm"],
		regexMap["PRACKm"],
		regexMap["SUBSCRIBEm"],
		regexMap["NOTIFYm"],
		regexMap["UPDATEm"],
		regexMap["MESSAGEm"],
		regexMap["REFERm"],
		regexMap["PUBLISHm"],
		regexMap["extension-method"])
	regexMap["method-param"] = fmt.Sprintf(`method=%s`, regexMap["Method"])
	regexMap["ttl"] = fmt.Sprintf(`%s{1,3}`, regexMap["DIGIT"])
	regexMap["ttl-param"] = fmt.Sprintf(`ttl=%s`, regexMap["ttl"])
	regexMap["maddr-param"] = fmt.Sprintf(`maddr=%s`, regexMap["host"])
	regexMap["compression-param"] = fmt.Sprintf(`comp=(sigcomp|%s)`, regexMap["other-compression"]) // check this regex
	regexMap["announcement-id"] = fmt.Sprintf(`[%s%s]+`, regexMap["ALPHA"], regexMap["DIGIT"])      // check this regex
	regexMap["variable-value"] = regexMap["announcement-id"]                                        // check this regex
	regexMap["prompt-url"] = fmt.Sprintf(`\/provisioned\/%s`, regexMap["announcement-id"])
	regexMap["play-param"] = fmt.Sprintf(`play=%s`, regexMap["prompt-url"])
	regexMap["delay-value"] = fmt.Sprintf(`%s+`, regexMap["DIGIT"])
	regexMap["duration-param"] = regexMap["duration-value"]
	regexMap["delay-param"] = fmt.Sprintf(`delay=%s`, regexMap["delay-value"])
	regexMap["duration-param"] = fmt.Sprintf(`duration=%s`, regexMap["duration-value"])
	regexMap["repeat-value"] = fmt.Sprintf(`(%s+|forever)`, regexMap["DIGIT"])
	regexMap["repeat-param"] = fmt.Sprintf(`repeat=%s`, regexMap["repeat-value"])
	regexMap["locale-param"] = fmt.Sprintf(`locale=%s`, regexMap["token"])
	regexMap["param-name"] = fmt.Sprintf(`param%s`, regexMap["DIGIT"])
	regexMap["variable-params"] = fmt.Sprintf(`%s=%s`, regexMap["param-name"], regexMap["variable-value"])
	regexMap["extension-param"] = fmt.Sprintf(`%s=%s`, regexMap["token"], regexMap["token"])
	regexMap["extension-params"] = fmt.Sprintf(`%s(?:;%s)?`,
		regexMap["extension-param"],
		regexMap["extension-params"]) // check this regex, it uses it's self
	regexMap["annc-parameters"] = fmt.Sprintf(`;(%s)(?:;(%s))?(?:;(%s))?(?:;(%s))?(?:;(%s))?(?:;(%s))?(?:;(%s))?`, // check this regex
		regexMap["play-param"],
		regexMap["delay-param"],
		regexMap["duration-param"],
		regexMap["repeat-param"],
		regexMap["locale-param"],
		regexMap["variable-params"],
		regexMap["extension-params"])
	regexMap["dialog-param"] = fmt.Sprintf(`voicexml=%s`, regexMap["vxml-url"]) // vxml-url is not defined and not found in the document
	regexMap["vxml-param"] = fmt.Sprintf(`;%s=%s`, regexMap["vxml-keyword"], regexMap["vxml-value"])
	regexMap["vxml-parameters"] = fmt.Sprintf(`%s(?:%s)?`, regexMap["vxml-param"], regexMap["vxml-parameters"])                                         // check this regex
	regexMap["dialog-parameters"] = fmt.Sprintf(`;%s(?:%s)?(?:%s)?`, regexMap["dialog-param"], regexMap["vxml-parameters"], regexMap["uri-parameters"]) // uri-parameters is circular dependency
	regexMap["target-param"] = fmt.Sprintf(`target%s%s`, regexMap["EQUAL"], regexMap["pvalue"])
	regexMap["Status-Code"] = fmt.Sprintf(
		`(%s|%s|%s|%s|%s|%s|%s)`,
		regexMap["Informational"],
		regexMap["Success"],
		regexMap["Redirection"],
		regexMap["Client-Error"],
		regexMap["Server-Error"],
		regexMap["Global-Failure"],
		regexMap["extension-code"],
	)
	regexMap["cause-param"] = fmt.Sprintf(`cause%s%s`, regexMap["EQUAL"], regexMap["Status-Code"])
	regexMap["uri-sip-sigcomp-id"] = fmt.Sprintf(`sigcomp-id=%s`, regexMap["paramchar"])
	regexMap["maxage-param"] = fmt.Sprintf(`maxage=%s+`, regexMap["DIGIT"])
	regexMap["maxstale-param"] = fmt.Sprintf(`maxstale=%s+`, regexMap["DIGIT"])
	regexMap["postbody-param"] = fmt.Sprintf(`postbody=%s`, regexMap["token"])
	regexMap["ccxml-param"] = fmt.Sprintf(`ccxml=%s+`, regexMap["json-value"])
	regexMap["aai-param"] = fmt.Sprintf(`aai=%s+`, regexMap["json-value"])
	regexMap["gr-param"] = fmt.Sprintf(`gr(?:=%s)?`, regexMap["pvalue"])
	regexMap["iotl-char"] = fmt.Sprintf(`(?:%s|\-)`, regexMap["alphanum"])
	regexMap["other-iotl"] = fmt.Sprintf(`%s+`, regexMap["iotl-char"]) // check this regex
	regexMap["iotl-value"] = `homea-homeb|homeb-visitedb|visiteda-homea|visiteda-homeb|homea-visiteda|visiteda-homeb|` + regexMap["other-iotl"]
	regexMap["iotl-param"] = fmt.Sprintf(`%s=%s(?:\.%s)?`, regexMap["iotl-tag"], regexMap["iotl-value"], regexMap["iotl-value"])
	regexMap["pn-param"] = fmt.Sprintf(`pn-param%s%s`, regexMap["EQUAL"], regexMap["pvalue"])
	regexMap["pn-prid"] = fmt.Sprintf(`pn-prid%s%s`, regexMap["EQUAL"], regexMap["pvalue"])
	regexMap["pn-provider"] = fmt.Sprintf(`pn-provider(?:%s%s)?`, regexMap["EQUAL"], regexMap["pvalue"])
	regexMap["pn-purr"] = fmt.Sprintf(`pn-purr%s%s`, regexMap["EQUAL"], regexMap["pvalue"])
	regexMap["other-param"] = fmt.Sprintf(`%s(?:=%s)?`, regexMap["pname"], regexMap["pvalue"])
	regexMap["uri-parameter"] = fmt.Sprintf(
		`%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s`,
		regexMap["transport-param"], regexMap["user-param"], regexMap["method-param"], regexMap["ttl-param"],
		regexMap["maddr-param"], regexMap["lr-param"], regexMap["compression-param"], regexMap["annc-parameters"],
		regexMap["dialog-parameters"], regexMap["target-param"], regexMap["cause-param"], regexMap["uri-sip-sigcomp-id"],
		regexMap["dialog-param"], regexMap["maxage-param"], regexMap["maxstale-param"], regexMap["postbody-param"],
		regexMap["ccxml-param"], regexMap["aai-param"], regexMap["ob-param"], regexMap["gr-param"],
		regexMap["bnc-param"], regexMap["sg-param"], regexMap["m-param"], regexMap["iotl-param"],
		regexMap["pn-param"], regexMap["pn-prid"], regexMap["pn-provider"], regexMap["pn-purr"],
		regexMap["orig"], regexMap["sos-param"], regexMap["other-param"],
	)
	regexMap["uri-parameters"] = fmt.Sprintf(`(?:;(%s))*`, regexMap["uri-parameter"]) // check this regex
	regexMap["ANNC-URL"] = fmt.Sprintf(`%s%s@%s%s%s`, regexMap["sip-ind"], regexMap["annc-ind"], regexMap["hostport"], regexMap["annc-parameters"], regexMap["uri-parameters"])
	regexMap["userinfo"] = fmt.Sprintf(`(%s|%s)(:%s)?@`, regexMap["user"], regexMap["telephone-subscriber"], regexMap["password"])
	regexMap["SIP-URI"] = fmt.Sprintf(`sip:(%s)?%s%s(%s)?$`, regexMap["userinfo"], regexMap["hostport"], regexMap["uri-parameters"], regexMap["headers"])
	regexMap["SIPS-URI"] = fmt.Sprintf(`sips:(%s)?%s%s(%s)?$`, regexMap["userinfo"], regexMap["hostport"], regexMap["uri-parameters"], regexMap["headers"])
	regexMap["srvr"] = fmt.Sprintf(`((%s)?%s)?`, regexMap["userinfo"], regexMap["hostport"]) // check this regex
	regexMap["authority"] = fmt.Sprintf(`%s|%s`, regexMap["srvr"], regexMap["reg-name"])
	regexMap["net-path"] = fmt.Sprintf(`\/\/%s(?:%s)?`,
		regexMap["authority"],
		regexMap["abs-path"])
	regexMap["hier-part"] = fmt.Sprintf(`(?:%s|%s)(?:\?%s)?`, regexMap["net-path"], regexMap["abs-path"], regexMap["query"])
	regexMap["scheme"] = fmt.Sprintf(`%s[%s|%s|%s]*`, regexMap["ALPHA"], regexMap["ALPHA"], regexMap["DIGIT"], `\+\-\.`)
	regexMap["absoluteURI"] = fmt.Sprintf(`%s:(%s|%s)`, regexMap["scheme"], regexMap["hier-part"], regexMap["opaque-part"])
	regexMap["addr-spec"] = fmt.Sprintf(`%s|%s|%s`, regexMap["SIP-URI"], regexMap["SIPS-URI"], regexMap["absoluteURI"])
	regexMap["name-addr"] = fmt.Sprintf(`(?:%s)?%s%s%s`, regexMap["display-name"], regexMap["LAQUOTE"], regexMap["addr-spec"], regexMap["RAQUOTE"])
	regexMap["hi-targeted-to-uri"] = regexMap["name-addr"]
	regexMap["hi-entry"] = fmt.Sprintf(`%s(?:%s%s)*`, regexMap["hi-targeted-to-uri"], regexMap["SEMI"], regexMap["hi-param"])
	regexMap["STAR"] = fmt.Sprintf(`%s\*%s`, regexMap["SWS"], regexMap["SWS"])
	regexMap["c-p-q"] = fmt.Sprintf(`q%s%s`, regexMap["EQUAL"], regexMap["qvalue"])                    // check this regex
	regexMap["c-p-expires"] = fmt.Sprintf(`expires%s%s`, regexMap["EQUAL"], regexMap["delta-seconds"]) // check this regex
	regexMap["token-nobang"] = fmt.Sprintf(`(?:%s|%s|\-|\.|%%|\*|_|\\+|`+"`|\\'|~)+",
		regexMap["ALPHA"],
		regexMap["DIGIT"])
	regexMap["numeric-relation"] = fmt.Sprintf(`%s|%s|%s|%s`, ">=", "<=", "=", regexMap["number"])
	regexMap["numeric"] = fmt.Sprintf(`#%s%s`, regexMap["numeric-relation"], regexMap["number"])
	regexMap["tag-value"] = fmt.Sprintf(`!?%s|%s|%s`,
		regexMap["token-nobang"],
		regexMap["boolean"],
		regexMap["numeric"])
	regexMap["tag-value-list"] = fmt.Sprintf(`%s(?:,%s)*`,
		regexMap["tag-value"],
		regexMap["tag-value"])
	regexMap["qdtext-no-abkt"] = fmt.Sprintf(`%s|%s|%s|%s|%s|%s|%s`,
		regexMap["LWS"],
		`!`,
		`[\x23-\x3B]`,
		`=`,
		`[\x3F-\x5B]`,
		`[\x5D-\x7E]`,
		regexMap["UTF8-NONASCII"]) // check this regex
	regexMap["string-value"] = fmt.Sprintf(`<%s|%s*>`, regexMap["qdtext-no-abkt"], regexMap["quoted-pair"])
	regexMap["ftag-name"] = fmt.Sprintf(`%s(?:%s|%s|!|'|\.|\-|%%)*`,
		regexMap["ALPHA"],
		regexMap["ALPHA"],
		regexMap["DIGIT"])

	regexMap["other-tags"] = fmt.Sprintf(`\+%s`, regexMap["ftag-name"])
	regexMap["enc-feature-tag"] = fmt.Sprintf("%s|%s", regexMap["base-tags"], regexMap["other-tags"])
	regexMap["feature-param"] = fmt.Sprintf(`%s(%s%s(%s|%s)%s)?`, regexMap["enc-feature-tag"], regexMap["EQUAL"], regexMap["LDQUOT"], regexMap["tag-value-list"], regexMap["string-value"], regexMap["RDQUOT"]) // check this regex
	regexMap["c-p-reg"] = fmt.Sprintf(`reg-id%s%s+`, regexMap["EQUAL"], regexMap["DIGIT"])
	regexMap["instance-val"] = fmt.Sprintf(`%s*`, regexMap["uric"])
	regexMap["c-p-instance"] = fmt.Sprintf(`\+sip\.instance%s%s<%s>%s`, regexMap["EQUAL"], regexMap["LDQUOT"], regexMap["instance-val"], regexMap["RDQUOT"])
	regexMap["temp-gruu"] = fmt.Sprintf(`temp-gruu%s%s(?:%s|%s)*%s`, regexMap["EQUAL"], regexMap["LDQUOT"], regexMap["qdtext"], regexMap["quoted-pair"], regexMap["RDQUOT"])
	regexMap["pub-gruu"] = fmt.Sprintf(`pub-gruu%s%s(?:%s|%s)*%s`, regexMap["EQUAL"], regexMap["LDQUOT"], regexMap["qdtext"], regexMap["quoted-pair"], regexMap["RDQUOT"])
	// temp‑gruu‑cookie Not found in the document
	regexMap["contact-extension"] = regexMap["generic-param"]
	regexMap["contact-params"] = fmt.Sprintf(`(?:%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s)`,
		regexMap["c-p-q"],
		regexMap["c-p-expires"],
		regexMap["feature-param"],
		regexMap["c-p-reg"],
		regexMap["c-p-instance"],
		regexMap["temp-gruu"],
		regexMap["pub-gruu"],
		regexMap["temp-gruu-cookie"],
		regexMap["mp-param"],
		regexMap["rc-param"],
		regexMap["np-param"],
		regexMap["contact-extension"])
	regexMap["contact-param"] = fmt.Sprintf(`(?:%s|%s)(?:%s%s)*`,
		regexMap["name-addr"],
		regexMap["addr-spec"],
		regexMap["SEMI"],
		regexMap["contact-params"])
	regexMap["pkg-param-value"] = fmt.Sprintf(`(?:isdn-uui|%s)`, regexMap["token"])
	regexMap["pkg-param"] = fmt.Sprintf(`purpose%s%s`, regexMap["EQUAL"], regexMap["pkg-param-value"])
	regexMap["cont-param-value"] = regexMap["pkg-param-value"]
	regexMap["cont-param"] = fmt.Sprintf(`content%s%s`, regexMap["EQUAL"], regexMap["cont-param-value"])
	regexMap["enc-param-value"] = fmt.Sprintf(`(?:hex|%s)`, regexMap["token"])
	regexMap["enc-param"] = fmt.Sprintf(`encoding%s%s`, regexMap["EQUAL"], regexMap["enc-param-value"])
	regexMap["uui-data"] = fmt.Sprintf(`(?:%s|%s|%s|%s)`,
		regexMap["pkg-param"],
		regexMap["cont-param"],
		regexMap["enc-param"],
		regexMap["generic-param"])
	regexMap["uui-param"] = fmt.Sprintf(`(?:%s|%s)`,
		regexMap["token"],
		regexMap["quoted-string"])
	regexMap["uui-value"] = fmt.Sprintf(`%s(?:%s%s)*`,
		regexMap["uui-data"],
		regexMap["SEMI"],
		regexMap["uui-param"])
	regexMap["PAssertedID-value"] = fmt.Sprintf(`(?:%s|%s)`,
		regexMap["name-addr"],
		regexMap["addr-spec"])
	regexMap["PAssertedID"] = fmt.Sprintf(`P-Asserted-Identity%s%s(?:%s%s)*`,
		regexMap["HCOLON"],
		regexMap["PAssertedID-value"],
		regexMap["COMMA"],
		regexMap["PAssertedID-value"])
	regexMap["priv-value"] = fmt.Sprintf(`(?:header|session|user|none|critical|id|history|%s)`,
		regexMap["token"])
	regexMap["tag-param"] = fmt.Sprintf(`tag%s%s`,
		regexMap["EQUAL"],
		regexMap["token"])
	regexMap["from-param"] = fmt.Sprintf(`(?:%s|%s)`,
		regexMap["tag-param"],
		regexMap["generic-param"])
	regexMap["from-spec"] = fmt.Sprintf(`(?:%s|%s)(?:%s%s)*`,
		regexMap["name-addr"],
		regexMap["addr-spec"],
		regexMap["SEMI"],
		regexMap["from-param"])
	regexMap["ietf-token"] = regexMap["token"]
	regexMap["iana-token"] = regexMap["token"]
	regexMap["m-attribute"] = regexMap["token"]
	regexMap["x-token"] = fmt.Sprintf(`x-%s`,
		regexMap["token"])
	regexMap["extension-token"] = fmt.Sprintf(`(?:%s|%s)`,
		regexMap["ietf-token"],
		regexMap["x-token"])
	regexMap["m-value"] = fmt.Sprintf(`(?:%s|%s)`,
		regexMap["token"],
		regexMap["quoted-string"])
	regexMap["discrete-type"] = fmt.Sprintf(`(?:text|image|audio|video|application|%s)`,
		regexMap["extension-token"])
	regexMap["composite-type"] = fmt.Sprintf(`(?:message|multipart|%s)`,
		regexMap["extension-token"])
	regexMap["m-type"] = fmt.Sprintf(`(?:%s|%s)`,
		regexMap["discrete-type"],
		regexMap["composite-type"])
	regexMap["m-subtype"] = fmt.Sprintf(`(?:%s|%s)`,
		regexMap["extension-token"],
		regexMap["iana-token"])
	regexMap["m-parameter"] = fmt.Sprintf(`%s%s%s`,
		regexMap["m-attribute"],
		regexMap["EQUAL"],
		regexMap["m-value"])
	regexMap["media-range"] = fmt.Sprintf(`(?:\*/\*|%s/\*|%s/%s)(?:%s%s)*`,
		regexMap["m-type"],
		regexMap["m-type"],
		regexMap["m-subtype"],
		regexMap["SEMI"],
		regexMap["m-parameter"])
	regexMap["accept-param"] = fmt.Sprintf(`(?:q%s%s|%s)`,
		regexMap["EQUAL"],
		regexMap["qvalue"],
		regexMap["generic-param"])
	regexMap["accept-range"] = fmt.Sprintf(`%s(?:%s%s)*`,
		regexMap["media-range"],
		regexMap["SEMI"],
		regexMap["accept-param"])
	regexMap["diversion-extension"] = fmt.Sprintf(`%s(?:%s(?:%s|%s))?`,
		regexMap["token"],
		regexMap["EQUAL"],
		regexMap["token"],
		regexMap["quoted-string"])
	regexMap["diversion-screen"] = fmt.Sprintf(`screen%s(?:yes|no|%s|%s)`,
		regexMap["EQUAL"],
		regexMap["token"],
		regexMap["quoted-string"])
	regexMap["diversion-privacy"] = fmt.Sprintf(`privacy%s(?:full|name|uri|off|%s|%s)`,
		regexMap["EQUAL"],
		regexMap["token"],
		regexMap["quoted-string"])
	regexMap["diversion-limit"] = fmt.Sprintf(`limit%s(?:%s){1,2}`,
		regexMap["EQUAL"],
		regexMap["DIGIT"])
	regexMap["diversion-counter"] = fmt.Sprintf(`counter%s(?:%s){1,2}`,
		regexMap["EQUAL"],
		regexMap["DIGIT"])
	regexMap["diversion-reason"] = fmt.Sprintf(`reason%s(?:unknown|user-busy|no-answer|unavailable|unconditional|time-of-day|do-not-disturb|deflection|follow-me|out-of-service|away|%s|%s)`,
		regexMap["EQUAL"],
		regexMap["token"],
		regexMap["quoted-string"])
	regexMap["diversion-params"] = fmt.Sprintf(`%s(?:%s(?:%s|%s|%s|%s|%s|%s)*)`,
		regexMap["name-addr"],
		regexMap["SEMI"],
		regexMap["diversion-reason"],
		regexMap["diversion-counter"],
		regexMap["diversion-limit"],
		regexMap["diversion-privacy"],
		regexMap["diversion-screen"],
		regexMap["diversion-extension"])
	regexMap["Diversion"] = fmt.Sprintf(`Diversion%s%s(?:%s%s)*`,
		regexMap["HCOLON"],
		regexMap["diversion-params"],
		regexMap["COMMA"],
		regexMap["diversion-params"])

	// Privacy Header
	regexMap["priv-value"] = fmt.Sprintf(`(?:header|session|user|none|critical|id|history|%s)`, regexMap["token"])
	regexMap["Privacy-hdr"] = fmt.Sprintf(`Privacy%s%s(?:;%s)*`, regexMap["HCOLON"], regexMap["priv-value"], regexMap["priv-value"])
	// ----------------------------
	// History-Info Header
	regexMap["np-param"] = fmt.Sprintf(`np%s%s`, regexMap["EQUAL"], regexMap["index-val"])
	regexMap["mp-param"] = fmt.Sprintf(`mp%s%s`, regexMap["EQUAL"], regexMap["index-val"])
	regexMap["rc-param"] = fmt.Sprintf(`rc%s%s`, regexMap["EQUAL"], regexMap["index-val"])
	regexMap["hi-target-param"] = fmt.Sprintf(`%s|%s|%s`, regexMap["np-param"], regexMap["mp-param"], regexMap["rc-param"])
	regexMap["hi-index"] = fmt.Sprintf(`index%s%s`, regexMap["EQUAL"], regexMap["index-val"])
	regexMap["hi-extension"] = regexMap["generic-param"]

	regexMap["hi-param"] = fmt.Sprintf(`^(%s|%s|%s)$`, regexMap["hi-index"], regexMap["hi-target-param"], regexMap["hi-extension"])
	regexMap["display-name"] = fmt.Sprintf(
		`((?:%s%s)*|%s)`,
		regexMap["token"],
		regexMap["LWS"],
		regexMap["quoted-string"],
	)
	regexMap["History-Info"] = fmt.Sprintf(`^History-Info%s%s(?:%s%s)*`, regexMap["HCOLON"], regexMap["hi-entry"], regexMap["COMMA"], regexMap["hi-entry"]) // check this regex
	// -----------------------------
	// Contact Header
	regexMap["Contact"] = fmt.Sprintf(`(?:Contact|m)%s(?:%s|(?:%s(?:%s%s)*))`,
		regexMap["HCOLON"],
		regexMap["STAR"],
		regexMap["contact-param"],
		regexMap["COMMA"],
		regexMap["contact-param"])

	// -----------------------------
	// Allow Header
	regexMap["Allow"] = fmt.Sprintf(`Allow%s(?:%s(?:%s%s)*)?`,
		regexMap["HCOLON"],
		regexMap["Method"],
		regexMap["COMMA"],
		regexMap["Method"])

	// -----------------------------FFF
	// User-to-User Header
	regexMap["UUI"] = fmt.Sprintf(`User-to-User%s%s(?:%s%s)*`,
		regexMap["HCOLON"],
		regexMap["uui-value"],
		regexMap["COMMA"],
		regexMap["uui-value"])

	// -----------------------------
	// To Header
	regexMap["To"] = fmt.Sprintf(`(?:To|t)%s(?:%s|%s)(?:%s%s)*`,
		regexMap["HCOLON"],
		regexMap["name-addr"],
		regexMap["addr-spec"],
		regexMap["SEMI"],
		regexMap["to-param"])

	// -----------------------------
	// From Header
	regexMap["From"] = fmt.Sprintf(`(?:From|f)%s%s`,
		regexMap["HCOLON"],
		regexMap["from-spec"])

	// -----------------------------
	// Accept Header
	regexMap["Accept"] = fmt.Sprintf(`Accept%s(?:%s(?:%s%s)*)?`,
		regexMap["HCOLON"],
		regexMap["accept-range"],
		regexMap["COMMA"],
		regexMap["accept-range"])

	// Precompiling regex patterns
	for key, pattern := range regexMap {
		CompiledRegexMap[key] = regexp.MustCompile("^" + pattern + "$")
	}
}
