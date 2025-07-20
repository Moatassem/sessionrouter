package global

import (
	"regexp"
	"sync"

	"SRGo/cl"
	"SRGo/prometheus"
)

const (
	EntityName       = "MT-Tools"
	B2BUAName        = "SRGo"
	B2BUANameVersion = "SRGo/1.7.2"

	RTPHeaderSize  int = 12
	RTPPayloadSize int = 160
	RTPMaxSize     int = 1500
	MediaStartPort int = 7000
	MediaEndPort   int = 57000

	ntpEpochOffset uint64 = 2208988800

	CdrBufferSize = 512
	PduBufferSize = 4096

	T1Timer                    = 500
	CancelTimeOut              = 10 // seconds
	ReTXCount                  = 5
	SipPort                    = 5060
	MaxPort                    = 65535
	MultipartBoundary   string = "unique-boundary-1"
	SipVersion          string = "SIP/2.0"
	DeltaRune           rune   = 'a' - 'A'
	MagicCookie         string = "z9hG4bK"
	AllowedMethods      string = "INVITE, PRACK, ACK, CANCEL, BYE, OPTIONS, UPDATE, INFO, REGISTER, REFER, SUBSCRIBE, NOTIFY, PUBLISH, MESSAGE"
	EchoAnswerDelaySec         = 2 // seconds
	SessionDropDelaySec        = 4 // seconds
	MinMaxFwds                 = 1
	OodProbingSec              = 60 // seconds
	IdProbingSec               = 60 // seconds
)

var (
	SipUdpPort  int // TODO add a list of listening UDP ports if needed later, for now, it is a single port
	HttpTcpPort int

	RateLimit = 1500 // TODO 2000 || 0 = switched off, -1 = unlimited, > 0 = limited

	BufferPool      *sync.Pool
	RTPRXBufferPool *sync.Pool
	RTPBuffer       *sync.Pool
	RTPTXBufferPool *sync.Pool

	Prometrics  *prometheus.Metrics
	CallLimiter *cl.CallLimiter
	WtGrp       sync.WaitGroup
)

var (
	MandatoryHeaders = [...]string{"From", "To", "Call-ID", "CSeq", "Via"}

	// =================================================================
	// Arrays to get the string representation of the enum values
	methods      = [...]string{"UNKNOWN", "INVITE", "INVITE", "REFER", "ACK", "CANCEL", "BYE", "OPTIONS", "NOTIFY", "UPDATE", "PRACK", "INFO", "REGISTER", "SUBSCRIBE", "MESSAGE", "PUBLISH", "NEGOTIATE"}
	directions   = [...]string{"INBOUND", "OUTBOUND"}
	messageTypes = [...]string{"INVALID", "REQUEST", "RESPONSE"}
	timeFormats  = [...]string{"Signaling", "Tracing", "version", "DateOnly", "TimeOnly", "DateTimeOnly", "Session", "HTML", "DateTimeLocal", "JsonDateTime", "HTMLDateOnly", "yyyy_MM_dd", "SimpleDT"}
	csModes      = [...]string{"CallRecording", "CallSummary", "CallTracing"}
	logtitles    = [...]string{"All", "AnswerMachine", "BadSIPMessage", "ChatMessage", "ConfigFiles", "Configuration", "Connectivity", "ContactCenter", "CustomCommand", "CustomCommandResult", "DTMF", "EmailNotification", "ExternalData", "FileUpload", "Webserver", "IPCollection", "License", "LogInOut", "MediaCapability", "MediaStack", "NAT", "PESQScore", "ResourceLimitation", "RTDGrabber", "Security", "SDPStack", "SIPStack", "SNMP", "StirShaken", "StressTester", "System", "TLSStack", "TTS", "UnhandledCritical", "Unspecified", "WebSocketData", "None"}
	loglevels    = [...]string{"Information", "Warning", "Error"}
	UriSchemes   = [...]string{"sip", "sips", "tel"}
	// =================================================================
	// Time Formats

	DicTFs = map[timeFormat]string{
		Signaling:      "Mon, 02 Jan 2006 15:04:05 GMT",
		Tracing:        "02-Jan-2006 15:04:05.000 GMT",
		Version:        "Monday 2-Jan-2006 15:04:05 GMT",
		DateOnly:       "2-Jan-2006 GMT",
		TimeOnly:       "15:04",
		DateTimeOnly:   "2-Jan-2006 15:04 GMT",
		Session:        "15:04:05 2-Jan-2006 GMT",
		HTML:           "2006-01-02T15:04:05Z",
		DateTimeLocal:  "2006-01-02T15:04",
		JsonDateTime:   "2006-01-02T15:04:05Z",
		JsonDateTimeMS: "2006-01-02T15:04:05.000Z",
		HTMLDateOnly:   "2006-01-02",
		SimpleDT:       "2006-01-02 15:04:05",
		CDRTimestamp:   "20060102_150405",
	}

	// =================================================================
	// Body Content Types

	DicBodyContentType = map[BodyType]string{
		SDP:                  "application/sdp",
		DTMF:                 "application/dtmf",
		DTMFRelay:            "application/dtmf-relay",
		MultipartMixed:       "multipart/mixed",
		MultipartAlternative: "multipart/alternative",
		MultipartRelated:     "multipart/related",
		ISUP:                 "application/isup",
		QSIG:                 "application/qsig",
		SIPFragment:          "message/sipfrag",
		SimpleMsgSummary:     "application/simple-message-summary",
		PlainText:            "text/plain",
		PIDFXML:              "application/pidf+xml",
		MSCPXML:              "application/mscp+xml",
		MSCXML:               "application/mediaservercontrol+xml",
		ResourceListXML:      "application/resource-lists+xml",
		VndEtsiPstnXML:       "application/vnd.etsi.pstn+xml",
		VndOrangeInData:      "application/vnd.orange.indata",
		AppJson:              "application/json",
		AnyXML:               "+xml",
	}

	// =================================================================
	// Field Regular Expressions
	DicFieldRegExp = map[FieldPattern]*regexp.Regexp{
		ExpiresParameter:           regexp.MustCompile(`(?i)expires\s*=\s*(\d+)`),
		RAckHeader:                 regexp.MustCompile(`(?i)^(\d+)\s+(\d+)\s+INVITE\s*$`),
		NumberOnly:                 regexp.MustCompile(`(?i)(?:sip|sips|tel):([\*\#\+]?[a-z0-9\.\-\(\)]+|Invalid|Anonymous|Unavailable)@?`),
		NameAndNumber:              regexp.MustCompile(`(?i)((?:[a-zA-Z0-9\-\.!%*_+` + "`" + `'~]+\s*)*"(?:[^"\\]|\\.)*")?\s*<(?:sip|tel):([\*\#\+]?[a-z0-9\.\-\(\)]+|Invalid|Anonymous|Unavailable)@?`),
		ReplaceNumberOnly:          regexp.MustCompile(`(?i)(.*?(?:sip|sips|tel):)(?:[\*\#\+]?[a-z0-9\.\-\(\)]+|Invalid|Anonymous|Unavailable)(.*)`),
		RequestStartLinePattern:    regexp.MustCompile(`(?i)^\s*([a-z]+)\s+((?:\w+):(?:(?:[^@]+)@)?(?:[^@]+))\s+(SIP/2\.0)$`),
		INVITERURI:                 regexp.MustCompile(`(?i)([a-z]+):(?:([\*\#\+]?[a-z0-9\.\-\(\)]+)((?:[,;](?:[\w\-]+=[^@=,;:]+|[\w\-]+))*)(:[^@]+)?@)?([^\*\#\+@,:;]+(?::(?:\d+))?)((?:[,;](?:[\w\-]+=[^@,;\?]+|[\w\-]+))*)(?:(\?[^?]+))*`),
		ContactHeader:              regexp.MustCompile(`(?i)([a-z]+):([\*\#\+]?[a-z0-9\.\-\(\)]+)((?:[,;](?:[\w\-]+=[^@=,;:]+|[\w\-]+))*)(:[^@]+)?@([^\*\#\+@,:;]+(?::(?:\d+))?)((?:[,;](?:[\w\-]+=[^@,;\?]+|[\w\-]+))*)(?:(\?[^?]+))*`),
		ResponseStartLinePattern:   regexp.MustCompile(`(?i)^\s*(SIP/2\.0)\s+(\d{3})(?:\s+([^,;]+)([,;].+)?)?$`),
		ViaBranchPattern:           regexp.MustCompile(`(?i);branch\s*=\s*([^;,]+)`),
		ViaTransport:               regexp.MustCompile(`(?i)SIP/2.0/(\w+)`),
		MediaPayloadTypes:          regexp.MustCompile(`(?i)^m=\w+\s+(\d+)\s+([^\s]+)\s+([\w\s]+)`),
		MediaPayloadTypeDefinition: regexp.MustCompile(`(?i)a=(?:rtpmap|fmtp)\s*:\s*(\d+)\s+`),
		SDPOriginLine:              regexp.MustCompile(`(?i)^o=([^\s]+)\s+(\d+)\s+(\d+)\s+IN\s+IP4\s+((?:\d{1,3}\.){3}\d{1,3})`),
		MediaDirective:             regexp.MustCompile(`(?i)^a=(sendrecv|sendonly|recvonly|inactive)\s*$`),
		ConnectionAddress:          regexp.MustCompile(`(?i)^c=IN\s+IP4\s+((?:\d{1,3}\.){3}\d{1,3})`),
		FullHeader:                 regexp.MustCompile(`(?i)^\s*([^:]+)\s*:\s*(.+)$`),
		MediaLine:                  regexp.MustCompile(`(?i)^m=(\w+)\s+(?:\d+)\s+`),
		HostIPPort:                 regexp.MustCompile(`(?i)(?:sip|sips|tel):(?:[^@]+@)?((?:\d{1,3}\.){3}\d{1,3}):(\d+);?`),
		FQDNPort:                   regexp.MustCompile(`(?i)(?:sip|sips|tel):(?:[^@]+@)?((?:[\w\-\.]+)(?::\d+)?)`),
		TransportProtocol:          regexp.MustCompile(`(?i)transport\s*=\s*(\w+)`),
		ViaIPv4Socket:              regexp.MustCompile(`(?i)\s*SIP/2\.0\/(\w+)\s+((?:\d{1,3}\.){3}\d{1,3})(?::(\d+))?\s*`),
		IP6:                        regexp.MustCompile(`(?i)((?:(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-f]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,1}(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,2}(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,3}(?:(?:[0-9a-f]{1,4})))?::(?:(?:[0-9a-f]{1,4})):)(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,4}(?:(?:[0-9a-f]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,5}(?:(?:[0-9a-f]{1,4})))?::)(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,6}(?:(?:[0-9a-f]{1,4})))?::)))))\s*$`),
		IP4:                        regexp.MustCompile(`(?i)((?:(?:2(?:5[0-5]|[0-4]\d)|1?\d?\d)\.){3}(?:2(?:5[0-5]|[0-4]\d)|1?\d?\d))\s*$`),
		HeaderParameter:            regexp.MustCompile(`(?i);([^=]+)=([^=;]+)`),
		SDPTime:                    regexp.MustCompile(`(?i)^t=(.+)`),
		Header:                     regexp.MustCompile(`(?i)^(?:[a-z]+-)*[a-z]+$`),
		URIFull:                    regexp.MustCompile(`(?i)((?:sip|sips|tel):[^>]+)`),
		URIParameters:              regexp.MustCompile(`(?i)^(?:[,;](?:[\w\-]+|[\w\-]+=[^@=,;]+))*$`),
		HTTPRequestStartLine:       regexp.MustCompile(`(?i)^([a-z]+)\s+((?:/[^\s/]*)+)\s+HTTP/1.1`),
		URIParameter:               regexp.MustCompile(`(?i)^([^=]+)=([^=]+)$`),
		Parameters:                 regexp.MustCompile(`([^=;"]+)(?:=(?:"([^"]+)"|([^;=]+)))?`),
		CSeqHeader:                 regexp.MustCompile(`(?i)(\d+)\s+([a-z]+)`),
		HandlingProfile:            regexp.MustCompile(`(?i)\[([a-z0-9_\-]+)\]`),
		ErrorStack:                 regexp.MustCompile(`(?i)(\w+\.vb):line\s(\d+)`),
		SDPALineReMapping:          regexp.MustCompile(`(?i)^(a=\w+\s*:\s*)(?:\d+)(.+)`),
		SDPPTDefinition:            regexp.MustCompile(`(?i)^a=rtpmap\s*:\s*\d+\s(.+)`),
		CodecPolicy:                regexp.MustCompile(`(?i)(([0-9]|[1-9][0-9]|1[01][0-9]|12[0-7])|\*)`),
		ObjectName:                 regexp.MustCompile(`(?i)^\[.+?\]$`),
		SignalDTMF:                 regexp.MustCompile(`(?i)^\s*(Signal)\s*=\s*([^\r\n]+)$`),
		DurationDTMF:               regexp.MustCompile(`(?i)^\s*(Duration)\s*=\s*([^\r\n]+)$`),
		ConfDropPart:               regexp.MustCompile(`(?i)^88(\d{1,2})[\*#]$`),
		Tag:                        regexp.MustCompile(`(?i);tag=([^;]+)`),
	}

	// =================================================================
	// Char Number to Name Mapping

	CharNumNameDic = map[string]string{
		"0": "Zero",
		"1": "One",
		"2": "Two",
		"3": "Three",
		"4": "Four",
		"5": "Five",
		"6": "Six",
		"7": "Seven",
		"8": "Eight",
		"9": "Nine",
	}

	// =================================================================
	// DicDTMFEvent

	DicDTMFEvent = map[byte]string{
		0:  "DTMF 0",
		1:  "DTMF 1",
		2:  "DTMF 2",
		3:  "DTMF 3",
		4:  "DTMF 4",
		5:  "DTMF 5",
		6:  "DTMF 6",
		7:  "DTMF 7",
		8:  "DTMF 8",
		9:  "DTMF 9",
		10: "DTMF *",
		11: "DTMF #",
		12: "DTMF A",
		13: "DTMF B",
		14: "DTMF C",
		15: "DTMF D",
		16: "DTMF Flash",
	}

	// =================================================================
	// DTMF Signal Mapping

	DicDTMFSignal = map[string]byte{
		"0":     0,
		"1":     1,
		"2":     2,
		"3":     3,
		"4":     4,
		"5":     5,
		"6":     6,
		"7":     7,
		"8":     8,
		"9":     9,
		"*":     10,
		"#":     11,
		"A":     12,
		"B":     13,
		"C":     14,
		"D":     15,
		"Flash": 16,
	}

	// =================================================================

	// =================================================================
	// Request Headers

	RequestHeaderCHs = []string{"Record-Route", "Route", "Via", "From", "To", "Call-ID", "CSeq", "Contact", "Supported", "Allow", "Max-Forwards", "Date", "User-Agent", "User-to-User", "Content-Type", "Content-Length", "Content-Disposition"}
	OtherCHs         = []string{"Referred-By", "Diversion", "History-Info", "X-FromHeader", "X-ToHeader", "Privacy", "Geolocation", "Require", "Authorization", "Identity", "Proxy-Authorization", "Expires", "Session-Expires", "Min-SE", "Subject", "Allow-Events", "Accept", "MIME-Version"}

	// returns proper case for headers
	DicRequestHeaders = map[Method][]string{
		INVITE:    append(RequestHeaderCHs, OtherCHs...),
		ReINVITE:  append(RequestHeaderCHs, OtherCHs...),
		ACK:       append(RequestHeaderCHs, "MIME-Version"),
		OPTIONS:   append(RequestHeaderCHs, "Subject", "Accept", "MIME-Version"),
		BYE:       append(RequestHeaderCHs, "Reason", "Warning"),
		CANCEL:    append(RequestHeaderCHs, "Reason", "Warning"),
		REFER:     append(RequestHeaderCHs, "Refer-Sub", "Refer-To"),
		PRACK:     append(RequestHeaderCHs, "RAck"),
		NOTIFY:    append(RequestHeaderCHs, "Event", "Subscription-State", "Subscription-Expires"),
		UPDATE:    append(RequestHeaderCHs, "Require", "Session-Expires", "Min-SE"),
		INFO:      RequestHeaderCHs,
		REGISTER:  append(RequestHeaderCHs, OtherCHs...),
		SUBSCRIBE: RequestHeaderCHs,
		MESSAGE:   RequestHeaderCHs,
	}

	// =================================================================
	// Headers

	HeaderStringtoEnum = map[string]HeaderEnum{
		"Accept":                        Accept,
		"Accept-Contact":                Accept_Contact,
		"Accept-Encoding":               Accept_Encoding,
		"Accept-Language":               Accept_Language,
		"Accept-Resource-Priority":      Accept_Resource_Priority,
		"Alert-Info":                    Alert_Info,
		"Allow":                         Allow,
		"Allow-Events":                  Allow_Events,
		"Answer-Mode":                   Answer_Mode,
		"Authentication-Info":           Authentication_Info,
		"Authorization":                 Authorization,
		"Call-ID":                       Call_ID,
		"Call-Info":                     Call_Info,
		"Compression":                   Compression,
		"Contact":                       Contact,
		"Content-Disposition":           Content_Disposition,
		"Content-Encoding":              Content_Encoding,
		"Content-Language":              Content_Language,
		"Content-Length":                Content_Length,
		"Content-Transfer-Encoding":     Content_Transfer_Encoding,
		"Content-Type":                  Content_Type,
		"Cisco-Guid":                    Cisco_Guid,
		"CSeq":                          CSeq,
		"Custom-CLI":                    Custom_CLI,
		"Date":                          Date,
		"Diversion":                     Diversion,
		"Error-Info":                    Error_Info,
		"Event":                         Event,
		"Expires":                       Expires,
		"Feature-Caps":                  Feature_Caps,
		"Flow-Timer":                    Flow_Timer,
		"From":                          From,
		"Geolocation":                   Geolocation,
		"Geolocation-Error":             Geolocation_Error,
		"Geolocation-Routing":           Geolocation_Routing,
		"History-Info":                  History_Info,
		"Identity":                      Identity,
		"Identity-Info":                 Identity_Info,
		"In-Reply-To":                   In_Reply_To,
		"Info-Package":                  Info_Package,
		"Join":                          Join,
		"Max-Breadth":                   Max_Breadth,
		"Max-Expires":                   Max_Expires,
		"Max-Forwards":                  Max_Forwards,
		"MIME-Version":                  MIME_Version,
		"Min-Expires":                   Min_Expires,
		"Min-SE":                        Min_SE,
		"Organization":                  Organization,
		"P-Add-BodyPart":                P_Add_BodyPart,
		"P-Access-Network-Info":         P_Access_Network_Info,
		"P-Answer-State":                P_Answer_State,
		"P-Asserted-Identity":           P_Asserted_Identity,
		"P-Asserted-Service":            P_Asserted_Service,
		"P-Associated-URI":              P_Associated_URI,
		"P-BusLayHeader":                P_BusLayHeader,
		"P-BusLayPayload":               P_BusLayPayload,
		"P-BusLayRefSIPA":               P_BusLayRefSIPA,
		"P-BusLayTimers":                P_BusLayTimers,
		"P-Called-Party-ID":             P_Called_Party_ID,
		"P-Charging-Function-Addresses": P_Charging_Function_Addresses,
		"P-Charging-Vector":             P_Charging_Vector,
		"P-DCS-Billing-Info":            P_DCS_Billing_Info,
		"P-DCS-LAES":                    P_DCS_LAES,
		"P-DCS-OSPS":                    P_DCS_OSPS,
		"P-DCS-Redirect":                P_DCS_Redirect,
		"P-DCS-Trace-Party-ID":          P_DCS_Trace_Party_ID,
		"P-Early-Media":                 P_Early_Media,
		"P-Media-Authorization":         P_Media_Authorization,
		"P-Orig":                        P_Orig,
		"P-OrigHeader":                  P_OrigHeader,
		"P-Preferred-Identity":          P_Preferred_Identity,
		"P-Preferred-Service":           P_Preferred_Service,
		"P-Private-Network-Indication":  P_Private_Network_Indication,
		"P-Profile-Key":                 P_Profile_Key,
		"P-Refused-URI-List":            P_Refused_URI_List,
		"P-Served-User":                 P_Served_User,
		"P-User-Database":               P_User_Database,
		"P-Visited-Network-ID":          P_Visited_Network_ID,
		"Path":                          Path,
		"Permission-Missing":            Permission_Missing,
		"Policy-Contact":                Policy_Contact,
		"Policy-ID":                     Policy_ID,
		"Priority":                      Priority,
		"Priv-Answer-Mode":              Priv_Answer_Mode,
		"Privacy":                       Privacy,
		"Proxy-Authenticate":            Proxy_Authenticate,
		"Proxy-Authorization":           Proxy_Authorization,
		"Proxy-Require":                 Proxy_Require,
		"RAck":                          RAck,
		"Reason":                        Reason,
		"Reason-Phrase":                 Reason_Phrase,
		"Record-Route":                  Record_Route,
		"Recv-Info":                     Recv_Info,
		"Refer-Events-At":               Refer_Events_At,
		"Refer-Sub":                     Refer_Sub,
		"Refer-To":                      Refer_To,
		"Referred-By":                   Referred_By,
		"Reject-Contact":                Reject_Contact,
		"Replaces":                      Replaces,
		"Reply-To":                      Reply_To,
		"Request-Disposition":           Request_Disposition,
		"Require":                       Require,
		"Resource-Priority":             Resource_Priority,
		"Retry-After":                   Retry_After,
		"Route":                         Route,
		"RSeq":                          RSeq,
		"Security-Client":               Security_Client,
		"Security-Server":               Security_Server,
		"Security-Verify":               Security_Verify,
		"Server":                        Server,
		"Service-Route":                 Service_Route,
		"Session-Expires":               Session_Expires,
		"Session-ID":                    Session_ID,
		"SIP-ETag":                      SIP_ETag,
		"SIP-If-Match":                  SIP_If_Match,
		"Subject":                       Subject,
		"Subscription-State":            Subscription_State,
		"Subscription-Expires":          Subscription_Expires,
		"Supported":                     Supported,
		"Suppress-If-Match":             Suppress_If_Match,
		"Target-Dialog":                 Target_Dialog,
		"Timestamp":                     Timestamp,
		"To":                            To,
		"Trigger-Consent":               Trigger_Consent,
		"Unsupported":                   Unsupported,
		"User-Agent":                    User_Agent,
		"User-to-User":                  User_to_User,
		"Via":                           Via,
		"Warning":                       Warning,
		"WWW-Authenticate":              WWW_Authenticate,
		"X-BusLayBehavior":              X_BusLayBehavior,
	}

	HeaderEnumToString = map[HeaderEnum]string{
		Accept:                        "Accept",
		Accept_Contact:                "Accept-Contact",
		Accept_Encoding:               "Accept-Encoding",
		Accept_Language:               "Accept-Language",
		Accept_Resource_Priority:      "Accept-Resource-Priority",
		Alert_Info:                    "Alert-Info",
		Allow:                         "Allow",
		Allow_Events:                  "Allow-Events",
		Answer_Mode:                   "Answer-Mode",
		Authentication_Info:           "Authentication-Info",
		Authorization:                 "Authorization",
		Call_ID:                       "Call-ID",
		Call_Info:                     "Call-Info",
		Compression:                   "Compression",
		Contact:                       "Contact",
		Content_Disposition:           "Content-Disposition",
		Content_Encoding:              "Content-Encoding",
		Content_Language:              "Content-Language",
		Content_Length:                "Content-Length",
		Content_Transfer_Encoding:     "Content-Transfer-Encoding",
		Content_Type:                  "Content-Type",
		Cisco_Guid:                    "Cisco-Guid",
		CSeq:                          "CSeq",
		Custom_CLI:                    "Custom-CLI",
		Date:                          "Date",
		Diversion:                     "Diversion",
		Error_Info:                    "Error-Info",
		Event:                         "Event",
		Expires:                       "Expires",
		Feature_Caps:                  "Feature-Caps",
		Flow_Timer:                    "Flow-Timer",
		From:                          "From",
		Geolocation:                   "Geolocation",
		Geolocation_Error:             "Geolocation-Error",
		Geolocation_Routing:           "Geolocation-Routing",
		History_Info:                  "History-Info",
		Identity:                      "Identity",
		Identity_Info:                 "Identity-Info",
		In_Reply_To:                   "In-Reply-To",
		Info_Package:                  "Info-Package",
		Join:                          "Join",
		Max_Breadth:                   "Max-Breadth",
		Max_Expires:                   "Max-Expires",
		Max_Forwards:                  "Max-Forwards",
		MIME_Version:                  "MIME-Version",
		Min_Expires:                   "Min-Expires",
		Min_SE:                        "Min-SE",
		Organization:                  "Organization",
		P_Add_BodyPart:                "P-Add-BodyPart",
		P_Access_Network_Info:         "P-Access-Network-Info",
		P_Answer_State:                "P-Answer-State",
		P_Asserted_Identity:           "P-Asserted-Identity",
		P_Asserted_Service:            "P-Asserted-Service",
		P_Associated_URI:              "P-Associated-URI",
		P_BusLayHeader:                "P-BusLayHeader",
		P_BusLayPayload:               "P-BusLayPayload",
		P_BusLayRefSIPA:               "P-BusLayRefSIPA",
		P_BusLayTimers:                "P-BusLayTimers",
		P_Called_Party_ID:             "P-Called-Party-ID",
		P_Charging_Function_Addresses: "P-Charging-Function-Addresses",
		P_Charging_Vector:             "P-Charging-Vector",
		P_DCS_Billing_Info:            "P-DCS-Billing-Info",
		P_DCS_LAES:                    "P-DCS-LAES",
		P_DCS_OSPS:                    "P-DCS-OSPS",
		P_DCS_Redirect:                "P-DCS-Redirect",
		P_DCS_Trace_Party_ID:          "P-DCS-Trace-Party-ID",
		P_Early_Media:                 "P-Early-Media",
		P_Media_Authorization:         "P-Media-Authorization",
		P_Orig:                        "P-Orig",
		P_OrigHeader:                  "P-OrigHeader",
		P_Preferred_Identity:          "P-Preferred-Identity",
		P_Preferred_Service:           "P-Preferred-Service",
		P_Private_Network_Indication:  "P-Private-Network-Indication",
		P_Profile_Key:                 "P-Profile-Key",
		P_Refused_URI_List:            "P-Refused-URI-List",
		P_Served_User:                 "P-Served-User",
		P_User_Database:               "P-User-Database",
		P_Visited_Network_ID:          "P-Visited-Network-ID",
		Path:                          "Path",
		Permission_Missing:            "Permission-Missing",
		Policy_Contact:                "Policy-Contact",
		Policy_ID:                     "Policy-ID",
		Priority:                      "Priority",
		Priv_Answer_Mode:              "Priv-Answer-Mode",
		Privacy:                       "Privacy",
		Proxy_Authenticate:            "Proxy-Authenticate",
		Proxy_Authorization:           "Proxy-Authorization",
		Proxy_Require:                 "Proxy-Require",
		RAck:                          "RAck",
		Reason:                        "Reason",
		Reason_Phrase:                 "Reason-Phrase",
		Record_Route:                  "Record-Route",
		Recv_Info:                     "Recv-Info",
		Refer_Events_At:               "Refer-Events-At",
		Refer_Sub:                     "Refer-Sub",
		Refer_To:                      "Refer-To",
		Referred_By:                   "Referred-By",
		Reject_Contact:                "Reject-Contact",
		Replaces:                      "Replaces",
		Reply_To:                      "Reply-To",
		Request_Disposition:           "Request-Disposition",
		Require:                       "Require",
		Resource_Priority:             "Resource-Priority",
		Retry_After:                   "Retry-After",
		Route:                         "Route",
		RSeq:                          "RSeq",
		Security_Client:               "Security-Client",
		Security_Server:               "Security-Server",
		Security_Verify:               "Security-Verify",
		Server:                        "Server",
		Service_Route:                 "Service-Route",
		Session_Expires:               "Session-Expires",
		Session_ID:                    "Session-ID",
		SIP_ETag:                      "SIP-ETag",
		SIP_If_Match:                  "SIP-If-Match",
		Subject:                       "Subject",
		Subscription_State:            "Subscription-State",
		Subscription_Expires:          "Subscription-Expires",
		Supported:                     "Supported",
		Suppress_If_Match:             "Suppress-If-Match",
		Target_Dialog:                 "Target-Dialog",
		Timestamp:                     "Timestamp",
		To:                            "To",
		Trigger_Consent:               "Trigger-Consent",
		Unsupported:                   "Unsupported",
		User_Agent:                    "User-Agent",
		User_to_User:                  "User-to-User",
		Via:                           "Via",
		Warning:                       "Warning",
		WWW_Authenticate:              "WWW-Authenticate",
		X_BusLayBehavior:              "X-BusLayBehavior",
	}

	ResponseHeaderCHs  = []string{"Record-Route", "Via", "From", "To", "Call-ID", "CSeq", "Contact", "Date", "Server", "Content-Length", "Accept"}
	DicResponseHeaders = make(map[int][]string)
)

// =================================================================

// Response Headers
//
//nolint:cyclop
func responsesHeadersInit() {
	for Rspns := 100; Rspns <= 699; Rspns++ {
		var HDRs []string
		switch {
		case Rspns >= 100 && Rspns <= 199:
			HDRs = append(ResponseHeaderCHs, "Require", "RSeq", "Allow", "Content-Type")
		case Rspns == 200:
			HDRs = append(ResponseHeaderCHs, "Supported", "Allow", "Require", "Session-Expires", "Min-SE", "Compression", "Refer-Sub", "Expires", "Content-Type", "MIME-Version")
		case Rspns >= 201 && Rspns <= 399:
			HDRs = append(ResponseHeaderCHs, "Expires", "Content-Type")
		case Rspns == 401:
			HDRs = append(ResponseHeaderCHs, "WWW-Authenticate")
		case Rspns == 407:
			HDRs = append(ResponseHeaderCHs, "Proxy-Authenticate")
		case Rspns == 415:
			HDRs = append(ResponseHeaderCHs, "Expires")
		case Rspns == 422:
			HDRs = append(ResponseHeaderCHs, "Min-SE")
		case Rspns == 423:
			HDRs = append(ResponseHeaderCHs, "Min-Expires")
		case Rspns == 425:
			HDRs = append(ResponseHeaderCHs, "Max-Expires")
		case Rspns == 489:
			HDRs = append(ResponseHeaderCHs, "Allow-Events")
		default:
			HDRs = append(ResponseHeaderCHs, "Allow", "Min-Expires", "Unsupported", "Reason", "Warning", "Retry-After")
		}
		DicResponseHeaders[Rspns] = HDRs
	}
}
