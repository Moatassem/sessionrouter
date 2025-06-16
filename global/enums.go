package global

import "slices"

// ==============================================================
type Method int

const (
	UNKNOWN Method = iota
	INVITE
	ReINVITE
	REFER
	ACK
	CANCEL
	BYE
	OPTIONS
	NOTIFY
	UPDATE
	PRACK
	INFO
	REGISTER
	SUBSCRIBE
	MESSAGE
	PUBLISH
	NEGOTIATE
)

func (m Method) String() string {
	return methods[m]
}

func MethodFromName(nm string) Method {
	idx := slices.IndexFunc(methods[:], func(m string) bool { return m == nm })
	if idx == -1 {
		return UNKNOWN
	}
	return Method(idx)
}

// ==============================================================
type BodyType int

const (
	None BodyType = iota
	SDP
	DTMF
	DTMFRelay
	SIPFragment
	SimpleMsgSummary
	PlainText
	AppJson

	MultipartAlternative
	MultipartFormData
	MultipartMixed
	MultipartRelated

	ISUP
	QSIG

	PIDFXML
	MSCPXML
	MSCXML
	VndEtsiPstnXML
	VndOrangeInData
	ResourceListXML
	AnyXML
	Unknown
)

// ==============================================================
type TimerType int

const (
	NoAnswer TimerType = iota
	No18x
)

func (tt TimerType) Details() string {
	if tt == NoAnswer {
		return "No-answer timer expired"
	}
	return "No-18x timer expired"
}

// ==============================================================

type Direction int

const (
	INBOUND Direction = iota
	OUTBOUND
)

func (d Direction) String() string {
	return directions[d]
}

// ==============================================================
type MessageType int

const (
	REQUEST MessageType = iota
	RESPONSE
	INVALID
)

func (mt MessageType) String() string {
	return messageTypes[mt]
}

// ==============================================================

type timeFormat int

const (
	Signaling timeFormat = iota
	Tracing
	Version
	DateOnly
	TimeOnly
	DateTimeOnly
	Session
	HTML
	DateTimeLocal
	JsonDateTime
	JsonDateTimeMS
	HTMLDateOnly
	SimpleDT
	CDRTimestamp
)

func (tf timeFormat) String() string {
	return timeFormats[tf]
}

// ==============================================================

type CSModes int

const (
	CallRecording CSModes = iota
	CallSummary
	CallTracing
)

func (cs CSModes) String() string {
	return csModes[cs]
}

// ==============================================================
type FieldPattern int

const (
	NumberOnly FieldPattern = iota
	NameAndNumber
	ReplaceNumberOnly
	RequestStartLinePattern
	INVITERURI
	ContactHeader
	ResponseStartLinePattern
	ViaBranchPattern
	ViaTransport
	MediaPayloadTypes
	MediaPayloadTypeDefinition
	SDPOriginLine
	MediaDirective
	ConnectionAddress
	FullHeader
	MediaLine
	HostIPPort
	FQDNPort
	TransportProtocol
	ViaIPv4Socket
	IP6
	IP4
	HeaderParameter
	SDPTime
	Header
	URIFull
	URIParameters
	HTTPRequestStartLine
	Parameters
	URIParameter
	CSeqHeader
	HandlingProfile
	ErrorStack
	SDPALineReMapping
	SDPPTDefinition
	CodecPolicy
	ObjectName
	SignalDTMF
	DurationDTMF
	ConfDropPart
	Tag
	RAckHeader
	ExpiresParameter
)

// ==============================================================
type LogLevel int

const (
	LLInformation LogLevel = iota
	LLWarning
	LLError
)

func (ll LogLevel) String() string {
	return loglevels[ll]
}

type LogTitle int

const (
	LTAll LogTitle = iota
	LTAnswerMachine
	LTBadSIPMessage
	LTChatMessage
	LTConfigFiles
	LTConfiguration
	LTConnectivity
	LTContactCenter
	LTCustomCommand
	LTCustomCommandResult
	LTDTMF
	LTEmailNotification
	LTExternalData
	LTFileUpload
	LTWebserver
	LTIPCollection
	LTLicense
	LTLogInOut
	LTMediaCapability
	LTMediaStack
	LTNAT
	LTPESQScore
	LTResourceLimitation
	LTRTDGrabber
	LTSecurity
	LTSDPStack
	LTSIPStack
	LTSNMP
	LTStirShaken
	LTStressTester
	LTSystem
	LTTLSStack
	LTTTS
	LTUnhandledCritical
	LTUnspecified
	LTWebSocketData
	LTNone LogTitle = -1
)

func (lt LogTitle) String() string {
	return logtitles[lt]
}

// ==============================================================

type NewSessionType int

const (
	Unset NewSessionType = iota
	ValidRequest
	DuplicateRequest
	InvalidRequest
	UnsupportedURIScheme
	UnsupportedBody
	ForbiddenRequest
	WithRequireHeader
	Response
	UnExpectedMessage
	NoAllowedAudioCodecs
	TooLowMaxForwards
	RegistrarOff
	ServerOff
	EndpointNotRegistered
	ExceededRouteCAC
	DisposedSession
	CallLegTransactionNotExist
	RouteBlocked
	UCLimitReached
	DuplicateMessage
	RouteOutboundOnly
	RouteBlackhole
	ExceededCallRate
	UnknownEndPoint
)

// ==============================================================

type HeaderEnum int

// revive:disable:var-naming
const (
	Accept HeaderEnum = iota
	Accept_Contact
	Accept_Encoding
	Accept_Language
	Accept_Resource_Priority
	Alert_Info
	Allow
	Allow_Events
	Answer_Mode
	Authentication_Info
	Authorization
	Call_ID
	Call_Info
	Compression
	Contact
	Content_Disposition
	Content_Encoding
	Content_Language
	Content_Length
	Content_Transfer_Encoding
	Content_Type
	Cisco_Guid
	CSeq
	Custom_CLI
	Date
	Diversion
	Error_Info
	Event
	Expires
	Feature_Caps
	Flow_Timer
	From
	Geolocation
	Geolocation_Error
	Geolocation_Routing
	History_Info
	Identity
	Identity_Info
	In_Reply_To
	Info_Package
	Join
	Max_Breadth
	Max_Expires
	Max_Forwards
	MIME_Version
	Min_Expires
	Min_SE
	Organization
	P_Add_BodyPart
	P_Access_Network_Info
	P_Answer_State
	P_Asserted_Identity
	P_Asserted_Service
	P_Associated_URI
	P_BusLayHeader
	P_BusLayPayload
	P_BusLayRefSIPA
	P_BusLayTimers
	P_Called_Party_ID
	P_Charging_Function_Addresses
	P_Charging_Vector
	P_DCS_Billing_Info
	P_DCS_LAES
	P_DCS_OSPS
	P_DCS_Redirect
	P_DCS_Trace_Party_ID
	P_Early_Media
	P_Media_Authorization
	P_Orig
	P_OrigHeader
	P_Preferred_Identity
	P_Preferred_Service
	P_Private_Network_Indication
	P_Profile_Key
	P_Refused_URI_List
	P_Served_User
	P_User_Database
	P_Visited_Network_ID
	Path
	Permission_Missing
	Policy_Contact
	Policy_ID
	Priority
	Priv_Answer_Mode
	Privacy
	Proxy_Authenticate
	Proxy_Authorization
	Proxy_Require
	RAck
	Reason
	Reason_Phrase
	Record_Route
	Recv_Info
	Refer_Events_At
	Refer_Sub
	Refer_To
	Referred_By
	Reject_Contact
	Replaces
	Reply_To
	Request_Disposition
	Require
	Resource_Priority
	Retry_After
	Route
	RSeq
	Security_Client
	Security_Server
	Security_Verify
	Server
	Service_Route
	Session_Expires
	Session_ID
	SIP_ETag
	SIP_If_Match
	Subject
	Subscription_State
	Subscription_Expires
	Supported
	Suppress_If_Match
	Target_Dialog
	Timestamp
	To
	Trigger_Consent
	Unsupported
	User_Agent
	User_to_User
	Via
	Warning
	WWW_Authenticate
	X_BusLayBehavior
)

// revive:enable:var-naming

// ==============================================================

type PRACKStatus int

const (
	PRACKExpected PRACKStatus = iota
	PRACKUnexpected
	PRACKMissingBadRAck
)

// ==============================================================

var DicResponse = map[int]string{
	// 1xx-Provisional Responses
	100: "Trying",
	180: "Ringing",
	181: "Call Is Being Forwarded",
	182: "Queued",
	183: "Session Progress",
	199: "Early Dialog Terminated",
	// 2xx—Successful Responses
	200: "OK",
	202: "Accepted",
	204: "No Notification",
	206: "Partial Content",
	// 3xx—Redirection Responses
	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Moved Temporarily",
	303: "See Other",
	304: "Not Modified",
	305: "Use Proxy",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	380: "Alternative Service",
	// 4xx—Client Failure Responses
	400: "Bad Request",
	401: "Unauthorized",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required",
	408: "Request Timeout",
	409: "Conflict",
	410: "Gone",
	411: "Length Required",
	412: "Conditional Request Failed",
	413: "Request Entity Too Large",
	414: "Request-URI Too Long",
	415: "Unsupported Media Type",
	416: "Unsupported URI Scheme",
	417: "Unknown Resource-Priority",
	418: "Duplicate Configuration",
	419: "Missing Configuration",
	420: "Bad Extension",
	421: "Extension Required",
	422: "Session Interval Too Small",
	423: "Interval Too Brief",
	424: "Bad Location Information",
	425: "Interval Too Long",
	428: "Use Identity Header",
	429: "Provide Referrer Identity",
	430: "Flow Failed",
	433: "Anonymity Disallowed",
	436: "Bad Identity-Info",
	437: "Unsupported Certificate",
	438: "Invalid Identity Header",
	439: "First Hop Lacks Outbound Support",
	470: "Consent Needed",
	480: "Temporarily Unavailable",
	481: "Call Leg/Transaction Does Not Exist",
	482: "Loop Detected",
	483: "Too Many Hops",
	484: "Address Incomplete",
	485: "Ambiguous",
	486: "Busy Here",
	487: "Request Terminated",
	488: "Not Acceptable Here",
	489: "Bad Event",
	491: "Request Pending",
	493: "Undecipherable",
	494: "Security Agreement Required",
	// 5xx—Server Failure Responses
	500: "Server Internal Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Server Time-out",
	505: "Version Not Supported",
	513: "Message Too Large",
	580: "Precondition Failure",
	586: "Server Media Pool Depleted",
	// 6xx—Global Failure Responses
	600: "Busy Everywhere",
	603: "Decline",
	604: "Does Not Exist Anywhere",
	606: "Not Acceptable",
}

const (
	AddXMLPIDFLO int = iota + 1
	AddINDATA
)

var BodyAddParts = map[int]string{AddXMLPIDFLO: "pidflo", AddINDATA: "indata"}
