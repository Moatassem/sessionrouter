package cdr

import "fmt"

type (
	Field string

	Instance struct {
		data map[Field]string
	}
)

const (
	CallID                 Field = "callId"                 // Unique identifier for the call
	CallerNumber           Field = "callerNumber"           // Original Caller phone number
	CalledNumber           Field = "calledNumber"           // Original Called phone number
	TranslatedCallerNumber Field = "translatedCallerNumber" // Translated caller phone number
	TranslatedCalledNumber Field = "translatedCalledNumber" // Translated called phone number
	CallStartTime          Field = "callStartTime"          // Call start timestamp
	CallEndTime            Field = "callEndTime"            // Call end timestamp
	DurationSeconds        Field = "durationSeconds"        // Call duration in seconds
	CallStatus             Field = "callStatus"             // Status (Completed, Missed, Failed, etc.)
	CallDirection          Field = "callDirection"          // Incoming or Outgoing
	CallerLocation         Field = "callerLocation"         // Caller’s location (if available)
	CalleeLocation         Field = "calleeLocation"         // Receiver’s location (if available)
	CallerIP               Field = "callerIp"               // IP address of the caller (VoIP calls)
	CalleeIP               Field = "calleeIp"               // IP address of the callee (VoIP calls)
	CodecUsed              Field = "codecUsed"              // Audio codec used for the call
	NetworkProvider        Field = "networkProvider"        // Telecom provider for the caller
	Cost                   Field = "cost"                   // Cost of the call
	Currency               Field = "currency"               // Currency of the cost
	CallType               Field = "callType"               // Type of call (Mobile, Landline, VoIP)
	CallRecordingURL       Field = "callRecordingUrl"       // URL for call recording (if applicable)
	TerminationCause       Field = "terminationCause"       // Reason for call termination
	RedirectionStatus      Field = "redirectionStatus"      // Indicates if redirection occurred
	RoamingStatus          Field = "roamingStatus"          // Indicates if caller was roaming
)

func getAllFields() []Field {
	return []Field{
		CallID,
		CallerNumber,
		CalledNumber,
		TranslatedCallerNumber,
		TranslatedCalledNumber,
		CallStartTime,
		CallEndTime,
		DurationSeconds,
		CallStatus,
		CallDirection,
		CallerLocation,
		CalleeLocation,
		CallerIP,
		CalleeIP,
		CodecUsed,
		NetworkProvider,
		Cost,
		Currency,
		CallType,
		CallRecordingURL,
		TerminationCause,
		RedirectionStatus,
		RoamingStatus,
	}
}

func (f Field) String() string {
	return string(f)
}

func CastStringSlice[T fmt.Stringer](input []T) []string {
	output := make([]string, len(input))
	for i, v := range input {
		output[i] = v.String()
	}
	return output
}

func New() *Instance {
	return &Instance{
		data: make(map[Field]string, len(stringfields)),
	}
}

func (inst *Instance) Set(field Field, value string) {
	inst.data[field] = value
}

func (inst *Instance) Flush() {
	pipe <- inst.data
}
