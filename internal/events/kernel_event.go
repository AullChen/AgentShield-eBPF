package events

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"
)

var (
	ErrMalformedKernelEvent = errors.New("malformed kernel event")
	ErrUnsupportedSchema    = errors.New("unsupported kernel event schema")
)

const (
	WireSchemaVersion uint16 = 2
	JSONSchemaVersion uint16 = 2
	// SchemaVersion is kept as the wire-schema name used by the decoder and BPF ABI.
	SchemaVersion = WireSchemaVersion

	EventTypeUnspecified uint16 = 0
	EventTypeExecAttempt uint16 = 1
	EventTypeFileOpen    uint16 = 2
	EventTypeNetConnect  uint16 = 3
	EventTypePolicyHit   uint16 = 4
	EventTypeBlockResult uint16 = 5
	EventTypeDropNotice  uint16 = 6
	EventTypeSelfDiag    uint16 = 7

	ActionAudit   uint16 = 0
	ActionAlert   uint16 = 1
	ActionBlock   uint16 = 2
	ActionContain uint16 = 3
	// ActionKill is a deprecated source alias. JSON/wire v2 names value 3 "contain".
	ActionKill = ActionContain

	ActionResultNone    uint16 = 0
	ActionResultAllowed uint16 = 1
	ActionResultBlocked uint16 = 2
	ActionResultKilled  uint16 = 3
	ActionResultFailed  uint16 = 4
	// ActionResultFallback is deprecated. Use FlagFallback with killed/failed.
	ActionResultFallback uint16 = 5

	FlagTruncated        uint32 = 1 << 0
	FlagFallback         uint32 = 1 << 1
	FlagFieldUnavailable uint32 = 1 << 2

	AddressFamilyIPv4 uint16 = 2
	AddressFamilyIPv6 uint16 = 10
	ProtocolTCP       uint8  = 6

	execExecutableLength = 128
	execArgumentCount    = 4
	execArgumentLength   = 32
)

type KernelEvent struct {
	JSONSchemaVersion uint16            `json:"schema_version"`
	SchemaVersion     uint16            `json:"wire_schema_version"`
	EventType         uint16            `json:"event_type"`
	EventTypeName     string            `json:"event_type_name"`
	Action            uint16            `json:"action"`
	ActionName        string            `json:"action_name"`
	ActionResult      uint16            `json:"action_result"`
	ActionResultName  string            `json:"action_result_name"`
	TimestampNS       uint64            `json:"timestamp_ns,string"`
	CgroupID          uint64            `json:"cgroup_id,string"`
	PID               uint32            `json:"pid"`
	TGID              uint32            `json:"tgid"`
	PPID              uint32            `json:"ppid"`
	UID               uint32            `json:"uid"`
	ProfileID         uint32            `json:"profile_id"`
	PolicyID          uint32            `json:"policy_id"`
	RuleID            uint32            `json:"rule_id"`
	Flags             uint32            `json:"flags"`
	SyscallFlags      uint32            `json:"syscall_flags"`
	Comm              string            `json:"comm"`
	Data              string            `json:"data"`
	Argv              []string          `json:"argv,omitempty"`
	CapturedArgc      uint32            `json:"captured_argc,omitempty"`
	DestinationIP     string            `json:"dst_ip,omitempty"`
	DestinationPort   uint16            `json:"dst_port,omitempty"`
	AddressFamily     uint16            `json:"family,omitempty"`
	AddressFamilyName string            `json:"family_name,omitempty"`
	Protocol          uint8             `json:"protocol,omitempty"`
	ProtocolName      string            `json:"protocol_name,omitempty"`
	Truncated         bool              `json:"truncated"`
	FieldsUnavailable bool              `json:"fields_unavailable"`
	RawEncoding       map[string]string `json:"raw_encoding,omitempty"`
}

type rawKernelEventV2 struct {
	SchemaVersion       uint16
	EventType           uint16
	Action              uint16
	ActionResult        uint16
	TimestampNS         uint64
	CgroupID            uint64
	PID                 uint32
	TGID                uint32
	PPID                uint32
	UID                 uint32
	ProfileID           uint32
	PolicyID            uint32
	RuleID              uint32
	Flags               uint32
	SyscallFlags        uint32
	CapturedArgcPlusOne uint32
	Comm                [16]byte
	Data                [256]byte
}

type rawNetworkPayloadV2 struct {
	DestinationAddress [16]byte
	DestinationPort    uint16
	AddressFamily      uint16
	Protocol           uint8
	Reserved           [3]byte
}

func KernelEventV2Size() int {
	return binary.Size(rawKernelEventV2{})
}

func DecodeKernelEvent(sample []byte) (KernelEvent, error) {
	if len(sample) < 2 {
		return KernelEvent{}, fmt.Errorf("%w: sample is %d bytes, need at least 2 for schema version", ErrMalformedKernelEvent, len(sample))
	}

	schemaVersion := binary.LittleEndian.Uint16(sample[:2])
	if schemaVersion != SchemaVersion {
		return KernelEvent{}, fmt.Errorf("%w: got %d want %d", ErrUnsupportedSchema, schemaVersion, SchemaVersion)
	}

	var raw rawKernelEventV2
	if len(sample) != KernelEventV2Size() {
		return KernelEvent{}, fmt.Errorf("%w: invalid size: got %d want %d", ErrMalformedKernelEvent, len(sample), KernelEventV2Size())
	}
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return KernelEvent{}, fmt.Errorf("%w: decode: %v", ErrMalformedKernelEvent, err)
	}

	event := KernelEvent{
		JSONSchemaVersion: JSONSchemaVersion,
		SchemaVersion:     raw.SchemaVersion,
		EventType:         raw.EventType,
		EventTypeName:     EventTypeName(raw.EventType),
		Action:            raw.Action,
		ActionName:        ActionName(raw.Action),
		ActionResult:      raw.ActionResult,
		ActionResultName:  ActionResultName(raw.ActionResult),
		TimestampNS:       raw.TimestampNS,
		CgroupID:          raw.CgroupID,
		PID:               raw.PID,
		TGID:              raw.TGID,
		PPID:              raw.PPID,
		UID:               raw.UID,
		ProfileID:         raw.ProfileID,
		PolicyID:          raw.PolicyID,
		RuleID:            raw.RuleID,
		Flags:             raw.Flags,
		SyscallFlags:      raw.SyscallFlags,
		Truncated:         raw.Flags&FlagTruncated != 0,
		FieldsUnavailable: raw.Flags&FlagFieldUnavailable != 0,
	}
	event.Comm = decodeEventCString(&event, "comm", raw.Comm[:])
	switch raw.EventType {
	case EventTypeExecAttempt:
		event.Data = decodeEventCString(&event, "data", raw.Data[:execExecutableLength])
		if raw.CapturedArgcPlusOne == 0 {
			return KernelEvent{}, fmt.Errorf("%w: exec event is missing captured argc", ErrMalformedKernelEvent)
		}
		if raw.CapturedArgcPlusOne > uint32(execArgumentCount+1) {
			return KernelEvent{}, fmt.Errorf("%w: captured argc is %d, maximum is %d", ErrMalformedKernelEvent, raw.CapturedArgcPlusOne-1, execArgumentCount)
		}
		capturedArgc := int(raw.CapturedArgcPlusOne - 1)
		for i := 0; i < execArgumentCount; i++ {
			start := execExecutableLength + i*execArgumentLength
			arg := decodeEventCString(&event, fmt.Sprintf("argv[%d]", i), raw.Data[start:start+execArgumentLength])
			if i >= capturedArgc {
				break
			}
			event.Argv = append(event.Argv, arg)
		}
		event.CapturedArgc = uint32(len(event.Argv))
	case EventTypeNetConnect:
		if err := decodeNetworkPayload(&event, raw.Data[:]); err != nil {
			return KernelEvent{}, err
		}
	default:
		event.Data = decodeEventCString(&event, "data", raw.Data[:])
	}

	return event, nil
}

func decodeNetworkPayload(event *KernelEvent, data []byte) error {
	var payload rawNetworkPayloadV2
	size := binary.Size(payload)
	if len(data) < size {
		return fmt.Errorf("%w: network payload is %d bytes, need %d", ErrMalformedKernelEvent, len(data), size)
	}
	if err := binary.Read(bytes.NewReader(data[:size]), binary.LittleEndian, &payload); err != nil {
		return fmt.Errorf("%w: decode network payload: %v", ErrMalformedKernelEvent, err)
	}

	var address netip.Addr
	switch payload.AddressFamily {
	case AddressFamilyIPv4:
		address = netip.AddrFrom4([4]byte(payload.DestinationAddress[:4]))
	case AddressFamilyIPv6:
		address = netip.AddrFrom16(payload.DestinationAddress)
	default:
		return fmt.Errorf("%w: unsupported network address family %d", ErrMalformedKernelEvent, payload.AddressFamily)
	}
	if payload.Protocol != ProtocolTCP {
		return fmt.Errorf("%w: unsupported network protocol %d", ErrMalformedKernelEvent, payload.Protocol)
	}

	event.DestinationIP = address.String()
	event.DestinationPort = payload.DestinationPort
	event.AddressFamily = payload.AddressFamily
	event.AddressFamilyName = AddressFamilyName(payload.AddressFamily)
	event.Protocol = payload.Protocol
	event.ProtocolName = ProtocolName(payload.Protocol)
	return nil
}

func CleanCString(value []byte) string {
	return string(trimCString(value))
}

func decodeEventCString(event *KernelEvent, field string, value []byte) string {
	cleaned, encoding := cleanCString(value)
	if encoding != "" {
		if event.RawEncoding == nil {
			event.RawEncoding = make(map[string]string)
		}
		event.RawEncoding[field] = encoding
	}
	return cleaned
}

func cleanCString(value []byte) (string, string) {
	value = trimCString(value)
	if utf8.Valid(value) {
		return string(value), ""
	}
	return base64.StdEncoding.EncodeToString(value), "base64"
}

func trimCString(value []byte) []byte {
	if idx := bytes.IndexByte(value, 0); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func EventTypeName(eventType uint16) string {
	switch eventType {
	case EventTypeExecAttempt:
		return "exec_attempt"
	case EventTypeFileOpen:
		return "file_open"
	case EventTypeNetConnect:
		return "net_connect"
	case EventTypePolicyHit:
		return "policy_hit"
	case EventTypeBlockResult:
		return "block_result"
	case EventTypeDropNotice:
		return "drop_notice"
	case EventTypeSelfDiag:
		return "self_diag"
	case EventTypeUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

func ActionName(action uint16) string {
	switch action {
	case ActionAudit:
		return "audit"
	case ActionAlert:
		return "alert"
	case ActionBlock:
		return "block"
	case ActionContain:
		return "contain"
	default:
		return "unknown"
	}
}

func ActionResultName(result uint16) string {
	switch result {
	case ActionResultNone:
		return "none"
	case ActionResultAllowed:
		return "allowed"
	case ActionResultBlocked:
		return "blocked"
	case ActionResultKilled:
		return "killed"
	case ActionResultFailed:
		return "failed"
	case ActionResultFallback:
		return "fallback"
	default:
		return "unknown"
	}
}

func AddressFamilyName(family uint16) string {
	switch family {
	case AddressFamilyIPv4:
		return "ipv4"
	case AddressFamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

func ProtocolName(protocol uint8) string {
	if protocol == ProtocolTCP {
		return "tcp"
	}
	return "unknown"
}
