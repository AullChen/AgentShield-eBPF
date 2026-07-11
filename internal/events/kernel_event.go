package events

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
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

	FlagTruncated uint32 = 1 << 0
	FlagFallback  uint32 = 1 << 1

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
	Truncated         bool              `json:"truncated"`
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
	}
	event.Comm = decodeEventCString(&event, "comm", raw.Comm[:])
	if raw.EventType == EventTypeExecAttempt {
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
	} else {
		event.Data = decodeEventCString(&event, "data", raw.Data[:])
	}

	return event, nil
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
