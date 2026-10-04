package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/agentshield/agentshield-ebpf/internal/evidence"
	"github.com/agentshield/agentshield-ebpf/internal/inspection"
	"github.com/agentshield/agentshield-ebpf/internal/store"
	"github.com/agentshield/agentshield-ebpf/internal/stream"
)

type InspectionOptions struct {
	Registration *RegistrationHandler
	Database     *store.SQLite
	Hub          *stream.Hub
	Redactor     store.Redactor
	OwnerRead    func(string) ([]byte, error)
}

func NewInspectionChecker(cfg inspection.Config, options InspectionOptions) (*inspection.Checker, error) {
	if options.Registration == nil || options.Database == nil || options.Hub == nil {
		return nil, errors.New("inspection requires registered identity and evidence storage")
	}
	registration := options.Registration
	return inspection.New(cfg, inspection.Options{
		Authenticate: func(token string) (string, error) {
			run, err := registration.VerifyIngestToken(token)
			return run.RunID, err
		},
		ActiveRun: func(id string) bool {
			registration.store.mu.RLock()
			defer registration.store.mu.RUnlock()
			run, exists := registration.store.runs[id]
			_, terminating := registration.store.terminating[id]
			now := time.Now()
			return exists && !terminating && run.Status == "active" && now.Before(run.RunExpiry) && now.Before(run.TokenExpiry)
		},
		Audit: func(decision inspection.Decision) error {
			run, exists := registration.store.Get(decision.RunID)
			if !exists {
				return errors.New("inspection identity unavailable")
			}
			receipt, err := captureCheckpointReceiptTime()
			if err != nil {
				return err
			}
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return err
			}
			result, severity := "rejected", "warning"
			if decision.Checked {
				result, severity = "checked", "info"
			}
			if decision.Reason == "approval_granted" {
				result, severity = "approval_granted", "info"
			}
			event := evidence.Event{ID: "inspection-" + hex.EncodeToString(nonce[:]), Type: "local_inspection", Source: evidence.PolicyDecision,
				ServerMonotonicNS: receipt.MonotonicNS, ServerUnixNS: receipt.UnixNS,
				Summary:  fmt.Sprintf("local-only %s route=%s sha256=%s; not forwarded or executed", decision.Reason, decision.RouteID, decision.SHA256),
				Decision: &evidence.Decision{PolicyID: "local-inspection", RuleID: decision.RouteID, RequestedAction: "check", FinalDecision: result, Enforced: false, Mechanism: "local_preflight_only"}}
			if _, err := evidence.Build(run.RunID, []evidence.Event{event}); err != nil {
				return err
			}
			payload, err := json.Marshal(event)
			if err != nil {
				return err
			}
			record, err := options.Redactor.Apply(store.Record{ID: event.ID, RecordType: event.Type, RunID: run.RunID, Source: store.SourcePolicyDecision,
				ServerMonotonicNS: receipt.MonotonicNS, ServerUnixNS: receipt.UnixNS, InstanceID: run.InstanceID, ScopeCookie: run.ScopeCookie, Summary: event.Summary, Severity: severity, Payload: payload})
			if err != nil {
				return err
			}
			// Unlike asynchronous capture queues, a successful local check must
			// not be returned until its minimal evidence record is stored.
			if err := options.Database.AppendBatch([]store.Record{record}); err != nil {
				return errors.New("inspection audit storage unavailable")
			}
			if err := json.Unmarshal(record.Payload, &event); err != nil {
				return err
			}
			timeline, err := evidence.Build(run.RunID, []evidence.Event{event})
			if err != nil {
				return err
			}
			streamPayload, _ := json.Marshal(timeline.Items[0])
			// Persistence is authoritative; a live viewer failure does not erase
			// the stored check and never implies external execution occurred.
			_, _ = options.Hub.Publish(stream.Event{ID: event.ID, Type: event.Type, Source: string(event.Source), RunID: run.RunID, Severity: severity, EventType: event.Type, ServerMonotonicNS: receipt.MonotonicNS, ServerUnixNS: receipt.UnixNS, Audit: true, Payload: streamPayload})
			return nil
		},
	}, options.OwnerRead)
}
