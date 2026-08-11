package policy

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
)

var ErrNoCommittedGeneration = errors.New("no committed policy generation")

type Bank uint8

const (
	BankA Bank = iota
	BankB
)

type Generation struct {
	Revision uint64 `json:"revision"`
	Bank     Bank   `json:"bank"`
}

type MapEntry struct {
	Key   uint32
	Value []byte
}

type BankImage struct {
	Rules    []MapEntry
	Profiles []MapEntry
}

type RecoveredGeneration struct {
	Generation Generation `json:"generation"`
	Image      BankImage  `json:"image"`
}

// PolicyUpdateFailedRecord is emitted when a generation cannot be committed.
// Pointer fields distinguish an unknown generation from generation zero.
type PolicyUpdateFailedRecord struct {
	RecordType          string      `json:"record_type"`
	ActiveGeneration    *Generation `json:"active_generation,omitempty"`
	AttemptedGeneration *Generation `json:"attempted_generation,omitempty"`
	Error               string      `json:"error"`
}

type PolicyUpdateFailureReporter func(PolicyUpdateFailedRecord) error

// BankStore represents the two rule/profile map banks and their active
// selector. BeginUpdate must exclude every other update against the same
// backing store until the returned update is closed.
type BankStore interface {
	BeginUpdate(context.Context) (BankUpdate, error)
}

// BankUpdate is an exclusive update transaction. Activate must compare the
// active generation with expected and atomically switch to next only when they
// match. Returning an error must leave the active generation unchanged.
type BankUpdate interface {
	Active(context.Context) (Generation, error)
	Reset(context.Context, Bank) error
	PutRule(context.Context, Bank, MapEntry) error
	PutProfile(context.Context, Bank, MapEntry) error
	Read(context.Context, Bank) (BankImage, error)
	Activate(context.Context, Generation, Generation) error
	Close()
}

type GenerationUpdater struct {
	store           BankStore
	ruleCapacity    int
	profileCapacity int
	reportFailure   PolicyUpdateFailureReporter
}

func NewGenerationUpdater(store BankStore, ruleCapacity, profileCapacity int) (*GenerationUpdater, error) {
	return newGenerationUpdater(store, ruleCapacity, profileCapacity, nil)
}

func NewReportingGenerationUpdater(store BankStore, ruleCapacity, profileCapacity int, reporter PolicyUpdateFailureReporter) (*GenerationUpdater, error) {
	if reporter == nil {
		return nil, errors.New("policy update failure reporter is required")
	}
	return newGenerationUpdater(store, ruleCapacity, profileCapacity, reporter)
}

func newGenerationUpdater(store BankStore, ruleCapacity, profileCapacity int, reporter PolicyUpdateFailureReporter) (*GenerationUpdater, error) {
	if store == nil {
		return nil, errors.New("bank store is required")
	}
	if ruleCapacity <= 0 || profileCapacity <= 0 {
		return nil, errors.New("rule and profile capacities must be positive")
	}
	return &GenerationUpdater{
		store:           store,
		ruleCapacity:    ruleCapacity,
		profileCapacity: profileCapacity,
		reportFailure:   reporter,
	}, nil
}

// Commit writes a complete image to the inactive bank, verifies an exact
// readback, and only then switches the active generation.
func (updater *GenerationUpdater) Commit(ctx context.Context, image BankImage) (committed Generation, resultErr error) {
	var activeGeneration, attemptedGeneration *Generation
	defer func() {
		if resultErr == nil || updater == nil || updater.reportFailure == nil {
			return
		}
		record := PolicyUpdateFailedRecord{
			RecordType:          "policy_update_failed",
			ActiveGeneration:    activeGeneration,
			AttemptedGeneration: attemptedGeneration,
			Error:               resultErr.Error(),
		}
		if err := updater.reportFailure(record); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("report policy update failure: %w", err))
		}
	}()
	if updater == nil {
		return Generation{}, errors.New("generation updater is required")
	}
	if ctx == nil {
		return Generation{}, errors.New("generation update context is required")
	}
	image = cloneBankImage(image)
	if err := validateBankImage(image, updater.ruleCapacity, updater.profileCapacity); err != nil {
		return Generation{}, err
	}
	update, err := updater.store.BeginUpdate(ctx)
	if err != nil {
		return Generation{}, fmt.Errorf("begin bank update: %w", err)
	}
	defer update.Close()

	active, err := update.Active(ctx)
	if err != nil {
		return Generation{}, fmt.Errorf("read active generation: %w", err)
	}
	if active.Bank != BankA && active.Bank != BankB {
		return Generation{}, fmt.Errorf("active bank %d is invalid", active.Bank)
	}
	activeCopy := active
	activeGeneration = &activeCopy
	if active.Revision == math.MaxUint64 {
		return Generation{}, errors.New("generation revision exhausted")
	}
	inactive := otherBank(active.Bank)
	next := Generation{Revision: active.Revision + 1, Bank: inactive}
	nextCopy := next
	attemptedGeneration = &nextCopy
	if err := update.Reset(ctx, inactive); err != nil {
		return Generation{}, fmt.Errorf("reset inactive bank %d: %w", inactive, err)
	}
	for _, entry := range image.Rules {
		if err := ctx.Err(); err != nil {
			return Generation{}, fmt.Errorf("write inactive rule bank: %w", err)
		}
		if err := update.PutRule(ctx, inactive, entry); err != nil {
			return Generation{}, fmt.Errorf("write rule %d to inactive bank: %w", entry.Key, err)
		}
	}
	for _, entry := range image.Profiles {
		if err := ctx.Err(); err != nil {
			return Generation{}, fmt.Errorf("write inactive profile bank: %w", err)
		}
		if err := update.PutProfile(ctx, inactive, entry); err != nil {
			return Generation{}, fmt.Errorf("write profile %d to inactive bank: %w", entry.Key, err)
		}
	}
	readback, err := update.Read(ctx, inactive)
	if err != nil {
		return Generation{}, fmt.Errorf("read back inactive bank: %w", err)
	}
	if err := verifyBankImage(image, readback); err != nil {
		return Generation{}, fmt.Errorf("verify inactive bank: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Generation{}, fmt.Errorf("activate verified generation: %w", err)
	}
	if err := update.Activate(ctx, active, next); err != nil {
		return Generation{}, fmt.Errorf("activate generation %d: %w", next.Revision, err)
	}
	return next, nil
}

// Recover returns the only committed active image and clears the inactive
// staging bank. It rejects generation zero instead of guessing whether a
// partial image is authoritative.
func (updater *GenerationUpdater) Recover(ctx context.Context) (RecoveredGeneration, error) {
	if updater == nil {
		return RecoveredGeneration{}, errors.New("generation updater is required")
	}
	if ctx == nil {
		return RecoveredGeneration{}, errors.New("generation recovery context is required")
	}
	update, err := updater.store.BeginUpdate(ctx)
	if err != nil {
		return RecoveredGeneration{}, fmt.Errorf("begin generation recovery: %w", err)
	}
	defer update.Close()

	active, err := update.Active(ctx)
	if err != nil {
		return RecoveredGeneration{}, fmt.Errorf("read active generation during recovery: %w", err)
	}
	if active.Bank != BankA && active.Bank != BankB {
		return RecoveredGeneration{}, fmt.Errorf("active bank %d is invalid", active.Bank)
	}
	if active.Revision == 0 {
		return RecoveredGeneration{}, ErrNoCommittedGeneration
	}
	image, err := update.Read(ctx, active.Bank)
	if err != nil {
		return RecoveredGeneration{}, fmt.Errorf("read active bank %d during recovery: %w", active.Bank, err)
	}
	if err := validateBankImage(image, updater.ruleCapacity, updater.profileCapacity); err != nil {
		return RecoveredGeneration{}, fmt.Errorf("validate active generation %d during recovery: %w", active.Revision, err)
	}
	if err := ctx.Err(); err != nil {
		return RecoveredGeneration{}, fmt.Errorf("clear inactive staging bank during recovery: %w", err)
	}
	if err := update.Reset(ctx, otherBank(active.Bank)); err != nil {
		return RecoveredGeneration{}, fmt.Errorf("clear inactive staging bank during recovery: %w", err)
	}
	return RecoveredGeneration{Generation: active, Image: cloneBankImage(image)}, nil
}

func otherBank(bank Bank) Bank {
	if bank == BankA {
		return BankB
	}
	return BankA
}

func validateBankImage(image BankImage, ruleCapacity, profileCapacity int) error {
	if len(image.Rules) > ruleCapacity {
		return fmt.Errorf("rule image has %d entries; capacity is %d", len(image.Rules), ruleCapacity)
	}
	if len(image.Profiles) > profileCapacity {
		return fmt.Errorf("profile image has %d entries; capacity is %d", len(image.Profiles), profileCapacity)
	}
	if err := validateMapEntries("rule", image.Rules); err != nil {
		return err
	}
	return validateMapEntries("profile", image.Profiles)
}

func validateMapEntries(kind string, entries []MapEntry) error {
	seen := make(map[uint32]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Key == 0 {
			return fmt.Errorf("%s key 0 is reserved", kind)
		}
		if len(entry.Value) == 0 {
			return fmt.Errorf("%s %d has an empty value", kind, entry.Key)
		}
		if _, exists := seen[entry.Key]; exists {
			return fmt.Errorf("%s key %d is duplicated", kind, entry.Key)
		}
		seen[entry.Key] = struct{}{}
	}
	return nil
}

func verifyBankImage(expected, actual BankImage) error {
	if err := validateBankImage(actual, len(expected.Rules), len(expected.Profiles)); err != nil {
		return fmt.Errorf("invalid readback: %w", err)
	}
	if !equalEntries(expected.Rules, actual.Rules) {
		return errors.New("rule readback differs from the requested image")
	}
	if !equalEntries(expected.Profiles, actual.Profiles) {
		return errors.New("profile readback differs from the requested image")
	}
	return nil
}

func equalEntries(first, second []MapEntry) bool {
	first = slices.Clone(first)
	second = slices.Clone(second)
	slices.SortFunc(first, func(a, b MapEntry) int { return cmp.Compare(a.Key, b.Key) })
	slices.SortFunc(second, func(a, b MapEntry) int { return cmp.Compare(a.Key, b.Key) })
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].Key != second[index].Key || !bytes.Equal(first[index].Value, second[index].Value) {
			return false
		}
	}
	return true
}

func cloneBankImage(image BankImage) BankImage {
	return BankImage{
		Rules:    cloneEntries(image.Rules),
		Profiles: cloneEntries(image.Profiles),
	}
}

func cloneEntries(entries []MapEntry) []MapEntry {
	cloned := make([]MapEntry, len(entries))
	for index, entry := range entries {
		cloned[index] = MapEntry{Key: entry.Key, Value: bytes.Clone(entry.Value)}
	}
	return cloned
}
