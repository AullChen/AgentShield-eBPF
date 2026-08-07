package policy

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
)

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

// BankStore represents the two rule/profile map banks and their active
// selector. Activate must be atomic: returning an error must leave the active
// generation unchanged.
type BankStore interface {
	Active(context.Context) (Generation, error)
	Reset(context.Context, Bank) error
	PutRule(context.Context, Bank, MapEntry) error
	PutProfile(context.Context, Bank, MapEntry) error
	Read(context.Context, Bank) (BankImage, error)
	Activate(context.Context, Generation) error
}

type GenerationUpdater struct {
	store           BankStore
	ruleCapacity    int
	profileCapacity int
	mu              sync.Mutex
}

func NewGenerationUpdater(store BankStore, ruleCapacity, profileCapacity int) (*GenerationUpdater, error) {
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
	}, nil
}

// Commit writes a complete image to the inactive bank, verifies an exact
// readback, and only then switches the active generation.
func (updater *GenerationUpdater) Commit(ctx context.Context, image BankImage) (Generation, error) {
	updater.mu.Lock()
	defer updater.mu.Unlock()

	image = cloneBankImage(image)
	if err := validateBankImage(image, updater.ruleCapacity, updater.profileCapacity); err != nil {
		return Generation{}, err
	}
	active, err := updater.store.Active(ctx)
	if err != nil {
		return Generation{}, fmt.Errorf("read active generation: %w", err)
	}
	if active.Bank != BankA && active.Bank != BankB {
		return Generation{}, fmt.Errorf("active bank %d is invalid", active.Bank)
	}
	if active.Revision == math.MaxUint64 {
		return Generation{}, errors.New("generation revision exhausted")
	}
	inactive := BankA
	if active.Bank == BankA {
		inactive = BankB
	}
	if err := updater.store.Reset(ctx, inactive); err != nil {
		return Generation{}, fmt.Errorf("reset inactive bank %d: %w", inactive, err)
	}
	for _, entry := range image.Rules {
		if err := ctx.Err(); err != nil {
			return Generation{}, fmt.Errorf("write inactive rule bank: %w", err)
		}
		if err := updater.store.PutRule(ctx, inactive, entry); err != nil {
			return Generation{}, fmt.Errorf("write rule %d to inactive bank: %w", entry.Key, err)
		}
	}
	for _, entry := range image.Profiles {
		if err := ctx.Err(); err != nil {
			return Generation{}, fmt.Errorf("write inactive profile bank: %w", err)
		}
		if err := updater.store.PutProfile(ctx, inactive, entry); err != nil {
			return Generation{}, fmt.Errorf("write profile %d to inactive bank: %w", entry.Key, err)
		}
	}
	readback, err := updater.store.Read(ctx, inactive)
	if err != nil {
		return Generation{}, fmt.Errorf("read back inactive bank: %w", err)
	}
	if err := verifyBankImage(image, readback); err != nil {
		return Generation{}, fmt.Errorf("verify inactive bank: %w", err)
	}
	next := Generation{Revision: active.Revision + 1, Bank: inactive}
	if err := updater.store.Activate(ctx, next); err != nil {
		return Generation{}, fmt.Errorf("activate generation %d: %w", next.Revision, err)
	}
	return next, nil
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
