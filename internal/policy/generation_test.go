package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGenerationUpdaterCommitsAndAlternatesBanks(t *testing.T) {
	store := newMemoryBankStore()
	updater, err := NewGenerationUpdater(store, 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater: %v", err)
	}
	image := testBankImage()

	first, err := updater.Commit(context.Background(), image)
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if first != (Generation{Revision: 1, Bank: BankB}) {
		t.Fatalf("first generation = %+v", first)
	}
	image.Rules[0].Value[0] = 99
	if store.banks[BankB].Rules[0].Value[0] == 99 {
		t.Fatal("committed bank retained caller-owned bytes")
	}

	second, err := updater.Commit(context.Background(), testBankImage())
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	if second != (Generation{Revision: 2, Bank: BankA}) {
		t.Fatalf("second generation = %+v", second)
	}
}

func TestGenerationUpdaterFailureNeverSwitchesActiveBank(t *testing.T) {
	for _, step := range []string{"active", "reset", "rule", "profile", "read", "activate"} {
		t.Run(step, func(t *testing.T) {
			store := newMemoryBankStore()
			store.failStep = step
			updater, err := NewGenerationUpdater(store, 4, 2)
			if err != nil {
				t.Fatalf("NewGenerationUpdater: %v", err)
			}
			_, err = updater.Commit(context.Background(), testBankImage())
			if err == nil {
				t.Fatal("Commit succeeded despite injected failure")
			}
			if store.active != (Generation{Revision: 0, Bank: BankA}) {
				t.Fatalf("active generation changed after %s failure: %+v", step, store.active)
			}
		})
	}
}

func TestGenerationUpdaterRejectsReadbackMismatch(t *testing.T) {
	store := newMemoryBankStore()
	store.corruptReadback = true
	updater, err := NewGenerationUpdater(store, 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater: %v", err)
	}
	_, err = updater.Commit(context.Background(), testBankImage())
	if err == nil || !strings.Contains(err.Error(), "readback differs") {
		t.Fatalf("Commit error = %v", err)
	}
	if store.active.Bank != BankA {
		t.Fatalf("active bank changed: %+v", store.active)
	}
}

func TestGenerationUpdaterValidatesImageBeforeWriting(t *testing.T) {
	store := newMemoryBankStore()
	updater, err := NewGenerationUpdater(store, 1, 1)
	if err != nil {
		t.Fatalf("NewGenerationUpdater: %v", err)
	}
	tests := []BankImage{
		{Rules: []MapEntry{{Key: 0, Value: []byte{1}}}},
		{Rules: []MapEntry{{Key: 1, Value: nil}}},
		{Rules: []MapEntry{{Key: 1, Value: []byte{1}}, {Key: 2, Value: []byte{2}}}},
		{Profiles: []MapEntry{{Key: 1, Value: []byte{1}}, {Key: 1, Value: []byte{2}}}},
	}
	for _, image := range tests {
		if _, err := updater.Commit(context.Background(), image); err == nil {
			t.Fatalf("invalid image accepted: %+v", image)
		}
	}
	if store.calls != 0 {
		t.Fatalf("store called %d times for invalid images", store.calls)
	}
}

func TestGenerationUpdaterHonorsCancellationBeforeActivation(t *testing.T) {
	store := newMemoryBankStore()
	store.cancelAfterRule = true
	ctx, cancel := context.WithCancel(context.Background())
	store.cancel = cancel
	updater, err := NewGenerationUpdater(store, 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater: %v", err)
	}
	_, err = updater.Commit(ctx, testBankImage())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Commit error = %v, want context.Canceled", err)
	}
	if store.active.Bank != BankA {
		t.Fatalf("active bank changed: %+v", store.active)
	}
}

func testBankImage() BankImage {
	return BankImage{
		Rules: []MapEntry{
			{Key: 1, Value: []byte{1, 2}},
			{Key: 2, Value: []byte{3, 4}},
		},
		Profiles: []MapEntry{{Key: 7, Value: []byte{5, 6}}},
	}
}

type memoryBankStore struct {
	active          Generation
	banks           map[Bank]BankImage
	failStep        string
	corruptReadback bool
	cancelAfterRule bool
	cancel          context.CancelFunc
	calls           int
}

func newMemoryBankStore() *memoryBankStore {
	return &memoryBankStore{
		active: Generation{Revision: 0, Bank: BankA},
		banks:  map[Bank]BankImage{BankA: {}, BankB: {}},
	}
}

func (store *memoryBankStore) fail(step string) error {
	store.calls++
	if store.failStep == step {
		store.failStep = ""
		return errors.New("injected " + step + " failure")
	}
	return nil
}

func (store *memoryBankStore) Active(context.Context) (Generation, error) {
	if err := store.fail("active"); err != nil {
		return Generation{}, err
	}
	return store.active, nil
}

func (store *memoryBankStore) Reset(_ context.Context, bank Bank) error {
	if err := store.fail("reset"); err != nil {
		return err
	}
	store.banks[bank] = BankImage{}
	return nil
}

func (store *memoryBankStore) PutRule(_ context.Context, bank Bank, entry MapEntry) error {
	if err := store.fail("rule"); err != nil {
		return err
	}
	image := store.banks[bank]
	image.Rules = append(image.Rules, MapEntry{Key: entry.Key, Value: append([]byte(nil), entry.Value...)})
	store.banks[bank] = image
	if store.cancelAfterRule {
		store.cancel()
	}
	return nil
}

func (store *memoryBankStore) PutProfile(_ context.Context, bank Bank, entry MapEntry) error {
	if err := store.fail("profile"); err != nil {
		return err
	}
	image := store.banks[bank]
	image.Profiles = append(image.Profiles, MapEntry{Key: entry.Key, Value: append([]byte(nil), entry.Value...)})
	store.banks[bank] = image
	return nil
}

func (store *memoryBankStore) Read(_ context.Context, bank Bank) (BankImage, error) {
	if err := store.fail("read"); err != nil {
		return BankImage{}, err
	}
	image := cloneBankImage(store.banks[bank])
	if store.corruptReadback {
		image.Rules[0].Value[0]++
	}
	return image, nil
}

func (store *memoryBankStore) Activate(_ context.Context, generation Generation) error {
	if err := store.fail("activate"); err != nil {
		return err
	}
	store.active = generation
	return nil
}
