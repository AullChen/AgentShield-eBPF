package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
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
	for _, step := range []string{"begin", "active", "reset", "rule", "profile", "read", "activate"} {
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

func TestGenerationUpdaterHonorsCancellationAfterReadback(t *testing.T) {
	store := newMemoryBankStore()
	store.cancelAfterRead = true
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
	if store.active != (Generation{Revision: 0, Bank: BankA}) {
		t.Fatalf("active generation changed after readback cancellation: %+v", store.active)
	}
}

func TestGenerationUpdatersSerializeOnSharedStore(t *testing.T) {
	store := newMemoryBankStore()
	first, err := NewGenerationUpdater(store, 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater(first): %v", err)
	}
	second, err := NewGenerationUpdater(store, 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater(second): %v", err)
	}

	type result struct {
		generation Generation
		value      byte
		err        error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for index, updater := range []*GenerationUpdater{first, second} {
		value := byte(index + 10)
		go func() {
			<-start
			image := testBankImage()
			image.Rules[0].Value[0] = value
			generation, commitErr := updater.Commit(context.Background(), image)
			results <- result{generation: generation, value: value, err: commitErr}
		}()
	}
	close(start)

	valuesByRevision := make(map[uint64]byte, 2)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("Commit: %v", result.err)
		}
		valuesByRevision[result.generation.Revision] = result.value
	}
	if len(valuesByRevision) != 2 {
		t.Fatalf("committed revisions = %v, want distinct revisions 1 and 2", valuesByRevision)
	}
	if store.active.Revision != 2 {
		t.Fatalf("active generation = %+v, want revision 2", store.active)
	}
	activeImage := store.banks[store.active.Bank]
	if got, want := activeImage.Rules[0].Value[0], valuesByRevision[2]; got != want {
		t.Fatalf("active rule value = %d, want revision 2 value %d", got, want)
	}
}

func TestGenerationUpdaterReportsFailedAttemptWithoutChangingActive(t *testing.T) {
	store := newMemoryBankStore()
	var failures []PolicyUpdateFailedRecord
	updater, err := NewReportingGenerationUpdater(store, 4, 2, func(record PolicyUpdateFailedRecord) error {
		failures = append(failures, record)
		return nil
	})
	if err != nil {
		t.Fatalf("NewReportingGenerationUpdater: %v", err)
	}
	active, err := updater.Commit(context.Background(), testBankImage())
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	store.failStep = "activate"
	if _, err := updater.Commit(context.Background(), testBankImage()); err == nil {
		t.Fatal("second Commit succeeded despite activation failure")
	}
	if store.active != active {
		t.Fatalf("active generation = %+v, want unchanged %+v", store.active, active)
	}
	if len(failures) != 1 {
		t.Fatalf("failure records = %+v, want one", failures)
	}
	record := failures[0]
	if record.RecordType != "policy_update_failed" || record.ActiveGeneration == nil ||
		*record.ActiveGeneration != active || record.AttemptedGeneration == nil ||
		*record.AttemptedGeneration != (Generation{Revision: 2, Bank: BankA}) ||
		!strings.Contains(record.Error, "activate generation 2") {
		t.Fatalf("failure record = %+v", record)
	}
}

func TestGenerationUpdaterRecoversCommittedBankAndClearsStaging(t *testing.T) {
	store := newMemoryBankStore()
	updater, err := NewGenerationUpdater(store, 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater: %v", err)
	}
	committedImage := testBankImage()
	active, err := updater.Commit(context.Background(), committedImage)
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}

	store.failStep = "profile"
	stagedImage := testBankImage()
	stagedImage.Rules[0].Value[0] = 99
	if _, err := updater.Commit(context.Background(), stagedImage); err == nil {
		t.Fatal("staging Commit succeeded despite injected profile failure")
	}
	if len(store.banks[BankA].Rules) == 0 {
		t.Fatal("test did not leave a partial inactive bank")
	}

	restarted, err := NewGenerationUpdater(store, 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater after restart: %v", err)
	}
	recovered, err := restarted.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if recovered.Generation != active || !equalEntries(recovered.Image.Rules, committedImage.Rules) ||
		!equalEntries(recovered.Image.Profiles, committedImage.Profiles) {
		t.Fatalf("recovered = %+v, want generation %+v and committed image", recovered, active)
	}
	if len(store.banks[BankA].Rules) != 0 || len(store.banks[BankA].Profiles) != 0 {
		t.Fatalf("inactive staging bank was not cleared: %+v", store.banks[BankA])
	}

	next, err := restarted.Commit(context.Background(), stagedImage)
	if err != nil {
		t.Fatalf("Commit after recovery: %v", err)
	}
	if next != (Generation{Revision: 2, Bank: BankA}) {
		t.Fatalf("next generation = %+v", next)
	}
}

func TestGenerationUpdaterRejectsRecoveryWithoutCommittedGeneration(t *testing.T) {
	updater, err := NewGenerationUpdater(newMemoryBankStore(), 4, 2)
	if err != nil {
		t.Fatalf("NewGenerationUpdater: %v", err)
	}
	if _, err := updater.Recover(context.Background()); !errors.Is(err, ErrNoCommittedGeneration) {
		t.Fatalf("Recover error = %v, want ErrNoCommittedGeneration", err)
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
	updateMu        sync.Mutex
	active          Generation
	banks           map[Bank]BankImage
	failStep        string
	corruptReadback bool
	cancelAfterRule bool
	cancelAfterRead bool
	cancel          context.CancelFunc
	calls           int
}

type memoryBankUpdate struct {
	store *memoryBankStore
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

func (store *memoryBankStore) BeginUpdate(ctx context.Context) (BankUpdate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.updateMu.Lock()
	if err := store.fail("begin"); err != nil {
		store.updateMu.Unlock()
		return nil, err
	}
	return &memoryBankUpdate{store: store}, nil
}

func (update *memoryBankUpdate) Close() {
	update.store.updateMu.Unlock()
}

func (update *memoryBankUpdate) Active(context.Context) (Generation, error) {
	if err := update.store.fail("active"); err != nil {
		return Generation{}, err
	}
	return update.store.active, nil
}

func (update *memoryBankUpdate) Reset(_ context.Context, bank Bank) error {
	if err := update.store.fail("reset"); err != nil {
		return err
	}
	update.store.banks[bank] = BankImage{}
	return nil
}

func (update *memoryBankUpdate) PutRule(_ context.Context, bank Bank, entry MapEntry) error {
	if err := update.store.fail("rule"); err != nil {
		return err
	}
	image := update.store.banks[bank]
	image.Rules = append(image.Rules, MapEntry{Key: entry.Key, Value: append([]byte(nil), entry.Value...)})
	update.store.banks[bank] = image
	if update.store.cancelAfterRule {
		update.store.cancel()
	}
	return nil
}

func (update *memoryBankUpdate) PutProfile(_ context.Context, bank Bank, entry MapEntry) error {
	if err := update.store.fail("profile"); err != nil {
		return err
	}
	image := update.store.banks[bank]
	image.Profiles = append(image.Profiles, MapEntry{Key: entry.Key, Value: append([]byte(nil), entry.Value...)})
	update.store.banks[bank] = image
	return nil
}

func (update *memoryBankUpdate) Read(_ context.Context, bank Bank) (BankImage, error) {
	if err := update.store.fail("read"); err != nil {
		return BankImage{}, err
	}
	image := cloneBankImage(update.store.banks[bank])
	if update.store.corruptReadback {
		image.Rules[0].Value[0]++
	}
	if update.store.cancelAfterRead {
		update.store.cancel()
	}
	return image, nil
}

func (update *memoryBankUpdate) Activate(_ context.Context, expected, generation Generation) error {
	if err := update.store.fail("activate"); err != nil {
		return err
	}
	if update.store.active != expected {
		return errors.New("active generation changed during update")
	}
	update.store.active = generation
	return nil
}
