package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

type BatchStore interface {
	AppendBatch([]Record) error
}

const maximumBatchSize = 256

type WriterOptions struct {
	QueueCapacity  int
	RecentCapacity int
	RecentBytes    int64
	BatchSize      int
	FlushInterval  time.Duration
	RetryInterval  time.Duration
	Redactor       Redactor
	Diagnostics    io.Writer
}

type Diagnostics struct {
	CircuitOpen       bool   `json:"circuit_open"`
	LastError         string `json:"last_error,omitempty"`
	QueueDepth        int    `json:"queue_depth"`
	QueueDrops        uint64 `json:"queue_drops"`
	StoreDrops        uint64 `json:"store_drops"`
	RecentDepth       int    `json:"recent_depth"`
	RecentBytes       int64  `json:"recent_bytes"`
	GapFirstRecordID  string `json:"gap_first_record_id,omitempty"`
	GapLatestRecordID string `json:"gap_latest_record_id,omitempty"`
}

type Writer struct {
	backend     BatchStore
	options     WriterOptions
	queue       chan Record
	done        chan struct{}
	cancel      context.CancelFunc
	submitMu    sync.RWMutex
	closing     bool
	mu          sync.RWMutex
	recent      []Record
	recentBytes int64
	diagnostics Diagnostics
	closeErr    error
}

func NewWriter(backend BatchStore, options WriterOptions) (*Writer, error) {
	if backend == nil {
		return nil, errors.New("store backend is required")
	}
	if options.QueueCapacity == 0 {
		options.QueueCapacity = 1024
	}
	if options.RecentCapacity == 0 {
		options.RecentCapacity = 1024
	}
	if options.RecentBytes == 0 {
		options.RecentBytes = 4 << 20
	}
	if options.BatchSize == 0 {
		options.BatchSize = 64
	}
	if options.FlushInterval == 0 {
		options.FlushInterval = 50 * time.Millisecond
	}
	if options.RetryInterval == 0 {
		options.RetryInterval = time.Second
	}
	if options.Diagnostics == nil {
		options.Diagnostics = io.Discard
	}
	if options.QueueCapacity < 1 || options.QueueCapacity > 100_000 || options.RecentCapacity < 1 ||
		options.RecentBytes < 1 || options.BatchSize < 1 || options.BatchSize > options.QueueCapacity || options.BatchSize > maximumBatchSize ||
		options.FlushInterval < time.Millisecond || options.RetryInterval < time.Millisecond {
		return nil, errors.New("store writer limits are invalid")
	}
	context, cancel := context.WithCancel(context.Background())
	writer := &Writer{backend: backend, options: options, queue: make(chan Record, options.QueueCapacity), done: make(chan struct{}), cancel: cancel}
	go writer.run(context)
	return writer, nil
}

func (writer *Writer) Submit(record Record) bool {
	writer.submitMu.RLock()
	defer writer.submitMu.RUnlock()
	if writer.closing {
		return false
	}
	sanitized, err := writer.options.Redactor.Apply(record)
	if err != nil {
		writer.drop(record.ID, true)
		return false
	}
	select {
	case writer.queue <- sanitized:
		return true
	default:
		writer.drop(record.ID, false)
		return false
	}
}

func (writer *Writer) Diagnostics() Diagnostics {
	writer.mu.RLock()
	defer writer.mu.RUnlock()
	diagnostic := writer.diagnostics
	diagnostic.QueueDepth = len(writer.queue)
	return diagnostic
}

func (writer *Writer) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("store close context is required")
	}
	writer.submitMu.Lock()
	if !writer.closing {
		writer.closing = true
		writer.cancel()
	}
	writer.submitMu.Unlock()
	select {
	case <-writer.done:
		writer.mu.RLock()
		defer writer.mu.RUnlock()
		return writer.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (writer *Writer) run(ctx context.Context) {
	defer close(writer.done)
	flush := time.NewTicker(writer.options.FlushInterval)
	retry := time.NewTicker(writer.options.RetryInterval)
	defer flush.Stop()
	defer retry.Stop()
	batch := make([]Record, 0, writer.options.BatchSize)
	for {
		select {
		case record := <-writer.queue:
			batch = append(batch, record)
			if len(batch) >= writer.options.BatchSize {
				writer.flush(batch)
				batch = batch[:0]
			}
		case <-flush.C:
			if len(batch) != 0 {
				writer.flush(batch)
				batch = batch[:0]
			}
		case <-retry.C:
			writer.probe()
		case <-ctx.Done():
			for {
				select {
				case record := <-writer.queue:
					batch = append(batch, record)
				default:
					writer.probe()
					if len(batch) != 0 {
						writer.flush(batch)
					}
					writer.mu.Lock()
					if len(writer.recent) != 0 {
						writer.closeErr = errors.New("store closed with unpersisted records")
					}
					writer.mu.Unlock()
					return
				}
			}
		}
	}
}

func (writer *Writer) flush(batch []Record) {
	writer.mu.RLock()
	open := writer.diagnostics.CircuitOpen
	writer.mu.RUnlock()
	if open {
		writer.buffer(batch)
		return
	}
	if err := writer.backend.AppendBatch(batch); err != nil {
		writer.openCircuit(err)
		writer.buffer(batch)
	}
}

func (writer *Writer) probe() {
	writer.mu.Lock()
	if !writer.diagnostics.CircuitOpen || len(writer.recent) == 0 {
		writer.mu.Unlock()
		return
	}
	batch := append([]Record(nil), writer.recent...)
	writer.mu.Unlock()
	if err := writer.backend.AppendBatch(batch); err != nil {
		writer.openCircuit(err)
		return
	}
	writer.mu.Lock()
	writer.recent = writer.recent[:0]
	writer.recentBytes = 0
	writer.diagnostics.CircuitOpen = false
	writer.diagnostics.LastError = ""
	writer.diagnostics.RecentDepth = 0
	writer.diagnostics.RecentBytes = 0
	writer.mu.Unlock()
}

func (writer *Writer) buffer(records []Record) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, record := range records {
		size := int64(len(record.Summary) + len(labelsJSON(record.Labels)) + len(record.Payload) + 512)
		if len(writer.recent) >= writer.options.RecentCapacity || writer.recentBytes+size > writer.options.RecentBytes {
			writer.diagnostics.StoreDrops++
			writer.noteGapLocked(record.ID)
			continue
		}
		writer.recent = append(writer.recent, record)
		writer.recentBytes += size
	}
	writer.diagnostics.RecentDepth = len(writer.recent)
	writer.diagnostics.RecentBytes = writer.recentBytes
}

func (writer *Writer) openCircuit(err error) {
	writer.mu.Lock()
	writer.diagnostics.CircuitOpen = true
	writer.diagnostics.LastError = "storage unavailable"
	writer.mu.Unlock()
	_, _ = fmt.Fprintln(writer.options.Diagnostics, "agentshield store degraded: storage unavailable")
}

func (writer *Writer) drop(id string, storeDrop bool) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if storeDrop {
		writer.diagnostics.StoreDrops++
	} else {
		writer.diagnostics.QueueDrops++
	}
	writer.noteGapLocked(id)
}

func (writer *Writer) noteGapLocked(id string) {
	if writer.diagnostics.GapFirstRecordID == "" {
		writer.diagnostics.GapFirstRecordID = id
	}
	writer.diagnostics.GapLatestRecordID = id
}
