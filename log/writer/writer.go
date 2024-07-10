package writer

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type SequencedBatch struct {
	Entries [][]byte
	// Index of the log that this batch starts at.
	BatchStartIdx uint64
}

// FlushFunc knows how to commit the Batch to the log.
// Must not return successfully until the Batch is durably stored (but may not yet be integrated).
type FlushFunc func(context.Context, SequencedBatch) error

func NewPreorderedPool(bufferSize int, maxAge time.Duration, startSeq uint64, f FlushFunc) *PreorderedPool {
	return &PreorderedPool{
		current: &batch{
			Done: make(chan struct{}),
		},
		bufferSize: bufferSize,
		flush:      f,
		maxAge:     maxAge,
		startSeq:   startSeq,
	}
}

// PreorderedPool is a helper for setting entries in a log.
type PreorderedPool struct {
	sync.Mutex
	current    *batch
	bufferSize int
	maxAge     time.Duration
	flushTimer *time.Timer
	startSeq   uint64

	flush FlushFunc
}

// Set Sets an entry in the tree.
// TODO: why do we need to lock the pool? Can we remove channels if only one instance of Migrillian runs?
func (p *PreorderedPool) Set(index uint64, e []byte) error {
	p.Lock()
	b := p.current
	// If this is the first entry in a batch, set a flush timer so we attempt to sequence it within maxAge.
	if len(b.Entries) == 0 {
		p.flushTimer = time.AfterFunc(p.maxAge, func() {
			p.Lock()
			defer p.Unlock()
			p.flushWithLock()
		})
	}
	if err := b.Set(p.startSeq, index, e); err != nil {
		return err
	}

	// If the batch is full, then put it in Seq table.
	if len(p.current.Entries) == p.bufferSize {
		p.flushWithLock()
	}
	p.Unlock()
	<-b.Done
	return b.Err
}

func (p *PreorderedPool) flushWithLock() {
	// timer can be nil if a batch was flushed because it because full at about the same time as it hit maxAge.
	// In this case we can just return.
	if p.flushTimer == nil {
		return
	}
	p.flushTimer.Stop()
	p.flushTimer = nil

	b := p.current
	sb := SequencedBatch{Entries: b.Entries, BatchStartIdx: p.startSeq}

	p.current = &batch{
		Done: make(chan struct{}),
	}
	p.startSeq = p.startSeq + uint64(len(b.Entries))
	go func() {
		b.Err = p.flush(context.TODO(), sb)
		close(b.Done)
	}()
}

type Batch struct {
	Entries [][]byte
}

// SequenceFunc knows how to assign contiguous sequence numbers to the entries in Batch.
// Returns the sequence number of the first entry, or an error.
// Must not return successfully until the assigned sequence numbers are durably stored.
type SequenceFunc func(context.Context, Batch) (uint64, error)

func NewPool(bufferSize int, maxAge time.Duration, s SequenceFunc) *Pool {
	return &Pool{
		current: &batch{
			Done: make(chan struct{}),
		},
		bufferSize: bufferSize,
		seq:        s,
		maxAge:     maxAge,
	}
}

// Pool is a helper for adding entries to a log.
type Pool struct {
	sync.Mutex
	current    *batch
	bufferSize int
	maxAge     time.Duration
	flushTimer *time.Timer

	seq SequenceFunc
}

// Add adds an entry to the tree.
// Returns the assigned sequence number, or an error.
func (p *Pool) Add(e []byte) (uint64, error) {
	p.Lock()
	b := p.current
	// If this is the first entry in a batch, set a flush timer so we attempt to sequence it within maxAge.
	if len(b.Entries) == 0 {
		p.flushTimer = time.AfterFunc(p.maxAge, func() {
			p.Lock()
			defer p.Unlock()
			p.flushWithLock()
		})
	}
	n := b.Add(e)
	// If the batch is full, then attempt to sequence it immediately.
	if n >= p.bufferSize {
		p.flushWithLock()
	}
	p.Unlock()
	<-b.Done
	return b.FirstSeq + uint64(n), b.Err
}

func (p *Pool) flushWithLock() {
	// timer can be nil if a batch was flushed because it because full at about the same time as it hit maxAge.
	// In this case we can just return.
	if p.flushTimer == nil {
		return
	}
	p.flushTimer.Stop()
	p.flushTimer = nil
	b := p.current
	p.current = &batch{
		Done: make(chan struct{}),
	}
	go func() {
		b.FirstSeq, b.Err = p.seq(context.TODO(), Batch{Entries: b.Entries})
		close(b.Done)
	}()
}

type batch struct {
	Entries  [][]byte
	Done     chan struct{}
	FirstSeq uint64
	Err      error
}

func (b *batch) Add(e []byte) int {
	b.Entries = append(b.Entries, e)
	return len(b.Entries)
}

func (b *batch) Set(startSeq uint64, seq uint64, e []byte) error {
	if seq-startSeq != uint64(len(b.Entries)) {
		return fmt.Errorf("integrity fail - expected seq %d, but started at %d", startSeq+uint64(len(b.Entries)), seq)
	}
	b.Entries = append(b.Entries, e)
	return nil
}
