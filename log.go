package betty

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
	"k8s.io/klog/v2"
)

// Entry represents an entry in a log.
type Entry struct {
	data     []byte
	identity []byte
	leafHash []byte
}

func (e Entry) Data() []byte     { return e.data }
func (e Entry) Identity() []byte { return e.identity }
func (e Entry) LeafHash() []byte { return e.leafHash }

// NewEntry creates a new Entry object with leaf data.
func NewEntry(data []byte) Entry {
	return Entry{
		data: data,
	}
}

// NewEntryWithIdentity creates a new Entry with leaf data and a semantic identity.
func NewEntryWithIdentity(data []byte, identity []byte) Entry {
	e := NewEntry(data)
	e.identity = identity
	return e
}

// BadPractice exports functions which are generally considered bad practice.
// These functions are only provided for backwards compatibility with legacy systems,
// modern transparency ecosystems should not use them.
var BadPractice *badPractice

type badPractice struct{}

// SetLeafHash overrides an entry's MerkleLeafHash.
//
// Normally, this should be calculated automatically and commit to the entirety of the
// leaf data. Overriding this can result in anything from a tree with entries which
// cannot shown to have been included, to broken security properties due to malleable
// entries.
func (bp badPractice) SetLeafHash(e *Entry, leafHash []byte) {
	e.leafHash = leafHash
}

// SequenceWriter takes a Entry, assigns it to an index in the log, and returns the assigned index.
// If the entry's Identity has previously been assigned an index, the storage MAY return a previous index.
// Implementations MAY integrate the entry into the log before returning, but SHOULD target integrating entries
// within 1-2 seconds in all cases.
//
// This is a low-level function intended to be used by Tessera directly, but may be used by legacy personalities
// to implement subtle/non-recommended functionality.
type SequenceWriter func(ctx context.Context, entry Entry) (uint64, error)

// Storage describes the required functions for the underlying low-level storage implementation.
type Storage interface {
	Sequence(context.Context, Entry) (uint64, error)
	CurrentTree(context.Context) (uint64, []byte, error)
}

func NewSequencingWriter[T Storage](ctx context.Context, s T, opts ...WriterOpts[T]) (*Log, SequenceWriter) {
	// Use a safe algorithm for calulating Merkle leaf hashes.
	seq := func(ctx context.Context, entry Entry) (uint64, error) {
		entry.leafHash = rfc6962.DefaultHasher.HashLeaf(entry.data)
		return s.Sequence(ctx, entry)
	}
	// Apply all the options
	for _, opt := range opts {
		s, seq = opt(s, seq)
	}

	l := &Log{s: s}
	return l, seq
}

// WriterOpts is the type signature for the various option parameters which can be passed in to NewSequencingWriter.
type WriterOpts[T Storage] func(T, SequenceWriter) (T, SequenceWriter)

// DedupStorage describes the required functions for a low-level storage implementation which supports deduplication.
type DedupStorage interface {
	SequenceForLeafHash(context.Context, []byte) (uint64, error)
	StoreSequenceForLeafHash(context.Context, []byte, uint64) error
}

// WithDedup is an option which causes sequencing to attempt to squash dupes.
// In order to use this option, the underlying storage must also implement the DedupStorage interface.
func WithDedup[T DedupStorage](s T, seq SequenceWriter) (T, SequenceWriter) {
	seq = func(ctx context.Context, e Entry) (uint64, error) {
		if seq, err := s.SequenceForLeafHash(ctx, e.Identity()); err != nil {
			if err != os.ErrNotExist {
				return 0, fmt.Errorf("failed to dedupe: %v", err)
			}
			// Already exists, so return the previously assigned sequence number
			return seq, nil
		}
		seq, err := seq(ctx, e)
		if err != nil {
			return 0, err
		}
		if err := s.StoreSequenceForLeafHash(ctx, e.Identity(), seq); err != nil {
			return 0, fmt.Errorf("failed to store dedupe info: %v", err)
		}
		return seq, nil
	}
	return s, seq
}

// WithSynchronousIntegration is an option which causes calls to Sequence to only return once the sequence numbers
// assigned to the entries have also been integrated into the tree.
func WithSynchronousIntegration[T Storage](s T, seq SequenceWriter) (T, SequenceWriter) {
	seq = func(ctx context.Context, e Entry) (uint64, error) {
		idx, err := seq(ctx, e)
		if err != nil {
			return 0, err
		}
		// TODO: can we do better than polling?
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-t.C:
			}
			size, _, err := s.CurrentTree(ctx)
			if err != nil {
				klog.Warningf("Failed to check current tree size: %v", err)
			}
			if size >= idx {
				break
			}
		}
		return idx, nil
	}
	return s, seq
}

// Log represents an instance of a Tessera log.
type Log struct {
	s Storage
}

// CurrentTree returns the current state of the Merkle tree.
func (l Log) CurrentTree(ctx context.Context) (uint64, []byte, error) { return l.s.CurrentTree(ctx) }
