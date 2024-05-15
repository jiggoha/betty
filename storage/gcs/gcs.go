// Copyright 2021 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcs

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AlCutter/betty/log/writer"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/serverless-log/api"
	"github.com/transparency-dev/serverless-log/api/layout"
	"golang.org/x/mod/sumdb/note"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"k8s.io/klog/v2"

	gcs "cloud.google.com/go/storage"
	f_log "github.com/transparency-dev/formats/log"
)

// NewTreeFunc is the signature of a function which receives information about newly integrated trees.
type NewTreeFunc func(size uint64, root []byte) error

// CurrentTree is the signature of a function which retrieves the current integrated tree size and root hash.
type CurrentTreeFunc func() (uint64, []byte, error)

// Storage is a serverless storage implementation which uses a GCS bucket to store tree state.
// The naming of the objects of the GCS object is:
//
//	leaves/aa/bb/cc/ddeeff...
//	seq/aa/bb/cc/ddeeff...
//	tile/<level>/aa/bb/ccddee...
//	checkpoint
//
// The functions on this struct are not thread-safe.
type Storage struct {
	mu sync.Mutex

	gcsClient *gcs.Client
	projectID string
	// bucket is the name of the bucket where tree data will be stored.
	bucket string
	// nextSeq is a hint to the Sequence func as to what the next available
	// sequence number is to help performance.
	// Note that nextSeq may be <= than the actual next available number, but
	// never greater.
	nextSeq uint64
	// checkpointGen is the GCS object generation number that this client last
	// read. This is useful for read-modify-write operation of the checkpoint.
	checkpointGen int64

	pool *writer.Pool

	checkpointCacheControl string
	otherCacheControl      string

	entryBundleSize int

	cpV note.Verifier
	cpS note.Signer

	curSize uint64
}

// StorageOpts holds configuration options for the storage client.
type StorageOpts struct {
	// ProjectID is the GCP project which hosts the storage bucket for the log.
	ProjectID string
	// Bucket is the name of the bucket to use for storing log state.
	Bucket string
	// CheckpointCacheControl, if set, will cause the Cache-Control header associated with the
	// checkpoint object to be set to this value. If unset, the current GCP default will be used.
	CheckpointCacheControl string
	// OtherCacheControl, if set, will cause the Cache-Control header associated with the
	// all non-checkpoint objects to be set to this value. If unset, the current GCP default
	// will be used.
	OtherCacheControl string
	EntryBundleSize   int
}

// New returns a Client which allows interaction with the log stored in
// the specified bucket on GCS.
func New(ctx context.Context, opts StorageOpts, batchMaxSize int, batchMaxAge time.Duration, cpV note.Verifier, cpS note.Signer) *Storage {
	c, err := gcs.NewClient(ctx)
	if err != nil {
		klog.Exitf("Failed to create GCS storage: %v", err)
	}

	r := &Storage{
		gcsClient:              c,
		projectID:              opts.ProjectID,
		bucket:                 opts.Bucket,
		checkpointGen:          0,
		checkpointCacheControl: opts.CheckpointCacheControl,
		otherCacheControl:      opts.OtherCacheControl,
		entryBundleSize:        opts.EntryBundleSize,
		cpV:                    cpV,
		cpS:                    cpS,
	}
	r.pool = writer.NewPool(batchMaxSize, batchMaxAge, r.sequenceBatch)

	return r
}

func (c *Storage) BucketExists(ctx context.Context, bucket string) (bool, error) {
	it := c.gcsClient.Buckets(ctx, c.projectID)
	for {
		bAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return false, err
		}
		if bAttrs.Name == bucket {
			return true, nil
		}
	}
	return false, nil
}

// Create creates a new GCS bucket and returns an error on failure.
func (s *Storage) Create(ctx context.Context, bucket string) error {
	// Check if the bucket already exists.
	exists, err := s.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("expected bucket %q to not be created yet)", bucket)
	}

	// Create the bucket.
	bkt := s.gcsClient.Bucket(bucket)
	if err := bkt.Create(ctx, s.projectID, nil); err != nil {
		return fmt.Errorf("failed to create bucket %q in project %s: %w", bucket, s.projectID, err)
	}
	bkt.ACL().Set(ctx, gcs.AllUsers, gcs.RoleReader)

	s.bucket = bucket
	s.nextSeq = 0
	return nil
}

// SetNextSeq sets the input as the nextSeq of the client.
func (s *Storage) SetNextSeq(num uint64) {
	s.nextSeq = num
}

// WriteCheckpoint stores a raw log checkpoint on GCS if it matches the
// generation that the client thinks the checkpoint is. The client updates the
// generation number of the checkpoint whenever ReadCheckpoint is called.
//
// This method will fail to write if 1) the checkpoint exists and the client
// has never read it or 2) the checkpoint has been updated since the client
// called ReadCheckpoint.
func (s *Storage) WriteCheckpoint(ctx context.Context, newCPRaw []byte) error {
	bkt := s.gcsClient.Bucket(s.bucket)
	obj := bkt.Object(layout.CheckpointPath)

	var cond gcs.Conditions
	if s.checkpointGen == 0 {
		cond = gcs.Conditions{DoesNotExist: true}
	} else {
		cond = gcs.Conditions{GenerationMatch: s.checkpointGen}
	}

	w := obj.If(cond).NewWriter(ctx)
	if s.checkpointCacheControl != "" {
		w.ObjectAttrs.CacheControl = s.checkpointCacheControl
	}
	if _, err := w.Write(newCPRaw); err != nil {
		return err
	}
	return w.Close()
}

// ReadCheckpoint reads from GCS and returns the contents of the log checkpoint.
func (s *Storage) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	bkt := s.gcsClient.Bucket(s.bucket)
	obj := bkt.Object(layout.CheckpointPath)

	// Get the GCS generation number.
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		return nil, fmt.Errorf("Object(%q).Attrs: %w", obj.ObjectName(), err)
	}
	s.checkpointGen = attrs.Generation

	// Get the content of the checkpoint.
	r, err := obj.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

// GetTile returns the tile at the given tile-level and tile-index.
// If no complete tile exists at that location, it will attempt to find a
// partial tile for the given tree size at that location.
func (s *Storage) GetTile(ctx context.Context, level, index, logSize uint64) (*api.Tile, error) {
	tileSize := layout.PartialTileSize(level, index, logSize)
	bkt := s.gcsClient.Bucket(s.bucket)

	// Pass an empty rootDir since we don't need this concept in GCS.
	objName := filepath.Join(layout.TilePath("", level, index, tileSize))
	r, err := bkt.Object(objName).NewReader(ctx)
	if err != nil {
		fmt.Printf("GetTile: failed to create reader for object %q in bucket %q: %v", objName, s.bucket, err)

		if errors.Is(err, gcs.ErrObjectNotExist) {
			// Return the generic NotExist error so that tileCache.Visit can differentiate
			// between this and other errors.
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	defer r.Close()

	t, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read tile object %q in bucket %q: %v", objName, s.bucket, err)
	}

	var tile api.Tile
	if err := tile.UnmarshalText(t); err != nil {
		return nil, fmt.Errorf("failed to parse tile: %w", err)
	}
	return &tile, nil
}

// GetEntryBundle retrieves the Nth entries bundle.
// If size is != the max size of the bundle, a partial bundle is returned.
func (s *Storage) GetEntryBundle(ctx context.Context, index, size uint64) ([]byte, error) {
	bd, bf := layout.SeqPath("", index)
	if size < uint64(s.entryBundleSize) {
		bf = fmt.Sprintf("%s.%d", bf, size)
	}
	objName := filepath.Join(bd, bf)
	return s.GetObjectData(ctx, objName)
}

// GetObjectData returns the bytes of the input object path.
func (s *Storage) GetObjectData(ctx context.Context, obj string) ([]byte, error) {
	r, err := s.gcsClient.Bucket(s.bucket).Object(obj).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetObjectData: failed to create reader for object %q in bucket %q: %q", obj, s.bucket, err)
	}
	defer r.Close()

	return io.ReadAll(r)
}

// Sequence commits to sequence numbers for an entry
// Returns the sequence number assigned to the first entry in the batch, or an error.
func (s *Storage) Sequence(ctx context.Context, leaf []byte) (uint64, error) {
	return s.pool.Add(leaf)
}

// sequenceBatch writes the entries from the provided batch into the entry bundle files of the log.
//
// This func starts filling entries bundles at the next available slot in the log, ensuring that the
// sequenced entries are contiguous from the zeroth entry (i.e left-hand dense).
// We try to minimise the number of partially complete entry bundles by writing entries in chunks rather
// than one-by-one.
func (s *Storage) sequenceBatch(ctx context.Context, batch writer.Batch) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	size, _, err := s.CurrentTree(ctx)
	if err != nil {
		return 0, err
	}
	s.curSize = size

	if len(batch.Entries) == 0 {
		return 0, nil
	}
	seq := s.curSize
	bundleIndex, entriesInBundle := seq/uint64(s.entryBundleSize), seq%uint64(s.entryBundleSize)
	bundle := &bytes.Buffer{}
	if entriesInBundle > 0 {
		// If the latest bundle is partial, we need to read the data it contains in for our newer, larger, bundle.
		part, err := s.GetEntryBundle(ctx, bundleIndex, entriesInBundle)
		if err != nil {
			return 0, err
		}
		bundle.Write(part)
	}
	// Add new entries to the bundle
	for _, e := range batch.Entries {
		bundle.WriteString(base64.StdEncoding.EncodeToString(e))
		bundle.WriteString("\n")
		entriesInBundle++
		if entriesInBundle == uint64(s.entryBundleSize) {
			//  This bundle is full, so we need to write it out...
			klog.V(1).Infof("Bundle idx %x is full", bundleIndex)
			objName := filepath.Join(layout.SeqPath("", bundleIndex))
			if err := s.createExclusive(ctx, objName, bundle.Bytes()); err != nil {
				if !errors.Is(os.ErrExist, err) {
					return 0, err
				}
			}
			// ... and prepare the next entry bundle for any remaining entries in the batch
			bundleIndex++
			entriesInBundle = 0
			bundle = &bytes.Buffer{}
			klog.V(1).Infof("Starting bundle idx %d", bundleIndex)
		}
	}
	// If we have a partial bundle remaining once we've added all the entries from the batch,
	// this needs writing out too.
	if entriesInBundle > 0 {
		klog.V(1).Infof("Writing partial bundle idx %d.%d is full", bundleIndex, entriesInBundle)
		bd, bf := layout.SeqPath("", bundleIndex)
		bf = fmt.Sprintf("%s.%d", bf, entriesInBundle)
		if err := s.createExclusive(ctx, filepath.Join(bd, bf), bundle.Bytes()); err != nil {
			if !errors.Is(os.ErrExist, err) {
				return 0, err
			}
		}
	}

	// For simplicitly, well in-line the integration of these new entries into the Merkle structure too.
	return seq, s.doIntegrate(ctx, seq, batch.Entries)
}

// doIntegrate handles integrating new entries into the log, and updating the checkpoint.
func (s *Storage) doIntegrate(ctx context.Context, from uint64, batch [][]byte) error {
	newSize, newRoot, err := writer.Integrate(ctx, from, batch, s, rfc6962.DefaultHasher)
	if err != nil {
		klog.Errorf("Failed to integrate: %v", err)
		return err
	}
	if err := s.NewTree(ctx, newSize, newRoot); err != nil {
		return fmt.Errorf("newTree: %v", err)
	}
	return nil
}

// assertContent checks that the content at `gcsPath` matches the passed in `data`.
func (c *Storage) assertContent(ctx context.Context, gcsPath string, data []byte) (equal bool, err error) {
	bkt := c.gcsClient.Bucket(c.bucket)

	obj := bkt.Object(gcsPath)
	r, err := obj.NewReader(ctx)
	if err != nil {
		klog.V(2).Infof("assertContent: failed to create reader for object %q in bucket %q: %v",
			gcsPath, c.bucket, err)
		return false, err
	}
	defer r.Close()

	gcsData, err := io.ReadAll(r)
	if err != nil {
		return false, err
	}

	if bytes.Equal(gcsData, data) {
		return true, nil
	}
	klog.V(2).Infof("assertContent(%q):\nGCS:\n%s\nWrite:\n%s", gcsPath, gcsData, data)
	return false, nil
}

// StoreTile writes a tile out to GCS.
// Fully populated tiles are stored at the path corresponding to the level &
// index parameters, partially populated (i.e. right-hand edge) tiles are
// stored with a .xx suffix where xx is the number of "tile leaves" in hex.
func (s *Storage) StoreTile(ctx context.Context, level, index uint64, tile *api.Tile) error {
	tileSize := uint64(tile.NumLeaves)
	klog.V(2).Infof("StoreTile: level %d index %x ts: %x", level, index, tileSize)
	if tileSize == 0 || tileSize > 256 {
		return fmt.Errorf("tileSize %d must be > 0 and <= 256", tileSize)
	}
	t, err := tile.MarshalText()
	if err != nil {
		return fmt.Errorf("failed to marshal tile: %w", err)
	}

	// Pass an empty rootDir since we don't need this concept in GCS.
	tPath := filepath.Join(layout.TilePath("", level, index, tileSize%256))
	return s.createExclusive(ctx, tPath, t)
}

func (s *Storage) createExclusive(ctx context.Context, objName string, data []byte) error {
	bkt := s.gcsClient.Bucket(s.bucket)
	obj := bkt.Object(objName)
	// Tiles, partial or full, should only be written once.
	w := obj.If(gcs.Conditions{DoesNotExist: true}).NewWriter(ctx)
	if s.otherCacheControl != "" {
		w.ObjectAttrs.CacheControl = s.otherCacheControl
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write tile object %q to bucket %q: %w", objName, s.bucket, err)
	}

	if err := w.Close(); err != nil {
		switch ee := err.(type) {
		case *googleapi.Error:
			// If we run into a precondition failure error, check that the object
			// which exists contains the same content that we want to write.
			if ee.Code == http.StatusPreconditionFailed {
				if equal, err := s.assertContent(ctx, objName, data); err != nil {
					return fmt.Errorf("failed to read content of %q: %w", objName, err)
				} else if !equal {
					return fmt.Errorf("assertion that resource content for %q has not changed failed", objName)
				}

				klog.V(2).Infof("StoreTile: identical resource already exists for %q:", objName)
				return nil
			}
		default:
			return err
		}
	}

	return nil
}

func (s *Storage) CurrentTree(ctx context.Context) (uint64, []byte, error) {
	b, err := s.ReadCheckpoint(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("ReadCheckpoint: %v", err)
	}
	cp, _, _, err := f_log.ParseCheckpoint(b, s.cpV.Name(), s.cpV)
	if err != nil {
		return 0, nil, err
	}
	return cp.Size, cp.Hash, nil
}

func (s *Storage) NewTree(ctx context.Context, size uint64, hash []byte) error {
	cp := &f_log.Checkpoint{
		Origin: s.cpS.Name(),
		Size:   size,
		Hash:   hash,
	}
	n, err := note.Sign(&note.Note{Text: string(cp.Marshal())}, s.cpS)
	if err != nil {
		return err
	}
	return s.WriteCheckpoint(ctx, n)
}
