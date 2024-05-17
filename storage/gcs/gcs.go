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
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
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

	"cloud.google.com/go/cloudsqlconn"
	"github.com/go-sql-driver/mysql"

	gcs "cloud.google.com/go/storage"
	f_log "github.com/transparency-dev/formats/log"
)

const (
	ringSize     = 10
	ringFormat   = "__seqRing/%04d"
	ringHeadPath = "__seqRing/head"
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

	dbPool *sql.DB

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
	// DBConn is the ConnectionName of the CloudSQL database to use.
	DBConn string
	DBUser string
	DBPass string
	DBName string

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

	d, err := cloudsqlconn.NewDialer(context.Background())
	if err != nil {
		klog.Exitf("cloudsqlconn.NewDialer: %v", err)
	}
	mysql.RegisterDialContext("cloudsqlconn",
		func(ctx context.Context, addr string) (net.Conn, error) {
			return d.Dial(ctx, opts.DBConn)
		})

	dbURI := fmt.Sprintf("%s:%s@cloudsqlconn(localhost:3306)/%s?parseTime=true",
		opts.DBUser, opts.DBPass, opts.DBName)

	dbPool, err := sql.Open("mysql", dbURI)
	if err != nil {
		klog.Exitf("Failed to open CloudSQL: %v", err)
	}

	if err := initDB(ctx, dbPool); err != nil {
		klog.Exitf("Failed to init DB: %v", err)
	}

	r := &Storage{
		gcsClient: c,
		projectID: opts.ProjectID,
		bucket:    opts.Bucket,
		dbPool:    dbPool,

		checkpointGen:          0,
		checkpointCacheControl: opts.CheckpointCacheControl,
		otherCacheControl:      opts.OtherCacheControl,
		entryBundleSize:        opts.EntryBundleSize,
		cpV:                    cpV,
		cpS:                    cpS,
	}
	r.pool = writer.NewPool(batchMaxSize, batchMaxAge, r.sequenceBatch)
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for {
					cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
					defer cancel()
					if more, err := r.assignSequenceAndIntegrate(cctx); err != nil {
						klog.Errorf("assignSequenceAndIntegrate: %v", err)
						break
					} else if !more {
						break
					}
					klog.Info("Quickloop")
				}
			}
		}
	}()

	return r
}

func initDB(ctx context.Context, dbPool *sql.DB) error {
	if _, err := dbPool.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS SeqCoord(
			id INT UNSIGNED NOT NULL,
			next BIGINT UNSIGNED NOT NULL,
			PRIMARY KEY (id)
		)`); err != nil {
		return err
	}
	if _, err := dbPool.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS Seq(
			id INT UNSIGNED NOT NULL,
			seq BIGINT UNSIGNED NOT NULL,
			v LONGBLOB,
			PRIMARY KEY (id, seq)
		)`); err != nil {
		return err
	}
	if _, err := dbPool.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS IntCoord(
			id INT UNSIGNED NOT NULL,
			seq BIGINT UNSIGNED NOT NULL,
			PRIMARY KEY (id)
		)`); err != nil {
		return err
	}
	if _, err := dbPool.ExecContext(ctx,
		`INSERT IGNORE INTO IntCoord (id, seq) VALUES (0, 0)`); err != nil {
		return err
	}
	return nil
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
	b, _, err := s.readCheckpoint(ctx)
	return b, err
}

func (s *Storage) readCheckpoint(ctx context.Context) ([]byte, int64, error) {
	cpRaw, mgen, err := s.GetObjectData(ctx, layout.CheckpointPath)
	if err == nil {
		s.checkpointGen = mgen
	}

	return cpRaw, mgen, err
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
	d, _, err := s.GetObjectData(ctx, objName)
	return d, err
}

// GetObjectData returns the bytes of the input object path.
func (s *Storage) GetObjectData(ctx context.Context, obj string) ([]byte, int64, error) {
	r, err := s.gcsClient.Bucket(s.bucket).Object(obj).NewReader(ctx)
	if err != nil {
		return nil, -1, fmt.Errorf("GetObjectData: failed to create reader for object %q in bucket %q: %w", obj, s.bucket, err)
	}
	defer r.Close()

	d, err := io.ReadAll(r)
	return d, r.Attrs.Generation, err
}

// Sequence commits to sequence numbers for an entry
// Returns the sequence number assigned to the first entry in the batch, or an error.
func (s *Storage) Sequence(ctx context.Context, leaf []byte) (uint64, error) {
	return s.pool.Add(leaf)
}

func (s *Storage) flushBatch(ctx context.Context, batch writer.Batch) (uint64, error) {
	b := &bytes.Buffer{}
	e := gob.NewEncoder(b)
	if err := e.Encode(batch); err != nil {
		return 0, fmt.Errorf("failed to serialise batch: %v", err)
	}
	data := b.Bytes()
	num := len(batch.Entries)

	tx, err := s.dbPool.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin tx: %v", err)
	}
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()

	r := tx.QueryRowContext(ctx, "SELECT id, next FROM SeqCoord WHERE id = ? FOR UPDATE", 0)
	var id, next uint64
	if err := r.Scan(&id, &next); err == sql.ErrNoRows {
		klog.Info("New log - first sequence")
		if _, err := tx.ExecContext(ctx, "INSERT INTO SeqCoord (id, next) VALUES (?, ?)", 0, next+uint64(num)); err != nil {
			return 0, fmt.Errorf("init new log in seqcoord: %v", err)
		}
	} else if err != nil {
		return 0, fmt.Errorf("failed to read seqcoord: %v", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO Seq(id, seq, v) VALUES(?, ?, ?)", 0, next, data); err != nil {
		return 0, fmt.Errorf("insert into seq: %v", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE SeqCoord SET next = ? WHERE ID = ?", next+uint64(num), 0); err != nil {
		return 0, fmt.Errorf("update seqcoord: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %v", err)
	}
	tx = nil

	return next, nil
}

// sequenceBatch writes the entries from the provided batch into the entry bundle files of the log.
//
// This func starts filling entries bundles at the next available slot in the log, ensuring that the
// sequenced entries are contiguous from the zeroth entry (i.e left-hand dense).
// We try to minimise the number of partially complete entry bundles by writing entries in chunks rather
// than one-by-one.
func (s *Storage) sequenceBatch(ctx context.Context, batch writer.Batch) (uint64, error) {
	return s.flushBatch(ctx, batch)
}

func (s *Storage) assignSequenceAndIntegrate(ctx context.Context) (bool, error) {
	tx, err := s.dbPool.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		if tx != nil {
			tx.Rollback()
		}
	}()

	row := tx.QueryRowContext(ctx, "SELECT seq FROM IntCoord WHERE id = ? FOR UPDATE", 0)
	var fromSeq uint64
	if err := row.Scan(&fromSeq); err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to read coord info: %v", err)
	}

	s.curSize = fromSeq
	now := time.Now()
	numAdded := 0

	klog.Infof("SA: Starting sequence & integrate...")
	defer func() {
		d := float64(time.Now().Sub(now)) / float64(time.Second)
		qps := 0.0
		if d > 0 {
			qps = float64(numAdded) / d
		}
		klog.Infof("SA: Sequencing & integrate @ %.1f qps took %vs", qps, d)
	}()

	row = tx.QueryRowContext(ctx, "SELECT v FROM Seq WHERE id = ? AND seq = ? FOR UPDATE", 0, fromSeq)
	var batchGob []byte
	if err := row.Scan(&batchGob); err == sql.ErrNoRows {
		return false, fmt.Errorf("integrity failure, Seq(%d/%d) not found", 0, fromSeq)
	} else if err != nil {
		return false, fmt.Errorf("failed to read seq(%d/%d): %v", 0, fromSeq, err)
	}

	g := gob.NewDecoder(bytes.NewReader(batchGob))
	batch := writer.Batch{}
	if err := g.Decode(&batch); err != nil {
		return false, fmt.Errorf("failed to deserialise batch: %v", err)
	}

	if len(batch.Entries) == 0 {
		return false, fmt.Errorf("no entries in batch seq %d", fromSeq)
	}

	seq := fromSeq
	bundleIndex, entriesInBundle := seq/uint64(s.entryBundleSize), seq%uint64(s.entryBundleSize)
	bundle := &bytes.Buffer{}
	if entriesInBundle > 0 {
		// If the latest bundle is partial, we need to read the data it contains in for our newer, larger, bundle.
		part, err := s.GetEntryBundle(ctx, bundleIndex, entriesInBundle)
		if err != nil {
			return false, err
		}
		bundle.Write(part)
	}
	// Add new entries to the bundle
	// TODO: write out hash -> seq objects.
	for _, e := range batch.Entries {
		bundle.WriteString(base64.StdEncoding.EncodeToString(e))
		bundle.WriteString("\n")
		entriesInBundle++
		seq++
		numAdded++
		if entriesInBundle == uint64(s.entryBundleSize) {
			//  This bundle is full, so we need to write it out...
			klog.V(1).Infof("Bundle idx %x is full", bundleIndex)
			objName := filepath.Join(layout.SeqPath("", bundleIndex))
			if err := s.createExclusive(ctx, objName, bundle.Bytes()); err != nil {
				if !errors.Is(os.ErrExist, err) {
					return false, err
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
		klog.V(1).Infof("Writing partial bundle idx %d.%d", bundleIndex, entriesInBundle)
		bd, bf := layout.SeqPath("", bundleIndex)
		bf = fmt.Sprintf("%s.%d", bf, entriesInBundle)
		if err := s.createExclusive(ctx, filepath.Join(bd, bf), bundle.Bytes()); err != nil {
			if !errors.Is(os.ErrExist, err) {
				return false, err
			}
		}
	}

	if err := s.doIntegrate(ctx, fromSeq, batch.Entries); err != nil {
		return false, fmt.Errorf("failed to integrate: %v", err)
	}

	if _, err := tx.ExecContext(ctx, "UPDATE IntCoord SET Seq=? WHERE ID=?", seq, 0); err != nil {
		return false, fmt.Errorf("update intcoord: %v", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM Seq WHERE Seq=? AND ID=?", fromSeq, 0); err != nil {
		return false, fmt.Errorf("update intcoord: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %v", err)
	}
	return true, nil
}

func (s *Storage) removeGen(ctx context.Context, gcsPath string, gen int64) error {
	bkt := s.gcsClient.Bucket(s.bucket)
	obj := bkt.Object(gcsPath)
	return obj.If(gcs.Conditions{GenerationMatch: gen}).Delete(ctx)

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

func (s *Storage) writeIfGen(ctx context.Context, objName string, gen int64, data []byte) error {
	bkt := s.gcsClient.Bucket(s.bucket)
	obj := bkt.Object(objName)

	var cond gcs.Conditions
	if gen == 0 {
		cond = gcs.Conditions{DoesNotExist: true}
	} else {
		cond = gcs.Conditions{GenerationMatch: gen}
	}

	w := obj.If(cond).NewWriter(ctx)
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write object %q to bucket %q: %w", objName, s.bucket, err)
	}

	return w.Close()
}

func (s *Storage) writeIfNotExists(ctx context.Context, objName string, data []byte) error {
	bkt := s.gcsClient.Bucket(s.bucket)
	obj := bkt.Object(objName)

	cond := gcs.Conditions{DoesNotExist: true}

	w := obj.If(cond).NewWriter(ctx)
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write object %q to bucket %q: %w", objName, s.bucket, err)
	}

	return w.Close()
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

				klog.V(2).Infof("createExclusive: identical resource already exists for %q:", objName)
				return nil
			}
		default:
			return err
		}
	}

	return nil
}

func (s *Storage) CurrentTree(ctx context.Context) (uint64, []byte, error) {
	size, hash, _, err := s.currentTreeGen(ctx)
	return size, hash, err
}

func (s *Storage) currentTreeGen(ctx context.Context) (uint64, []byte, int64, error) {
	cpRaw, cpGen, err := s.readCheckpoint(ctx)
	if err != nil {
		return 0, nil, -1, fmt.Errorf("readCheckpoint: %v", err)
	}
	cp, _, _, err := f_log.ParseCheckpoint(cpRaw, s.cpV.Name(), s.cpV)
	if err != nil {
		return 0, nil, -1, err
	}
	return cp.Size, cp.Hash, cpGen, nil
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
