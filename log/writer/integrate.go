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

package writer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/serverless-log/api"
	"github.com/transparency-dev/serverless-log/api/layout"
	"github.com/transparency-dev/serverless-log/client"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

// IntegrateStorage represents the set of functions needed by the integrate function.
type IntegrateStorage interface {
	// GetTile returns the tile at the given level & index.
	GetTile(ctx context.Context, level, index, logSize uint64) (*api.Tile, error)

	// StoreTile stores the tile at the given level & index.
	StoreTile(ctx context.Context, level, index uint64, tile *api.Tile) error

	GetEntryBundle(ctx context.Context, index uint64, size uint64) ([]byte, error)
}

var (
	// ErrDupeLeaf is returned by the Sequence method of storage implementations to
	// indicate that a leaf has already been sequenced.
	ErrDupeLeaf = errors.New("duplicate leaf")

	// ErrSeqAlreadyAssigned is returned by the Assign method of storage implementations
	// to indicate that the provided sequence number is already in use.
	ErrSeqAlreadyAssigned = errors.New("sequence number already assigned")
)

type readCache struct {
	sync.RWMutex

	hits    int
	entries map[string]*api.Tile
}

func (r *readCache) get(l, i uint64) (*api.Tile, bool) {
	r.RLock()
	defer r.RUnlock()
	e, ok := r.entries[fmt.Sprintf("%d/%d", l, i)]
	if ok {
		r.hits++
	}
	return e, ok
}

func (r *readCache) set(l, i uint64, t *api.Tile) {
	r.Lock()
	defer r.Unlock()
	k := fmt.Sprintf("%d/%d", l, i)
	if _, ok := r.entries[k]; ok {
		panic(fmt.Errorf("Attempting to overwrite %v", k))
	}
	r.entries[k] = t
}

// Integrate adds all sequenced entries greater than fromSize into the tree.
// Returns an updated Checkpoint, or an error.
func Integrate(ctx context.Context, fromSize uint64, batch [][]byte, st IntegrateStorage, h merkle.LogHasher) (uint64, []byte, error) {
	rc := readCache{entries: make(map[string]*api.Tile)}
	defer func() {
		klog.Infof("read cache hits: %d", rc.hits)
	}()
	getTile := func(l, i uint64) (*api.Tile, error) {
		r, ok := rc.get(l, i)
		if ok {
			return r, nil
		}
		t, err := st.GetTile(ctx, l, i, fromSize)
		if err != nil {
			return nil, err
		}
		rc.set(l, i, t)
		return t, nil
	}

	// Ugh, fill cache:
	nIDs := compact.RangeNodes(0, fromSize, nil)
	wg := sync.WaitGroup{}
	for _, n := range nIDs {
		wg.Add(1)
		go func(n compact.NodeID) {
			defer wg.Done()
			tileLevel, tileIndex, _, _ := layout.NodeCoordsToTileAddress(uint64(n.Level), uint64(n.Index))
			_, _ = getTile(tileLevel, tileIndex)
		}(n)
	}
	wg.Done()

	hashes, err := client.FetchRangeNodes(ctx, fromSize, func(_ context.Context, l, i uint64) (*api.Tile, error) {
		return getTile(l, i)
	})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to fetch compact range nodes: %w", err)
	}

	rf := compact.RangeFactory{Hash: h.HashChildren}
	baseRange, err := rf.NewRange(0, fromSize, hashes)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create range covering existing log: %w", err)
	}

	// Initialise a compact range representation, and verify the stored state.
	r, err := baseRange.GetRootHash(nil)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid log state, unable to recalculate root: %w", err)
	}

	klog.V(1).Infof("Loaded state with roothash %x", r)

	// Create a new compact range which represents the update to the tree
	newRange := rf.NewEmptyRange(fromSize)
	tc := tileCache{m: make(map[tileKey]*api.Tile), getTile: getTile}
	if len(batch) == 0 {
		klog.V(1).Infof("Nothing to do.")
		// Nothing to do, nothing done.
		return fromSize, r, nil
	}
	for _, e := range batch {
		lh := h.HashLeaf(e)
		// Update range and set nodes
		if err := newRange.Append(lh, tc.Visit); err != nil {
			return 0, nil, fmt.Errorf("newRange.Append(): %v", err)
		}

	}

	// Merge the update range into the old tree
	if err := baseRange.AppendRange(newRange, tc.Visit); err != nil {
		return 0, nil, fmt.Errorf("failed to merge new range onto existing log: %w", err)
	}

	// Calculate the new root hash - don't pass in the tileCache visitor here since
	// this will construct any ephemeral nodes and we do not want to store those.
	newRoot, err := baseRange.GetRootHash(nil)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to calculate new root hash: %w", err)
	}

	// All calculation is now complete, all that remains is to store the new
	// tiles and updated log state.
	klog.V(1).Infof("New log state: size 0x%x hash: %x", baseRange.End(), newRoot)

	eg := errgroup.Group{}
	for k, t := range tc.m {
		k := k
		t := t
		eg.Go(func() error {
			if err := st.StoreTile(ctx, k.level, k.index, t); err != nil {
				return fmt.Errorf("failed to store tile at level %d index %d: %w", k.level, k.index, err)
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return 0, nil, err
	}

	return baseRange.End(), newRoot, nil
}

// tileKey is a level/index key for the tile cache below.
type tileKey struct {
	level uint64
	index uint64
}

// tileCache is a simple cache for storing the newly created tiles produced by
// the integration of new leaves into the tree.
//
// Calls to Visit will cause the map of tiles to become filled with the set of
// `dirty` tiles which need to be flushed back to disk to preserve the updated
// tree state.
//
// Note that by itself, this cache does not update any on-disk state.
type tileCache struct {
	m map[tileKey]*api.Tile

	getTile func(level, index uint64) (*api.Tile, error)
}

// Visit should be called once for each newly set non-ephemeral node in the
// tree.
//
// If the tile containing id has not been seen before, this method will fetch
// it from disk (or create a new empty in-memory tile if it doesn't exist), and
// update it by setting the node corresponding to id to the value hash.
func (tc tileCache) Visit(id compact.NodeID, hash []byte) {
	tileLevel, tileIndex, nodeLevel, nodeIndex := layout.NodeCoordsToTileAddress(uint64(id.Level), uint64(id.Index))
	tileKey := tileKey{level: tileLevel, index: tileIndex}
	tile := tc.m[tileKey]
	if tile == nil {
		// We haven't see this tile before, so try to fetch it from disk
		created := false

		var err error
		tile, err = tc.getTile(tileLevel, tileIndex)
		if err != nil {
			if !os.IsNotExist(err) {
				panic(err)
			}
			// This is a brand new tile.
			created = true
			tile = &api.Tile{
				Nodes: make([][]byte, 0, 256*2),
			}
		}
		klog.V(2).Infof("GetTile: %v new: %v", tileKey, created)
		tc.m[tileKey] = tile
	}
	// Update the tile with the new node hash.
	idx := api.TileNodeKey(nodeLevel, nodeIndex)
	if l := uint(len(tile.Nodes)); idx >= l {
		tile.Nodes = append(tile.Nodes, make([][]byte, idx-l+1)...)
	}
	tile.Nodes[idx] = hash
	// Update the number of 'tile leaves', if necessary.
	if nodeLevel == 0 && nodeIndex >= uint64(tile.NumLeaves) {
		tile.NumLeaves = uint(nodeIndex + 1)
	}
}
