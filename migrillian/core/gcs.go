// Copyright 2018 Google LLC. All Rights Reserved.
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

package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
)

var errRetry = errors.New("retry")

func idHashCertData(_ int64, entry *ct.RawLogEntry) []byte {
	hash := sha256.Sum256(entry.Cert.Data)
	return hash[:]
}

func idHashLeafIndex(index int64, _ *ct.RawLogEntry) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(index))
	hash := sha256.Sum256(data)
	return hash[:]
}

// Storage defines the explicit interface that storage implementations must implement for the HTTP handler here.
// In addition, they'll need to implement the IntegrateStorage methods in log/writer/integrate.go too.
type Storage interface {
	// Sequence assigns the provided leaf data to an index in the log, returning
	// that index once it's durably committed.
	// Implementations are expected to integrate these new entries in a "timely" fashion.
	Sequence(context.Context, []byte) (uint64, error)
	AddSequenced(context.Context, uint64, []byte) error
	NextAvailable(context.Context) (uint64, error)
	SequenceForLeafHash(context.Context, []byte) (uint64, error)
	CurrentTree(context.Context) (uint64, []byte, error)
	NewTree(context.Context, uint64, []byte) error
}

// GCSTesseraClient is a means of communicating with a GCS Tiles log.
type GCSTesseraClient struct {
	treeID  int64
	idFunc  func(int64, *ct.RawLogEntry) []byte
	storage Storage
}

// NewGCSTesseraClient creates and initializes a GCS tiles log client.
func NewGCSTesseraClient(
	treeID int64,
	idFuncType configpb.IdentityFunction,
	s Storage,
) (*GCSTesseraClient, error) {

	ret := GCSTesseraClient{
		treeID:  treeID,
		storage: s,
	}

	switch idFuncType {
	case configpb.IdentityFunction_SHA256_CERT_DATA:
		ret.idFunc = idHashCertData
	case configpb.IdentityFunction_SHA256_LEAF_INDEX:
		ret.idFunc = idHashLeafIndex
	default:
		return nil, fmt.Errorf("unknown identity function: %v", idFuncType)
	}

	return &ret, nil
}

func ctBatchToTesseraBatch(b *scanner.EntryBatch) (startIndex uint64, data [][]byte) {
	startIndex = uint64(b.Start)

	for _, e := range b.Entries {
		// TODO: what about ExtraData?
		data = append(data, e.LeafInput)
	}

	return startIndex, data
}

// addSequencedLeaves adds a collection CT log entries into GCS Tessera log.
func (c *GCSTesseraClient) addSequencedLeaves(ctx context.Context, b *scanner.EntryBatch) error {
	startIndex, data := ctBatchToTesseraBatch(b)

	for i, entry := range data {
		if err := c.storage.AddSequenced(ctx, startIndex+uint64(i), entry); err != nil {
			return err
		}
	}

	return nil
}

// getNextAvailable returns the next unassigned sequence number.
func (c *GCSTesseraClient) getNextAvailable(ctx context.Context) (uint64, error) {
	// Call CurrentTree to load the checkpoint generation number into `storage`.
	// TODO: make this cleaner.
	_, _, err := c.storage.CurrentTree(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed read CurrentTree: %v", err)
	}

	return c.storage.NextAvailable(ctx)
}

func (c *GCSTesseraClient) getTreeID() int64 {
	return c.treeID
}
