package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/AlCutter/betty/storage/gcs"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	leavesPerSecond = flag.Int64("leaves_per_second", 10, "How many leaves to generate per second")
	leafSize        = flag.Int("leaf_size", 1024, "Leaf size in bytes")
	numWriters      = flag.Int("num_writers", 100, "Number of parallel writers")
	batchSize       = flag.Int("batch_size", 1, "Size of batch before flushing")
	batchMaxAge     = flag.Duration("batch_max_age", 100*time.Millisecond, "Max age for batch entries before flushing")

	project = flag.String("project", os.Getenv("GOOGLE_CLOUD_PROJECT"), "GCP Project, take from env if unset")
	bucket  = flag.String("bucket", "", "Bucket to use for storing log")

	listen = flag.String("listen", ":2024", "Address:port to listen on")

	signer   = flag.String("log_signer", "PRIVATE+KEY+Test-Betty+df84580a+Afge8kCzBXU7jb3cV2Q363oNXCufJ6u9mjOY1BGRY9E2", "Log signer")
	verifier = flag.String("log_verifier", "Test-Betty+df84580a+AQQASqPUZoIHcJAF5mBOryctwFdTV1E0GRY4kEAtTzwB", "log verifier")
)

// Storage defines the explicit interface that storage implementations must implement for the HTTP handler here.
// In addition, they'll need to implement the IntegrateStorage methods in log/writer/integrate.go too.
type Storage interface {
	// Sequence assigns the provided leaf data to an index in the log, returning
	// that index once it's durably committed.
	// Implementations are expected to integrate these new entries in a "timely" fashion.
	Sequence(context.Context, []byte) (uint64, error)
	CurrentTree(context.Context) (uint64, []byte, error)
	NewTree(context.Context, uint64, []byte) error
}

type latency struct {
	sync.Mutex
	total time.Duration
	n     int
	min   time.Duration
	max   time.Duration
}

func (l *latency) Add(d time.Duration) {
	l.Lock()
	defer l.Unlock()
	l.total += d
	l.n++
	if d < l.min {
		l.min = d
	}
	if d > l.max {
		l.max = d
	}
}

func (l *latency) String() string {
	l.Lock()
	defer l.Unlock()
	if l.n == 0 {
		return "--"
	}
	return fmt.Sprintf("[Mean: %v Min: %v Max %v]", l.total/time.Duration(l.n), l.min, l.max)
}

func keysFromFlag() (note.Signer, note.Verifier) {
	sKey, err := note.NewSigner(*signer)
	if err != nil {
		klog.Exitf("Invalid signing key: %v", err)
	}
	vKey, err := note.NewVerifier(*verifier)
	if err != nil {
		klog.Exitf("Invalid verifier key: %v", err)
	}
	return sKey, vKey
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	ctx := context.Background()

	opts := gcs.StorageOpts{
		ProjectID:       *project,
		Bucket:          *bucket,
		EntryBundleSize: *batchSize,
	}
	sKey, vKey := keysFromFlag()
	var s Storage = gcs.New(ctx, opts, *batchMaxAge, vKey, sKey)

	if _, _, err := s.CurrentTree(ctx); err != nil {
		klog.Infof("ct: %v", err)
		if err := s.NewTree(ctx, 0, []byte("Empty")); err != nil {
			klog.Exitf("Failed to initialise log: %v", err)
		}
	}
	l := &latency{}

	http.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		n := time.Now()
		defer func() { l.Add(time.Since(n)) }()

		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		idx, err := s.Sequence(ctx, b)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Failed to sequence entry: %v", err)))
			return
		}
		w.Write([]byte(fmt.Sprintf("%d\n", idx)))
	})
	/*
		fs := http.FileServer(http.Dir(*path))
		http.Handle("GET /", fs)
	*/

	go printStats(ctx, s.CurrentTree, l)
	if err := http.ListenAndServe(*listen, http.DefaultServeMux); err != nil {
		klog.Exitf("ListenAndServe: %v", err)
	}
}

func printStats(ctx context.Context, s func(ctx context.Context) (uint64, []byte, error), l *latency) {
	interval := time.Second
	var lastSize uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			size, _, err := s(ctx)
			if err != nil {
				klog.Errorf("Failed to get checkpoint: %v", err)
				continue
			}
			if lastSize > 0 {
				added := size - lastSize
				klog.Infof("CP size %d (+%d); Latency: %v", size, added, l.String())
			}
			lastSize = size
		}
	}
}
