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

// Migrillian tool transfers certs from CT logs to Trillian pre-ordered logs in
// the same order.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"

	"github.com/AlCutter/betty/migrillian/core"
	"github.com/AlCutter/betty/storage/gcs"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/util"
	"github.com/google/trillian/util/election2"
	etcdelect "github.com/google/trillian/util/election2/etcd"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Migrillian flags
	cfgPath = flag.String("config", "config/config.textproto", "Path to migration config file")

	forceMaster   = flag.Bool("force_master", false, "If true, assume master for all logs")
	etcdServers   = flag.String("etcd_servers", "", "A comma-separated list of etcd servers; no etcd registration if empty")
	lockDir       = flag.String("lock_file_path", "/migrillian/master", "etcd lock file directory path")
	electionDelay = flag.Duration("election_delay", 0, "Max random pause before participating in master election")

	metricsEndpoint = flag.String("metrics_endpoint", "localhost:8099", "Endpoint for serving metrics")

	maxIdleConnsPerHost = flag.Int("max_idle_conns_per_host", 10, "Max idle HTTP connections per host (0 = DefaultMaxIdleConnsPerHost)")
	maxIdleConns        = flag.Int("max_idle_conns", 100, "Max number of idle HTTP connections across all hosts (0 = unlimited)")

	// GCS Tessera flags
	bundleSize    = flag.Int("bundle_size", 256, "Size of leaf bundle")
	batchMaxSize  = flag.Int("batch_max_size", 256, "Size of batch before flushing")
	batchMaxAge   = flag.Duration("batch_max_age", 100*time.Millisecond, "Max age for batch entries before flushing")
	pushBackLimit = flag.Uint64("pushback", 1000, "Number of inflight requests after which further additions will be refused")

	project = flag.String("project", "", "GCP Project, take from env if unset")
	bucket  = flag.String("bucket", "", "Bucket to use for storing log")
	dbConn  = flag.String("db_conn", "", "CloudSQL DB URL")
	dbUser  = flag.String("db_user", "", "")
	dbPass  = flag.String("db_pass", "", "")
	dbName  = flag.String("db_name", "", "")

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
	AddSequenced(context.Context, uint64, []byte) error
	NextAvailable(context.Context) (uint64, error)
	SequenceForLeafHash(context.Context, []byte) (uint64, error)
	CurrentTree(context.Context) (uint64, []byte, error)
	NewTree(context.Context, uint64, []byte) error
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
	klog.CopyStandardLogTo("WARNING")
	defer klog.Flush()

	cfg, err := getConfig()
	if err != nil {
		klog.Exitf("Failed to load MigrillianConfig: %v", err)
	}
	if err := core.ValidateConfig(cfg); err != nil {
		klog.Exitf("Failed to validate MigrillianConfig: %v", err)
	}

	httpClient := getHTTPClient()
	mf := prometheus.MetricFactory{}
	ef, closeFn := getElectionFactory()
	defer closeFn()

	ctx := context.Background()
	opts := gcs.StorageOpts{
		ProjectID:       *project,
		Bucket:          *bucket,
		EntryBundleSize: *bundleSize,
		PushBackLimit:   *pushBackLimit,
		DBConn:          *dbConn,
		DBUser:          *dbUser,
		DBPass:          *dbPass,
		DBName:          *dbName,
	}
	sKey, vKey := keysFromFlag()
	gcsStorage := gcs.NewPreordered(ctx, opts, *batchMaxSize, *batchMaxAge, vKey, sKey)
	var s Storage = gcsStorage

	if _, _, err := s.CurrentTree(ctx); err != nil {
		klog.Infof("ct: %v", err)
		if err := s.NewTree(ctx, 0, []byte("Empty")); err != nil {
			klog.Exitf("Failed to initialise log: %v", err)
		}
	}

	var ctrls []*core.Controller
	for _, mc := range cfg.MigrationConfigs.Config {
		ctrl, err := getController(ctx, mc, httpClient, mf, ef, s)
		if err != nil {
			klog.Exitf("Failed to create Controller for %q: %v", mc.SourceUri, err)
		}
		ctrls = append(ctrls, ctrl)
	}

	// Handle metrics on the DefaultServeMux.
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(*metricsEndpoint, nil)
		klog.Fatalf("http.ListenAndServe(): %v", err)
	}()

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go util.AwaitSignal(cctx, cancel)

	go printStats(ctx, s.CurrentTree)
	core.RunMigration(cctx, ctrls)
}

// getController creates a single log migration Controller.
func getController(
	ctx context.Context,
	cfg *configpb.MigrationConfig,
	httpClient *http.Client,
	mf monitoring.MetricFactory,
	ef election2.Factory,
	s Storage,
) (*core.Controller, error) {
	ctOpts := jsonclient.Options{PublicKeyDER: cfg.PublicKey.Der, UserAgent: "ct-go-migrillian/1.0"}
	ctClient, err := client.New(cfg.SourceUri, httpClient, ctOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create CT client: %v", err)
	}
	destLogClient, err := newGCSTesseraLogClient(cfg, s)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCSTesseraLogClient: %v", err)
	}

	opts := core.OptionsFromConfig(cfg)
	opts.StartDelay = *electionDelay
	return core.NewController(opts, ctClient, destLogClient, ef, mf), nil
}

// getConfig returns MigrillianConfig loaded from the file specified in flags.
func getConfig() (*configpb.MigrillianConfig, error) {
	if len(*cfgPath) == 0 {
		return nil, errors.New("config file not specified")
	}
	cfg, err := core.LoadConfigFromFile(*cfgPath)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// getHTTPClient returns an HTTP client created from flags.
func getHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		DisableKeepAlives:     false,
		MaxIdleConns:          *maxIdleConns,
		MaxIdleConnsPerHost:   *maxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// TODO(pavelkalinnikov): Make the timeout tunable.
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}

// newGCSTesseraLogClient creates a PreorderedLogClient for the specified tree.
func newGCSTesseraLogClient(
	cfg *configpb.MigrationConfig,
	s Storage) (*core.GCSTesseraClient, error) {
	return core.NewGCSTesseraClient(cfg.LogId, cfg.IdentityFunction, s)
}

// getElectionFactory returns an election factory based on flags, and a
// function which releases the resources associated with the factory.
func getElectionFactory() (election2.Factory, func()) {
	if *forceMaster {
		klog.Warning("Acting as master for all logs")
		return election2.NoopFactory{}, func() {}
	}
	if len(*etcdServers) == 0 {
		klog.Exit("Either --force_master or --etcd_servers must be supplied")
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   strings.Split(*etcdServers, ","),
		DialTimeout: 5 * time.Second,
	})
	if err != nil || cli == nil {
		klog.Exitf("Failed to create etcd client: %v", err)
	}
	closeFn := func() {
		if err := cli.Close(); err != nil {
			klog.Warningf("etcd client Close(): %v", err)
		}
	}

	hostname, _ := os.Hostname()
	instanceID := fmt.Sprintf("%s.%d", hostname, os.Getpid())
	factory := etcdelect.NewFactory(instanceID, cli, *lockDir)

	return factory, closeFn
}

func printStats(ctx context.Context, s func(ctx context.Context) (uint64, []byte, error)) {
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
				klog.Infof("CP size %d (+%d)", size, added)
			}
			lastSize = size
		}
	}
}
