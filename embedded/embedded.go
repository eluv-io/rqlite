package embedded

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	golog "log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pkg/errors"
	"github.com/rqlite/rqlite-disco-clients/consul"
	"github.com/rqlite/rqlite-disco-clients/dns"
	"github.com/rqlite/rqlite-disco-clients/dnssrv"
	"github.com/rqlite/rqlite-disco-clients/etcd"
	"github.com/rqlite/rqlite/v7/rtls"

	"github.com/rqlite/rqlite/v7/auth"
	"github.com/rqlite/rqlite/v7/cluster"
	"github.com/rqlite/rqlite/v7/cmd"
	"github.com/rqlite/rqlite/v7/disco"
	httpd "github.com/rqlite/rqlite/v7/http"
	"github.com/rqlite/rqlite/v7/store"
	"github.com/rqlite/rqlite/v7/tcp"
)

const (
	name = "embedded rqlite daemon"
)

var log = golog.Default()

type Embedded struct {
	Config       *Config
	raftListener net.Listener
	cluster      *cluster.Service
	store        *store.Store
	startFn      func() error
	httpdService *httpd.Service
}

// Start starts the node by joining it to the cluster.
func (emb *Embedded) Start() (err error) {
	return emb.startFn()
}

// Shutdown stops the daemon gracefully.
func (emb *Embedded) Shutdown() (err error) {
	if emb.Config.RaftStepdownOnShutdown {
		if emb.store.IsLeader() {
			// Don't log a confusing message if not (probably) Leader
			log.Printf("stepping down as Leader before shutdown")
		}
		// Perform a stepdown, ignore any errors.
		_ = emb.store.Stepdown(true)
	}

	if emb.httpdService != nil {
		emb.httpdService.Close()
	}
	if emb.store != nil {
		err = emb.store.Close(true)
	}
	if emb.cluster != nil {
		_ = emb.cluster.Close()
	}
	if emb.raftListener != nil {
		_ = emb.raftListener.Close()
	}
	return err
}

// New creates a new embedded daemon
func New(config Config) (*Embedded, error) {
	var err error
	cfg := &config

	log = adaptLogger(cfg, golog.New(os.Stderr, "embedded", 0))

	err = cfg.Validate()
	if err != nil {
		return nil, errors.WithMessage(err, "invalid config")
	}

	emb := &Embedded{
		Config: cfg,
	}

	defer func() {
		if err != nil {
			_ = emb.Shutdown()
		}
	}()

	// Create inter-node network mux and configure.
	emb.raftListener, err = net.Listen("tcp", cfg.RaftAddr)
	if err != nil {
		return nil, errors.WithMessagef(err, "create raft listener at [%s]", cfg.RaftAddr)
	}
	mux, err := startNodeMux(cfg, emb.raftListener)
	if err != nil {
		return nil, errors.WithMessage(err, "start node mux")
	}
	raftTn := mux.Listen(cluster.MuxRaftHeader)
	log.Printf("Raft TCP mux Listener registered with %d", cluster.MuxRaftHeader)

	// Create the store.
	emb.store, err = createStore(cfg, raftTn)
	if err != nil {
		return nil, errors.WithMessage(err, "create store")
	}

	// Get any credential store.
	credStr, err := credentialStore(cfg)
	if err != nil {
		return nil, errors.WithMessage(err, "create credential store")
	}

	// Create cluster service now, so nodes will be able to learn information about each other.
	emb.cluster, err = clusterService(cfg, mux.Listen(cluster.MuxClusterHeader), emb.store, emb.store, credStr)
	if err != nil {
		return nil, errors.WithMessage(err, "create cluster service")
	}
	log.Printf("cluster TCP mux Listener registered with %d", cluster.MuxClusterHeader)

	// Start the HTTP API server.
	var dialerTLSConfig *tls.Config
	if cfg.NodeX509Cert != "" || cfg.NodeX509CACert != "" {
		dialerTLSConfig, err = rtls.CreateClientConfig(cfg.NodeX509Cert, cfg.NodeX509Key,
			cfg.NodeX509CACert, cfg.NoNodeVerify, cfg.TLS1011)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config for cluster dialer: %s", err.Error())
		}
	}
	clstrDialer := tcp.NewDialer(cluster.MuxClusterHeader, dialerTLSConfig)
	clstrClient := cluster.NewClient(clstrDialer, cfg.ClusterConnectTimeout)
	if err = clstrClient.SetLocal(cfg.RaftAdv, emb.cluster); err != nil {
		return nil, errors.WithMessage(err, "set cluster client local parameters")
	}
	emb.httpdService, err = startHTTPService(cfg, emb.store, clstrClient, credStr)
	if err != nil {
		return nil, errors.WithMessage(err, "start HTTP server")
	}
	log.Printf("HTTP server started")

	// Now, open store.
	if err := emb.store.Open(); err != nil {
		return nil, errors.WithMessage(err, "open store")
	}

	// Register remaining status providers.
	_ = emb.httpdService.RegisterStatus("cluster", emb.cluster)

	tlsConfig := tls.Config{InsecureSkipVerify: cfg.NoHTTPVerify}
	if cfg.HTTPx509CACert != "" {
		asn1Data, err := os.ReadFile(cfg.HTTPx509CACert)
		if err != nil {
			return nil, errors.WithMessagef(err, "reading ca cert [%s]", cfg.HTTPx509CACert)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		ok := tlsConfig.RootCAs.AppendCertsFromPEM(asn1Data)
		if !ok {
			return nil, fmt.Errorf("failed to parse root CA certificate(s) in %q", cfg.HTTPx509CACert)
		}
	}

	// Create the cluster!
	nodes, err := emb.store.Nodes()
	if err != nil {
		return nil, errors.WithMessage(err, "get nodes")
	}
	emb.startFn, err = createCluster(cfg, &tlsConfig, len(nodes) > 0, emb.store, emb.httpdService, credStr)
	if err != nil {
		return nil, errors.WithMessage(err, "create cluster")
	}

	return emb, nil
}

func createStore(cfg *Config, ln *tcp.Layer) (*store.Store, error) {
	dataPath, err := filepath.Abs(cfg.DataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to determine absolute data path: %s", err.Error())
	}
	dbConf := store.NewDBConfig(!cfg.OnDisk)
	dbConf.OnDiskPath = cfg.OnDiskPath
	dbConf.FKConstraints = cfg.FKConstraints

	str := store.New(ln, &store.Config{
		DBConf: dbConf,
		Dir:    cfg.DataPath,
		ID:     cfg.NodeID,
		Logger: adaptLogger(cfg, golog.New(os.Stderr, "[store] ", golog.LstdFlags)),
	})

	// Set optional parameters on store.
	str.StartupOnDisk = cfg.OnDiskStartup
	str.SetRequestCompression(cfg.CompressionBatch, cfg.CompressionSize)
	str.RaftLogLevel = cfg.RaftLogLevel
	str.RaftLogger = cfg.HcLogger
	str.NoFreeListSync = cfg.RaftNoFreelistSync
	str.ShutdownOnRemove = cfg.RaftShutdownOnRemove
	str.SnapshotThreshold = cfg.RaftSnapThreshold
	str.SnapshotInterval = cfg.RaftSnapInterval
	str.LeaderLeaseTimeout = cfg.RaftLeaderLeaseTimeout
	str.HeartbeatTimeout = cfg.RaftHeartbeatTimeout
	str.ElectionTimeout = cfg.RaftElectionTimeout
	str.ApplyTimeout = cfg.RaftApplyTimeout
	str.BootstrapExpect = cfg.BootstrapExpect
	str.ReapTimeout = cfg.RaftReapNodeTimeout
	str.ReapReadOnlyTimeout = cfg.RaftReapReadOnlyNodeTimeout

	isNew := store.IsNewNode(dataPath)
	if isNew {
		log.Printf("no preexisting node state detected in %s, node may be bootstrapping", dataPath)
	} else {
		log.Printf("preexisting node state detected in %s", dataPath)
	}

	return str, nil
}

func createDiscoService(cfg *Config, str *store.Store) (*disco.Service, error) {
	var c disco.Client
	var err error
	var rc io.ReadCloser

	rc = cfg.DiscoConfigReader()
	defer func() {
		if rc != nil {
			_ = rc.Close()
		}
	}()
	if cfg.DiscoMode == DiscoModeConsulKV {
		var consulCfg *consul.Config
		consulCfg, err = consul.NewConfigFromReader(rc)
		if err != nil {
			return nil, fmt.Errorf("create Consul config: %s", err.Error())
		}

		c, err = consul.New(cfg.DiscoKey, consulCfg)
		if err != nil {
			return nil, fmt.Errorf("create Consul client: %s", err.Error())
		}
	} else if cfg.DiscoMode == DiscoModeEtcdKV {
		var etcdCfg *etcd.Config
		etcdCfg, err = etcd.NewConfigFromReader(rc)
		if err != nil {
			return nil, fmt.Errorf("create etcd config: %s", err.Error())
		}

		c, err = etcd.New(cfg.DiscoKey, etcdCfg)
		if err != nil {
			return nil, fmt.Errorf("create etcd client: %s", err.Error())
		}
	} else {
		return nil, fmt.Errorf("invalid disco service: %s", cfg.DiscoMode)
	}

	return disco.NewService(c, str), nil
}

func startHTTPService(cfg *Config, str *store.Store, cltr *cluster.Client, credStr *auth.CredentialsStore) (*httpd.Service, error) {
	// Create HTTP server and load authentication information if required.
	var s *httpd.Service
	if credStr != nil {
		s = httpd.New(cfg.HTTPAddr, str, cltr, credStr)
	} else {
		s = httpd.New(cfg.HTTPAddr, str, cltr, nil)
	}

	adaptLogger(cfg, s.Logger())
	s.CertFile = cfg.HTTPx509Cert
	s.KeyFile = cfg.HTTPx509Key
	s.TLS1011 = cfg.TLS1011
	s.Expvar = cfg.Expvar
	s.Pprof = cfg.PprofEnabled
	s.DefaultQueueCap = cfg.WriteQueueCap
	s.DefaultQueueBatchSz = cfg.WriteQueueBatchSz
	s.DefaultQueueTimeout = cfg.WriteQueueTimeout
	s.DefaultQueueTx = cfg.WriteQueueTx
	s.BuildInfo = map[string]interface{}{
		"commit":     cmd.Commit,
		"branch":     cmd.Branch,
		"version":    cmd.Version,
		"compiler":   runtime.Compiler,
		"build_time": cmd.Buildtime,
	}
	return s, s.Start()
}

// startNodeMux starts the TCP mux on the given listener, which should be already
// bound to the relevant interface.
func startNodeMux(cfg *Config, ln net.Listener) (*tcp.Mux, error) {
	var err error
	adv := tcp.NameAddress{
		Address: cfg.RaftAdv,
	}

	var mux *tcp.Mux
	if cfg.NodeEncrypt {
		log.Printf("enabling node-to-node encryption with cert: %s, key: %s", cfg.NodeX509Cert, cfg.NodeX509Key)
		mux, err = tcp.NewTLSMux(ln, adv, cfg.NodeX509Cert, cfg.NodeX509Key, cfg.NodeX509CACert, cfg.NoNodeVerify, cfg.NodeVerifyClient)
	} else {
		mux, err = tcp.NewMux(ln, adv)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create node-to-node mux: %s", err.Error())
	}
	adaptLogger(cfg, mux.Logger)
	go mux.Serve()

	return mux, nil
}

func adaptLogger(cfg *Config, logger *golog.Logger) *golog.Logger {
	if cfg.LoggerOutput != nil {
		logger.SetOutput(cfg.LoggerOutput)
		logger.SetFlags(0)
	}
	return logger
}

func credentialStore(cfg *Config) (*auth.CredentialsStore, error) {
	if cfg.AuthFile == "" {
		return nil, nil
	}

	f, err := os.Open(cfg.AuthFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open authentication file %s: %s", cfg.AuthFile, err.Error())
	}

	cs := auth.NewCredentialsStore()
	if err = cs.Load(f); err != nil {
		return nil, fmt.Errorf("failed to load credential store: %s", err.Error())
	}
	return cs, nil
}

func clusterService(cfg *Config, tn cluster.Transport, db cluster.Database, mgr cluster.Manager, credStr *auth.CredentialsStore) (*cluster.Service, error) {
	c := cluster.New(tn, db, mgr, credStr)
	adaptLogger(cfg, c.Logger())
	c.SetAPIAddr(cfg.HTTPAdv)
	c.EnableHTTPS(cfg.HTTPx509Cert != "" && cfg.HTTPx509Key != "") // Conditions met for an HTTPS API

	if err := c.Open(); err != nil {
		return nil, err
	}
	return c, nil
}

func createCluster(
	cfg *Config,
	tlsConfig *tls.Config,
	hasPeers bool,
	str *store.Store,
	httpServ *httpd.Service,
	credStr *auth.CredentialsStore) (func() error, error) {

	noop := func() error { return nil }

	joins := cfg.JoinAddresses()
	if joins == nil && cfg.DiscoMode == "" && !hasPeers {
		// Brand new node, told to bootstrap itself. So do it.
		log.Println("bootstraping single new node")
		if err := str.Bootstrap(store.NewServer(str.ID(), cfg.RaftAdv, true)); err != nil {
			return noop, fmt.Errorf("failed to bootstrap single new node: %s", err.Error())
		}
		return noop, nil
	}

	// Prepare the Joiner
	joiner := cluster.NewJoiner(cfg.JoinSrcIP, cfg.JoinAttempts, cfg.JoinInterval, tlsConfig)
	adaptLogger(cfg, joiner.Logger())
	if cfg.JoinAs != "" {
		pw, ok := credStr.Password(cfg.JoinAs)
		if !ok {
			return noop, fmt.Errorf("user %s does not exist in credential store", cfg.JoinAs)
		}
		joiner.SetBasicAuth(cfg.JoinAs, pw)
	}

	// Prepare definition of being part of a cluster.
	isClustered := func() bool {
		leader, _ := str.LeaderAddr()
		return leader != ""
	}

	if joins != nil && cfg.BootstrapExpect == 0 {
		// Explicit join operation requested, so do it.
		j, err := joiner.Do(joins, str.ID(), cfg.RaftAdv, !cfg.RaftNonVoter)
		if err != nil {
			return noop, fmt.Errorf("failed to join cluster: %s", err.Error())
		}
		log.Println("successfully joined cluster at", j)
		return noop, nil
	}

	if joins != nil && cfg.BootstrapExpect > 0 {
		if hasPeers {
			log.Println("preexisting node configuration detected, ignoring bootstrap request")
			return noop, nil
		}

		// Bootstrap with explicit join addresses requests.
		bs := cluster.NewBootstrapper(cluster.NewAddressProviderString(joins), tlsConfig)
		adaptLogger(cfg, bs.Logger())
		adaptLogger(cfg, bs.JoinerLogger())
		bs.Interval = cfg.BootstrapRetryInterval
		bs.MaxInterval = cfg.BootstrapRetryMaxInterval
		if cfg.JoinAs != "" {
			pw, ok := credStr.Password(cfg.JoinAs)
			if !ok {
				return noop, fmt.Errorf("user %s does not exist in credential store", cfg.JoinAs)
			}
			bs.SetBasicAuth(cfg.JoinAs, pw)
		}
		return func() error {
			return bs.Boot(str.ID(), cfg.RaftAdv, isClustered, cfg.BootstrapExpectTimeout)
		}, nil
	}

	if cfg.DiscoMode == "" {
		// No more clustering techniques to try. Node will just sit, probably using
		// existing Raft state.
		return noop, nil
	}

	log.Printf("discovery mode: %s", cfg.DiscoMode)
	switch cfg.DiscoMode {
	case DiscoModeDNS, DiscoModeDNSSRV:
		if hasPeers {
			log.Printf("preexisting node configuration detected, ignoring %s", cfg.DiscoMode)
			return noop, nil
		}
		rc := cfg.DiscoConfigReader()
		defer func() {
			if rc != nil {
				_ = rc.Close()
			}
		}()

		var provider interface {
			cluster.AddressProvider
			httpd.StatusReporter
		}
		if cfg.DiscoMode == DiscoModeDNS {
			dnsCfg, err := dns.NewConfigFromReader(rc)
			if err != nil {
				return noop, fmt.Errorf("error reading DNS configuration: %s", err.Error())
			}
			provider = dns.New(dnsCfg)

		} else {
			dnssrvCfg, err := dnssrv.NewConfigFromReader(rc)
			if err != nil {
				return noop, fmt.Errorf("error reading DNS configuration: %s", err.Error())
			}
			provider = dnssrv.New(dnssrvCfg)
		}

		bs := cluster.NewBootstrapper(provider, tlsConfig)
		adaptLogger(cfg, bs.Logger())
		bs.Interval = cfg.BootstrapRetryInterval
		bs.MaxInterval = cfg.BootstrapRetryMaxInterval
		if cfg.JoinAs != "" {
			pw, ok := credStr.Password(cfg.JoinAs)
			if !ok {
				return noop, fmt.Errorf("user %s does not exist in credential store", cfg.JoinAs)
			}
			bs.SetBasicAuth(cfg.JoinAs, pw)
		}
		err := httpServ.RegisterStatus("disco", provider)
		if err != nil {
			return noop, fmt.Errorf("failed to register status provider 'disco': %s", err.Error())
		}
		return func() error {
			return bs.Boot(str.ID(), cfg.RaftAdv, isClustered, cfg.BootstrapExpectTimeout)
		}, nil

	case DiscoModeEtcdKV, DiscoModeConsulKV:
		discoService, err := createDiscoService(cfg, str)
		if err != nil {
			return noop, fmt.Errorf("failed to start discovery service: %s", err.Error())
		}

		if !hasPeers {
			log.Println("no preexisting nodes, registering with discovery service")

			leader, addr, err := discoService.Register(str.ID(), cfg.HTTPURL(), cfg.RaftAdv)
			if err != nil {
				return noop, fmt.Errorf("failed to register with discovery service: %s", err.Error())
			}
			if leader {
				log.Println("node registered as leader using discovery service")
				if err = str.Bootstrap(store.NewServer(str.ID(), str.Addr(), true)); err != nil {
					return noop, fmt.Errorf("failed to bootstrap single new node: %s", err.Error())
				}
			} else {
				for {
					log.Printf("discovery service returned %s as join address", addr)
					if j, err := joiner.Do([]string{addr}, str.ID(), cfg.RaftAdv, !cfg.RaftNonVoter); err != nil {
						log.Printf("failed to join cluster at %s: %s", addr, err.Error())

						time.Sleep(time.Second)
						_, addr, err = discoService.Register(str.ID(), cfg.HTTPURL(), cfg.RaftAdv)
						if err != nil {
							log.Printf("failed to get updated leader: %s", err.Error())
						}
						continue
					} else {
						log.Println("successfully joined cluster at", j)
						break
					}
				}
			}
		} else {
			log.Println("preexisting node configuration detected, not registering with discovery service")
		}
		go discoService.StartReporting(cfg.NodeID, cfg.HTTPURL(), cfg.RaftAdv)
		httpServ.RegisterStatus("disco", discoService)

	default:
		return noop, fmt.Errorf("invalid disco mode %s", cfg.DiscoMode)
	}
	return noop, nil
}
