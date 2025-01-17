package embedded

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

const (
	DiscoModeNone     = ""
	DiscoModeConsulKV = "consul-kv"
	DiscoModeEtcdKV   = "etcd-kv"
	DiscoModeDNS      = "dns"
	DiscoModeDNSSRV   = "dns-srv"

	HTTPAddrFlag    = "http-addr"
	HTTPAdvAddrFlag = "http-adv-addr"
	RaftAddrFlag    = "raft-addr"
	RaftAdvAddrFlag = "raft-adv-addr"
)

// DefaultConfig returns the default rqlite configuration.
func DefaultConfig() Config {
	return Config{
		HTTPAddr:                  "localhost:4001",
		NodeX509Cert:              "cert.pem",
		NodeX509Key:               "key.pem",
		RaftAddr:                  "localhost:4002",
		JoinAttempts:              5,
		JoinInterval:              3 * time.Second,
		BootstrapExpect:           0,
		BootstrapExpectTimeout:    120 * time.Second,
		BootstrapRetryInterval:    1 * time.Second,
		BootstrapRetryMaxInterval: 10 * time.Second,
		DiscoKey:                  "rqlite",
		Expvar:                    true,
		RaftHeartbeatTimeout:      time.Second,
		RaftElectionTimeout:       time.Second,
		RaftApplyTimeout:          10 * time.Second,
		RaftStepdownOnShutdown:    true,
		RaftSnapThreshold:         8192,
		RaftSnapInterval:          30 * time.Second,
		RaftLogLevel:              "INFO",
		ClusterConnectTimeout:     30 * time.Second,
		WriteQueueCap:             1024,
		WriteQueueBatchSz:         128,
		WriteQueueTimeout:         50 * time.Millisecond,
		CompressionSize:           150,
		CompressionBatch:          5,
	}
}

// Config represents the configuration as set by command-line flags.
// All variables will be set, unless explicit noted.
type Config struct {
	LoggerOutput io.Writer
	HcLogger     hclog.Logger

	// DataPath is path to node data. Has to be always set.
	DataPath string

	// HTTPAddr is the bind network address for the HTTP Server.
	// It never includes a trailing HTTP or HTTPS.
	HTTPAddr string

	// HTTPAdv is the advertised HTTP server network.
	HTTPAdv string

	// TLS1011 indicates whether the node should support deprecated
	// encryption standards.
	TLS1011 bool

	// AuthFile is the path to the authentication file. May not be set.
	AuthFile string `filepath:"true"`

	// AutoBackupFile is the path to the auto-backup file. May not be set.
	AutoBackupFile string `filepath:"true"`

	// AutoRestoreFile is the path to the auto-restore file. May not be set.
	AutoRestoreFile string `filepath:"true"`

	// HTTPx509CACert is the path to the CA certficate file for when this node verifies
	// other certificates for any HTTP communications. May not be set.
	HTTPx509CACert string `filepath:"true"`

	// HTTPx509Cert is the path to the X509 cert for the HTTP server. May not be set.
	HTTPx509Cert string `filepath:"true"`

	// HTTPx509Key is the path to the private key for the HTTP server. May not be set.
	HTTPx509Key string `filepath:"true"`

	// NoHTTPVerify disables checking other nodes' server HTTP X509 certs for validity.
	NoHTTPVerify bool

	// HTTPVerifyClient indicates whether the HTTP server should verify client certificates.
	HTTPVerifyClient bool

	// NodeEncrypt indicates whether node encryption should be enabled.
	NodeEncrypt bool

	// NodeX509CACert is the path to the CA certficate file for when this node verifies
	// other certificates for any inter-node communications. May not be set.
	NodeX509CACert string `filepath:"true"`

	// NodeX509Cert is the path to the X509 cert for the Raft server. May not be set.
	NodeX509Cert string `filepath:"true"`

	// NodeX509Key is the path to the X509 key for the Raft server. May not be set.
	NodeX509Key string `filepath:"true"`

	// NoNodeVerify disables checking other nodes' Node X509 certs for validity.
	NoNodeVerify bool

	// NodeVerifyClient indicates whether a node should verify client certificates from
	// other nodes.
	NodeVerifyClient bool

	// NodeID is the Raft ID for the node.
	NodeID string

	// RaftAddr is the bind network address for the Raft server.
	RaftAddr string

	// RaftAdv is the advertised Raft server address.
	RaftAdv string

	// JoinSrcIP sets the source IP address during Join request. May not be set.
	JoinSrcIP string

	// JoinAddr is the list addresses to use for a join attempt. Each address
	// will include the proto (HTTP or HTTPS) and will never include the node's
	// own HTTP server address. May not be set.
	JoinAddr string

	// JoinAs sets the user join attempts should be performed as. May not be set.
	JoinAs string

	// JoinAttempts is the number of times a node should attempt to join using a
	// given address.
	JoinAttempts int

	// JoinInterval is the time between retrying failed join operations.
	JoinInterval time.Duration

	// BootstrapExpect is the minimum number of nodes required for a bootstrap.
	BootstrapExpect int

	// BootstrapExpectTimeout is the maximum time a bootstrap operation can take.
	BootstrapExpectTimeout time.Duration

	// BootstrapRetryInterval is the retry interval between bootstrap attempts.
	// The interval is gets exponentially increased (including some jitter)
	// until it reaches BootstrapMaxRetryInterval.
	BootstrapRetryInterval time.Duration

	// BootstrapRetryMaxInterval is the maximum retry interval - see BootstrapRetryInterval.
	BootstrapRetryMaxInterval time.Duration

	// DisoMode sets the discovery mode. May not be set.
	DiscoMode string

	// DiscoKey sets the discovery prefix key.
	DiscoKey string

	// DiscoConfig sets the path to any discovery configuration file. May not be set.
	DiscoConfig string

	// Expvar enables go/expvar information. Defaults to true.
	Expvar bool

	// PprofEnabled enables Go PProf information. Defaults to true.
	PprofEnabled bool

	// OnDisk enables on-disk mode.
	OnDisk bool

	// OnDiskPath sets the path to the SQLite file. May not be set.
	OnDiskPath string

	// FKConstraints enables SQLite foreign key constraints.
	FKConstraints bool

	// Disable WAL mode if running in on-disk mode
	DisableWAL bool

	// RaftLogLevel sets the minimum logging level for the Raft subsystem.
	RaftLogLevel string

	// RaftNonVoter controls whether this node is a voting, read-only node.
	RaftNonVoter bool

	// RaftSnapThreshold is the number of outstanding log entries that trigger snapshot.
	RaftSnapThreshold uint64

	// RaftSnapInterval sets the threshold check interval.
	RaftSnapInterval time.Duration

	// RaftLeaderLeaseTimeout sets the leader lease timeout.
	RaftLeaderLeaseTimeout time.Duration

	// RaftHeartbeatTimeout sets the heartbeat timeout.
	RaftHeartbeatTimeout time.Duration

	// RaftElectionTimeout sets the election timeout.
	RaftElectionTimeout time.Duration

	// RaftApplyTimeout sets the Log-apply timeout.
	RaftApplyTimeout time.Duration

	// RaftShutdownOnRemove sets whether Raft should be shutdown if the node is removed
	RaftShutdownOnRemove bool

	// RaftClusterRemoveOnShutdown sets whether the node should remove itself from the cluster on shutdown
	RaftClusterRemoveOnShutdown bool

	// RaftStepdownOnShutdown sets whether Leadership should be relinquished on shutdown
	RaftStepdownOnShutdown bool

	// RaftNoFreelistSync disables syncing Raft database freelist to disk. When true,
	// it improves the database write performance under normal operation, but requires
	// a full database re-sync during recovery.
	RaftNoFreelistSync bool

	// RaftReapNodeTimeout sets the duration after which a non-reachable voting node is
	// reaped i.e. removed from the cluster.
	RaftReapNodeTimeout time.Duration

	// RaftReapReadOnlyNodeTimeout sets the duration after which a non-reachable non-voting node is
	// reaped i.e. removed from the cluster.
	RaftReapReadOnlyNodeTimeout time.Duration

	// ClusterConnectTimeout sets the timeout when initially connecting to another node in
	// the cluster, for non-Raft communications.
	ClusterConnectTimeout time.Duration

	// WriteQueueCap is the default capacity of Execute queues
	WriteQueueCap int

	// WriteQueueBatchSz is the default batch size for Execute queues
	WriteQueueBatchSz int

	// WriteQueueTimeout is the default time after which any data will be sent on
	// Execute queues, if a batch size has not been reached.
	WriteQueueTimeout time.Duration

	// WriteQueueTx controls whether writes from the queue are done within a transaction.
	WriteQueueTx bool

	// CompressionSize sets request query size for compression attempt
	CompressionSize int

	// CompressionBatch sets request batch threshold for compression attempt.
	CompressionBatch int

	// CPUProfile enables CPU profiling.
	CPUProfile string

	// MemProfile enables memory profiling.
	MemProfile string
}

// Validate checks the configuration for internal consistency, and activates
// important rqlite policies. It must be called at least once on a Config
// object before the Config object is used. It is OK to call more than
// once.
func (c *Config) Validate() error {
	if c.OnDiskPath != "" && !c.OnDisk {
		return errors.New("-on-disk-path is set, but -on-disk is not")
	}

	dataPath, err := filepath.Abs(c.DataPath)
	if err != nil {
		return fmt.Errorf("failed to determine absolute data path: %s", err.Error())
	}
	c.DataPath = dataPath

	err = c.CheckFilePaths()
	if err != nil {
		return err
	}

	if !bothUnsetSet(c.HTTPx509Cert, c.HTTPx509Key) {
		return fmt.Errorf("either both -%s and -%s must be set, or neither", "HTTPx509Cert", "HTTPx509Key")
	}
	if !bothUnsetSet(c.NodeX509Cert, c.NodeX509Key) {
		return fmt.Errorf("either both -%s and -%s must be set, or neither", "NodeX509Cert", "NodeX509Key")
	}

	if c.RaftAddr == c.HTTPAddr {
		return errors.New("HTTP and Raft addresses must differ")
	}

	// Enforce policies regarding addresses
	if c.RaftAdv == "" {
		c.RaftAdv = c.RaftAddr
	}
	if c.HTTPAdv == "" {
		c.HTTPAdv = c.HTTPAddr
	}

	// Node ID policy
	if c.NodeID == "" {
		c.NodeID = c.RaftAdv
	}

	// Perform some address validity checks.
	if strings.HasPrefix(strings.ToLower(c.HTTPAddr), "http") ||
		strings.HasPrefix(strings.ToLower(c.HTTPAdv), "http") {
		return errors.New("HTTP options should not include protocol (http:// or https://)")
	}
	if _, _, err := net.SplitHostPort(c.HTTPAddr); err != nil {
		return errors.New("HTTP bind address not valid")
	}

	hadv, _, err := net.SplitHostPort(c.HTTPAdv)
	if err != nil {
		return errors.New("HTTP advertised HTTP address not valid")
	}
	if addr := net.ParseIP(hadv); addr != nil && addr.IsUnspecified() {
		return fmt.Errorf("advertised HTTP address is not routable (%s), specify it via -%s or -%s",
			hadv, HTTPAddrFlag, HTTPAdvAddrFlag)
	}

	if _, _, err := net.SplitHostPort(c.RaftAddr); err != nil {
		return errors.New("raft bind address not valid")
	}

	radv, _, err := net.SplitHostPort(c.RaftAdv)
	if err != nil {
		return errors.New("raft advertised address not valid")
	}
	if addr := net.ParseIP(radv); addr != nil && addr.IsUnspecified() {
		return fmt.Errorf("advertised Raft address is not routable (%s), specify it via -%s or -%s",
			radv, RaftAddrFlag, RaftAdvAddrFlag)
	}

	if c.RaftAdv == c.HTTPAdv {
		return errors.New("advertised HTTP and Raft addresses must differ")
	}

	// Enforce bootstrapping policies
	if c.BootstrapExpect > 0 && c.RaftNonVoter {
		return errors.New("bootstrapping only applicable to voting nodes")
	}

	// Join parameters OK?
	if c.JoinAddr != "" {
		addrs := strings.Split(c.JoinAddr, ",")
		for i := range addrs {
			u, err := url.Parse(addrs[i])
			if err != nil {
				return fmt.Errorf("%s is an invalid join adddress", addrs[i])
			}
			if c.BootstrapExpect == 0 {
				if u.Host == c.HTTPAdv || addrs[i] == c.HTTPAddr {
					return errors.New("node cannot join with itself unless bootstrapping")
				}
				if c.AutoRestoreFile != "" {
					return errors.New("auto-restoring cannot be used when joining a cluster")
				}
			}
		}
	}
	if c.JoinSrcIP != "" && net.ParseIP(c.JoinSrcIP) == nil {
		return fmt.Errorf("invalid join source IP address: %s", c.JoinSrcIP)
	}

	// Valid disco mode?
	switch c.DiscoMode {
	case "":
	case DiscoModeEtcdKV, DiscoModeConsulKV:
		if c.BootstrapExpect > 0 {
			return fmt.Errorf("bootstrapping not applicable when using %s", c.DiscoMode)
		}
	case DiscoModeDNS, DiscoModeDNSSRV:
		if c.BootstrapExpect == 0 {
			return fmt.Errorf("bootstrap-expect value required when using %s", c.DiscoMode)
		}
	default:
		return fmt.Errorf("disco mode must be one of %s, %s, %s, or %s",
			DiscoModeConsulKV, DiscoModeEtcdKV, DiscoModeDNS, DiscoModeDNSSRV)
	}

	return nil
}

// JoinAddresses returns the join addresses set at the command line. Returns nil
// if no join addresses were set.
func (c *Config) JoinAddresses() []string {
	if c.JoinAddr == "" {
		return nil
	}
	return strings.Split(c.JoinAddr, ",")
}

// HTTPURL returns the fully-formed, advertised HTTP API address for this config, including
// protocol, host and port.
func (c *Config) HTTPURL() string {
	apiProto := "http"
	if c.HTTPx509Cert != "" {
		apiProto = "https"
	}
	return fmt.Sprintf("%s://%s", apiProto, c.HTTPAdv)
}

// DiscoConfigReader returns a ReadCloser providing access to the Disco config.
// The caller must call close on the ReadCloser when finished with it. If no
// config was supplied, it returns nil.
func (c *Config) DiscoConfigReader() io.ReadCloser {
	var rc io.ReadCloser
	if c.DiscoConfig == "" {
		return nil
	}

	// Open config file. If opening fails, assume string is the literal config.
	cfgFile, err := os.Open(c.DiscoConfig)
	if err != nil {
		rc = io.NopCloser(bytes.NewReader([]byte(c.DiscoConfig)))
	} else {
		rc = cfgFile
	}
	return rc
}

// CheckFilePaths checks that all file paths in the config exist.
// Empy filepaths are ignored.
func (c *Config) CheckFilePaths() error {
	v := reflect.ValueOf(c).Elem()

	// Iterate through the fields of the struct
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		fieldValue := v.Field(i)

		if fieldValue.Kind() != reflect.String {
			continue
		}

		if tagValue, ok := field.Tag.Lookup("filepath"); ok && tagValue == "true" {
			filePath := fieldValue.String()
			if filePath == "" {
				continue
			}
			_, err := os.Stat(filePath)
			if os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist", filePath)
			}
		}
	}
	return nil
}

// BuildInfo is build information for display at command line.
type BuildInfo struct {
	Version       string
	Commit        string
	Branch        string
	SQLiteVersion string
}

// bothUnsetSet returns true if both a and b are unset, or both are set.
func bothUnsetSet(a, b string) bool {
	return (a == "" && b == "") || (a != "" && b != "")
}
