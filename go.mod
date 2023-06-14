module github.com/rqlite/rqlite/v7

go 1.16

require (
	github.com/Bowery/prompt v0.0.0-20190916142128-fa8279994f75
	github.com/aws/aws-sdk-go v1.44.267
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/hashicorp/consul/api v1.20.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-msgpack v1.1.5 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/raft v1.5.0
	github.com/labstack/gommon v0.4.0 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mattn/go-sqlite3 v1.14.14
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mkideal/cli v0.2.7
	github.com/mkideal/pkg v0.1.3
	github.com/pkg/errors v0.9.1
	github.com/rqlite/raft-boltdb/v2 v2.0.0-20230523104317-c08e70f4de48
	github.com/rqlite/rqlite-disco-clients v0.0.0-20230505011544-70f7602795ff
	github.com/rqlite/sql v0.0.0-20221103124402-8f9ff0ceb8f0
	github.com/stretchr/testify v1.8.2
	go.etcd.io/bbolt v1.3.7
	go.etcd.io/etcd/client/v3 v3.5.9 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/crypto v0.9.0
	golang.org/x/net v0.10.0
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/grpc v1.55.0 // indirect
	google.golang.org/protobuf v1.30.0
)

replace (
	github.com/mattn/go-sqlite3 => github.com/rqlite/go-sqlite3 v1.28.0
	golang.org/x/text => golang.org/x/text v0.3.8
)
