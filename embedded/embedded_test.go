package embedded_test

import (
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	"github.com/rqlite/rqlite/v7/embedded"
	"github.com/stretchr/testify/require"
)

func TestStandalone(t *testing.T) {
	_, err := embedded.New(embedded.Config{})
	require.Error(t, err)

	var cleanup func()
	cfg := embedded.DefaultConfig()
	cfg.NodeX509Cert = ""
	cfg.NodeX509Key = ""
	cfg.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", freePort())
	cfg.RaftAddr = fmt.Sprintf("127.0.0.1:%d", freePort())
	cfg.DataPath, cleanup = makeTestDir("rqlite")

	defer cleanup()

	daemon, err := embedded.New(cfg)
	require.NoError(t, err)

	err = daemon.Shutdown()
	require.NoError(t, err)

	//&embedded.Config{
	//	NodeID: "standalone",
	//	//HTTPAddr:               "127.0.0.1:8009",
	//	//RaftAddr:               "127.0.0.1:8010",
	//	//JoinAddr:               "",
	//}
}

func makeTestDir(prefix string) (path string, cleanup func()) {
	path, err := os.MkdirTemp(os.TempDir(), prefix)
	if err != nil {
		log.Fatalf("failed to create test dir %s: %s", path, err)
	}
	cleanup = func() {
		err := os.RemoveAll(path)
		if err != nil {
			log.Printf("failed to remove test directory %s: %s", path, err)
		}
	}
	return
}

func makeListener(targetPort int) (listener net.Listener, actualPort int, err error) {
	address := fmt.Sprintf("127.0.0.1:%d", targetPort)
	listener, err = net.Listen("tcp", address)
	if err != nil {
		return nil, 0, err
	}

	return listener, listener.Addr().(*net.TCPAddr).Port, nil
}

func freePort() int {
	listener, port, err := makeListener(0)
	if err == nil {
		err = listener.Close()
	}
	if err != nil {
		panic(err)
	}
	return port
}
