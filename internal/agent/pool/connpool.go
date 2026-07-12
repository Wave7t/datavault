package pool

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/tlsconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// ConnPool manages mTLS gRPC connections to backup servers.
// Connections are created lazily on first use and reused thereafter.
// It is safe for concurrent use.
type ConnPool struct {
	mu      sync.RWMutex
	conns   map[string]*grpc.ClientConn
	clients map[string]backuppbv1.BackupServiceClient
	cert    tls.Certificate
	rootCAs *x509.CertPool
}

// New creates a new ConnPool that authenticates with the given mTLS
// certificate/key and verifies servers with the configured CA bundle.
func New(certFile, keyFile, caFile string) (*ConnPool, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	rootCAs, err := tlsconfig.LoadCertPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("load server CA: %w", err)
	}
	return &ConnPool{
		conns:   make(map[string]*grpc.ClientConn),
		clients: make(map[string]backuppbv1.BackupServiceClient),
		cert:    cert,
		rootCAs: rootCAs,
	}, nil
}

// GetClient returns a BackupServiceClient for the given server address.
// Connections are created lazily and cached for reuse.
func (p *ConnPool) GetClient(address string) (backuppbv1.BackupServiceClient, error) {
	p.mu.RLock()
	client, ok := p.clients[address]
	p.mu.RUnlock()
	if ok {
		return client, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double check after acquiring write lock
	if client, ok := p.clients[address]; ok {
		return client, nil
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{p.cert},
		RootCAs:      p.rootCAs,
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := grpc.Dial(address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			PermitWithoutStream: false,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(16*1024*1024),
			grpc.MaxCallSendMsgSize(16*1024*1024),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", address, err)
	}

	client = backuppbv1.NewBackupServiceClient(conn)
	p.conns[address] = conn
	p.clients[address] = client
	return client, nil
}

// Close shuts down all cached gRPC connections.
func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = nil
	p.clients = nil
}
