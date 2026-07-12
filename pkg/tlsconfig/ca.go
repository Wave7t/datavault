// Package tlsconfig contains shared TLS trust-store helpers.
package tlsconfig

import (
	"crypto/x509"
	"fmt"
	"os"
)

// LoadCertPool loads a PEM-encoded CA bundle. An empty path, unreadable file,
// or bundle with no certificates is an error so mTLS cannot silently fall back
// to the host trust store or an empty client-CA list.
func LoadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("CA file is required")
	}
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("parse CA file: no certificates found")
	}
	return pool, nil
}
