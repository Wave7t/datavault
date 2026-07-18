// Package pki creates the small private PKI required by datavault mTLS.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultCAValidity   = 10 * 365 * 24 * time.Hour
	DefaultLeafValidity = 365 * 24 * time.Hour
)

type CAOptions struct {
	CommonName string
	ValidFor   time.Duration
}

type IssueOptions struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	Client      bool
	Server      bool
	ValidFor    time.Duration
}

func CreateCA(opts CAOptions) ([]byte, []byte, error) {
	if opts.CommonName == "" {
		return nil, nil, fmt.Errorf("CA common name is required")
	}
	if opts.ValidFor == 0 {
		opts.ValidFor = DefaultCAValidity
	}
	if opts.ValidFor <= 0 {
		return nil, nil, fmt.Errorf("CA validity must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opts.CommonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(opts.ValidFor),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}
	keyPEM, err := marshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), keyPEM, nil
}

func Issue(caCertPEM, caKeyPEM []byte, opts IssueOptions) ([]byte, []byte, error) {
	if opts.CommonName == "" {
		return nil, nil, fmt.Errorf("certificate common name is required")
	}
	if opts.Client == opts.Server {
		return nil, nil, fmt.Errorf("exactly one of client or server usage is required")
	}
	if opts.ValidFor == 0 {
		opts.ValidFor = DefaultLeafValidity
	}
	if opts.ValidFor <= 0 {
		return nil, nil, fmt.Errorf("certificate validity must be positive")
	}
	caCert, err := parseCertificate(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, nil, fmt.Errorf("issuer certificate is not a CA")
	}
	caKey, err := parseECPrivateKey(caKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	notAfter := now.Add(opts.ValidFor)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: opts.CommonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPAddresses,
	}
	if opts.Client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if opts.Server {
		if len(opts.DNSNames) == 0 && len(opts.IPAddresses) == 0 {
			return nil, nil, fmt.Errorf("server certificate requires at least one DNS name or IP address")
		}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyPEM, err := marshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal certificate key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), keyPEM, nil
}

// WritePair atomically writes the certificate (0644) and private key (0600).
func WritePair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	for _, path := range []string{certPath, keyPath} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("certificate paths must be absolute: %q", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return fmt.Errorf("create certificate directory: %w", err)
		}
	}
	if err := writeFileAtomic(certPath, certPEM, 0644); err != nil {
		return err
	}
	return writeFileAtomic(keyPath, keyPEM, 0600)
}

func writeFileAtomic(path string, contents []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".datavault-pki-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

func marshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("missing certificate PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("missing private-key PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
