package pki

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateCAAndIssueMutualTLSCertificates(t *testing.T) {
	caCert, caKey, err := CreateCA(CAOptions{CommonName: "datavault test CA", ValidFor: time.Hour})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	serverCert, _, err := Issue(caCert, caKey, IssueOptions{CommonName: "backup.example", Server: true, DNSNames: []string{"backup.example"}, ValidFor: time.Minute})
	if err != nil {
		t.Fatalf("Issue server: %v", err)
	}
	clientCert, _, err := Issue(caCert, caKey, IssueOptions{CommonName: "agent-01", Client: true, ValidFor: time.Minute})
	if err != nil {
		t.Fatalf("Issue client: %v", err)
	}
	ca, err := parseCertificate(caCert)
	if err != nil {
		t.Fatal(err)
	}
	server, err := parseCertificate(serverCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: "backup.example"}); err != nil {
		t.Fatalf("verify server certificate: %v", err)
	}
	client, err := parseCertificate(clientCert)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.ExtKeyUsage) != 1 || client.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected client usages: %v", client.ExtKeyUsage)
	}
	if _, _, err := Issue(caCert, caKey, IssueOptions{CommonName: "missing-san", Server: true}); err == nil {
		t.Fatal("expected server certificate without SAN to fail")
	}
}

func TestWritePairUsesPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "nested", "cert.pem")
	keyPath := filepath.Join(dir, "nested", "key.pem")
	if err := WritePair(certPath, keyPath, []byte("cert"), []byte("key")); err != nil {
		t.Fatalf("WritePair: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode=%#o, want 0600", info.Mode().Perm())
	}
	if _, _, err := Issue([]byte("bad"), []byte("bad"), IssueOptions{CommonName: "client", Client: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}); err == nil {
		t.Fatal("expected invalid issuer input to fail")
	}
}
