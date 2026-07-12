package tlsconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCertPool(t *testing.T) {
	if _, err := LoadCertPool(""); err == nil {
		t.Fatal("expected empty CA path to fail")
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, testCertificatePEM(t), 0600); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadCertPool(path)
	if err != nil {
		t.Fatalf("LoadCertPool: %v", err)
	}
	if len(pool.Subjects()) != 1 {
		t.Fatalf("loaded %d CA subjects, want 1", len(pool.Subjects()))
	}
}

func TestLoadCertPoolRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertPool(path); err == nil {
		t.Fatal("expected invalid PEM to fail")
	}
}

func testCertificatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "datavault-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
