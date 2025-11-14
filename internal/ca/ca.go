package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	cfgpkg "mitm-proxy/internal/config"
)

// CA represents a certificate authority used to sign per-host leaf certificates.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.PrivateKey // *rsa.PrivateKey
}

// LoadOrCreate loads an existing CA from paths in config, or generates and saves a new one.
func LoadOrCreate(config *cfgpkg.Config) (*CA, error) {
	// Determine paths to use for loading
	certPath := config.CACertPath
	keyPath := config.CAKeyPath

	if certPath == "" {
		certPath = config.CACertOutputPath
	}

	if keyPath == "" {
		keyPath = config.CAKeyOutputPath
	}

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		log.Printf("Loading existing CA from %s / %s", certPath, keyPath)

		return parseCA(certPEM, keyPEM)
	}

	log.Printf("CA files not found, generating new CA...")

	ca, err := generateCA()

	if err != nil {
		return nil, err
	}

	if err := saveCA(config.CACertOutputPath, config.CAKeyOutputPath, ca); err != nil {
		return nil, err
	}

	return ca, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)

	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	priv, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)

	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{Cert: cert, Key: priv}, nil
}

func generateCA() (*CA, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Go MITM Proxy CA",
			Organization: []string{"Go MITM Proxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse created CA cert: %w", err)
	}

	return &CA{Cert: cert, Key: priv}, nil
}

func saveCA(certPath, keyPath string, ca *CA) error {
	priv, ok := ca.Key.(*rsa.PrivateKey)

	if !ok {
		return fmt.Errorf("CA key is not RSA private key")
	}

	if dir := filepath.Dir(certPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create cert directory: %w", err)
		}
	}

	if dir := filepath.Dir(keyPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create key directory: %w", err)
		}
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("create CA cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}); err != nil {
		return fmt.Errorf("write CA cert PEM: %w", err)
	}

	log.Printf("Wrote CA certificate to %s", certPath)

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("create CA key file: %w", err)
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("write CA key PEM: %w", err)
	}

	log.Printf("Wrote CA private key to %s", keyPath)

	return nil
}

// GenerateCertForHost generates a per-host leaf certificate signed by the CA.
func (ca *CA) GenerateCertForHost(host string) (tls.Certificate, error) {
	// strip port if present
	h := host

	if strings.Contains(host, ":") {
		if name, _, err := net.SplitHostPort(host); err == nil {
			h = name
		} else if i := strings.LastIndex(host, ":"); i != -1 {
			h = host[:i]
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: h},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{h},
	}

	parent := ca.Cert
	caPriv, ok := ca.Key.(*rsa.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("CA key not RSA")
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, caPriv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create leaf cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create X509KeyPair: %w", err)
	}

	return leaf, nil
}
