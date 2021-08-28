package tlsx

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

func LoadCa(caRaw []byte, keyRaw []byte) (caCert *x509.Certificate, privateKey crypto.PrivateKey, err error) {
	ca, _ := pem.Decode(caRaw)
	if ca == nil {
		return nil, nil, errors.New("CA load failed")
	}
	caCert, err = x509.ParseCertificate(ca.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, _ := pem.Decode(keyRaw)
	if key == nil {
		return nil, nil, errors.New("key load failed")
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(key.Bytes)
	if strings.Contains(err.Error(), "use ParseECPrivateKey") {
		err = nil
		privateKey, err = x509.ParseECPrivateKey(key.Bytes)
	}
	return
}

// GenerateCA will generator CA certificate and privateKey encode by pem structure
func GenerateCA() (privateKey []byte, cert []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	names := pkix.Name{
		Organization: []string{"Kitami"},
		CommonName:   "Kitami Generated CA",
		Names: []pkix.AttributeTypeAndValue{
			{
				Type:  []int{2, 5, 4, 10},
				Value: "Kitami",
			},
			{
				Type:  []int{2, 5, 4, 3},
				Value: "Kitami Generated CA",
			},
		},
	}
	template := &x509.Certificate{
		Version:               1,
		SerialNumber:          big.NewInt(1),
		Subject:               names,
		Issuer:                names,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return
	}
	// Generate cert
	certBuffer := bytes.Buffer{}
	if err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		return
	}
	cert = certBuffer.Bytes()

	// Generate key
	keyBuffer := bytes.Buffer{}
	if err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return
	}
	privateKey = keyBuffer.Bytes()
	return
}

// ref: https://blog.csdn.net/chenxing1230/article/details/83787036
func GenerateCAWithECC() (privateKey []byte, cert []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	names := pkix.Name{
		Organization: []string{"Kitami"},
		CommonName:   "Kitami Generated CA",
		Names: []pkix.AttributeTypeAndValue{
			{
				Type:  []int{2, 5, 4, 10},
				Value: "Kitami",
			},
			{
				Type:  []int{2, 5, 4, 3},
				Value: "Kitami Generated CA",
			},
		},
	}
	template := &x509.Certificate{
		Version:               1,
		SerialNumber:          big.NewInt(1),
		Subject:               names,
		Issuer:                names,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames: []string{
			"localhost",
		},
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey(key), key)
	if err != nil {
		return
	}
	// Generate cert
	certBuffer := bytes.Buffer{}
	if err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		return
	}
	cert = certBuffer.Bytes()

	// Generate key
	keyBuffer := bytes.Buffer{}
	if err = pem.Encode(&keyBuffer, pemBlockForKey(key)); err != nil {
		return
	}
	privateKey = keyBuffer.Bytes()
	return
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

type CertCacheStruct struct {
	Url  string
	Cert []byte
	Key  crypto.PrivateKey
}

var (
	CertCache = cache.New(5*time.Minute, 10*time.Minute)
)

func MakeCertForUrl(caRaw, keyRaw []byte, url string) (cert []byte, key crypto.PrivateKey, err error) {
	cacheCert, found := CertCache.Get(url)
	if found {
		return cacheCert.(CertCacheStruct).Cert, cacheCert.(CertCacheStruct).Key, nil
	}

	ca, priv, err := LoadCa(caRaw, keyRaw)
	if err != nil {
		return
	}

	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	names := pkix.Name{
		CommonName: url,
	}

	template := &x509.Certificate{
		Version:               1,
		SerialNumber:          big.NewInt(1),
		Subject:               names,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{url},
	}

	cert, err = x509.CreateCertificate(rand.Reader, template, ca, publicKey(key), priv)

	CertCache.Set(url, &CertCacheStruct{
		Url:  url,
		Cert: cert,
		Key:  key,
	}, cache.DefaultExpiration)
	return
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("crypto/tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("crypto/tls: failed to parse private key")
}
