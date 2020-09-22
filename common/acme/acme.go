package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/providers/dns/alidns"
	"github.com/go-acme/lego/v3/providers/dns/cloudflare"
	"github.com/go-acme/lego/v3/providers/dns/gandi"
	"github.com/go-acme/lego/v3/providers/dns/godaddy"
	"github.com/go-acme/lego/v3/registration"
	"time"
	"v2ray.com/core/transport/internet/tls"
)

// You'll need a user or account type that implements acme.User
type Account struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *Account) GetEmail() string {
	return u.Email
}
func (u Account) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *Account) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type Config struct {
	Domain    string `json:"domain"`
	Provider  string `json:"provider"`
	Email     string `json:"email"`
	ApiKey    string `json:"api_key"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

func ConfigFromString(jsonConfig string) (*Config, error) {
	config := new(Config)
	err := json.Unmarshal([]byte(jsonConfig), config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func AutoCert(config *Config) (*tls.Certificate, error) {
	//keyByte, certByte, err := LoadCert()
	//if err != nil {
	//	newError("loadcert failed").AtError().WriteToLog()
	//}
	//
	//if keyByte != nil && certByte != nil {
	//	cert := new(tls.Certificate)
	//	cert.Certificate = certByte
	//	cert.Key = keyByte
	//	cert.Usage = tls.Certificate_ENCIPHERMENT
	//	return cert, nil
	//}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	account := Account{
		Email: config.Email,
		key:   privateKey,
	}

	legoConfig := lego.NewConfig(&account)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	legoConfig.CADirURL = lego.LEDirectoryProduction
	legoConfig.Certificate.KeyType = certcrypto.EC256

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, err
	}

	// We specify an http port of 5002 and an tls port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	//err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "5002"))
	//if err != nil {
	//	log.Fatal(err)
	//}
	//err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "5001"))
	//if err != nil {
	//	log.Fatal(err)
	//}

	providerFunc, err := GetProvider(config.Provider)
	if err != nil {
		return nil, err
	}

	provider, err := providerFunc(config)
	if err != nil {
		return nil, err
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, err
	}

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	account.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{config.Domain},
		Bundle:  true,
	}

	response, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	// Temporarily unsaved
	//err = SaveCert(response.PrivateKey, response.Certificate)
	//if err != nil {
	//	newError("save cert error").Base(err).AtError().WriteToLog()
	//}

	cert := new(tls.Certificate)
	cert.Certificate = response.Certificate
	cert.Key = response.PrivateKey
	cert.Usage = tls.Certificate_ENCIPHERMENT

	return cert, nil
}

/* --------------------- DNS provider ---------------------*/
type DNSProviderCreater func(config *Config) (challenge.Provider, error)

var (
	providerCreaterRegistry = make(map[string]DNSProviderCreater)
)

func RegisterProvider(name string, creater DNSProviderCreater) {
	providerCreaterRegistry[name] = creater
}

func GetProvider(name string) (DNSProviderCreater, error) {
	provider, found := providerCreaterRegistry[name]
	if !found {
		return nil, newError(fmt.Sprintf("no provider %s found", name))
	}
	return provider, nil
}

func AliDNSProviderCreater(config *Config) (challenge.Provider, error) {
	alidnsConfig := alidns.NewDefaultConfig()
	alidnsConfig.APIKey = config.ApiKey
	alidnsConfig.SecretKey = config.SecretKey
	alidnsConfig.PropagationTimeout = 5 * time.Minute
	return alidns.NewDNSProviderConfig(alidnsConfig)
}

func CloudflareProviderCreater(config *Config) (challenge.Provider, error) {
	cloudflareConfig := cloudflare.NewDefaultConfig()
	cloudflareConfig.AuthEmail = config.Email
	cloudflareConfig.AuthKey = config.ApiKey
	cloudflareConfig.PropagationTimeout = 5 * time.Minute
	return cloudflare.NewDNSProviderConfig(cloudflareConfig)
}

func GandiProviderCreater(config *Config) (challenge.Provider, error) {
	gandiConfig := gandi.NewDefaultConfig()
	gandiConfig.APIKey = config.ApiKey
	gandiConfig.PropagationTimeout = 5 * time.Minute
	return gandi.NewDNSProviderConfig(gandiConfig)
}

func GodaddyProviderCreater(config *Config) (challenge.Provider, error) {
	godaddyConfig := godaddy.NewDefaultConfig()
	godaddyConfig.APIKey = config.ApiKey
	godaddyConfig.APISecret = config.AccessKey
	godaddyConfig.PropagationTimeout = 5 * time.Minute
	return godaddy.NewDNSProviderConfig(godaddyConfig)
}

/* --------------------- Certificate issuing process --------------------- */

func init() {
	RegisterProvider("cloudflare", CloudflareProviderCreater)
	RegisterProvider("alidns", AliDNSProviderCreater)
	RegisterProvider("gandi", GandiProviderCreater)
	RegisterProvider("godaddy", GodaddyProviderCreater)
}
