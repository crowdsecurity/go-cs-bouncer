package csbouncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"gopkg.in/yaml.v2"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type LiveBouncer struct {
	APIKey             string `yaml:"api_key"`
	APIUrl             string `yaml:"api_url"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"`
	CertPath           string `yaml:"cert_path"`
	KeyPath            string `yaml:"key_path"`
	CAPath             string `yaml:"ca_path"`

	APIClient *apiclient.ApiClient
	UserAgent string
}

func (b *LiveBouncer) Config(configPath string) error {
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		return errors.Wrapf(err, "unable to read config file '%s': %s", configPath, err)
	}
	err = yaml.Unmarshal(content, b)
	if err != nil {
		return errors.Wrapf(err, "unable to unmarshal config file '%s': %s", configPath, err)
	}
	return nil
}

func (b *LiveBouncer) Init() error {
	var err error
	var apiURL *url.URL
	var client *http.Client
	var caCertPool *x509.CertPool
	apiURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return errors.Wrapf(err, "local API Url '%s'", b.APIUrl)
	}

	if b.APIKey != "" {
		log.Infof("Using API key auth")
		t := &apiclient.APIKeyTransport{
			APIKey: b.APIKey,
		}
		client = t.Client()
		if b.InsecureSkipVerify == nil {
			apiclient.InsecureSkipVerify = false
		} else {
			apiclient.InsecureSkipVerify = *b.InsecureSkipVerify
		}
	} else if b.CertPath != "" && b.KeyPath != "" {
		var InsecureSkipVerify bool
		log.Infof("Using cert auth")
		certificate, err := tls.LoadX509KeyPair(b.CertPath, b.KeyPath)
		if err != nil {
			return errors.Wrapf(err, "unable to load certificate '%s' and key '%s'", b.CertPath, b.KeyPath)
		}

		if b.CAPath != "" {
			log.Infof("Using CA cert '%s'", b.CAPath)
			caCert, err := ioutil.ReadFile(b.CAPath)
			if err != nil {
				return errors.Wrapf(err, "unable to load CA certificate '%s'", b.CAPath)
			}
			caCertPool = x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
		} else {
			caCertPool = nil
		}

		if b.InsecureSkipVerify == nil {
			InsecureSkipVerify = false
		} else {
			InsecureSkipVerify = *b.InsecureSkipVerify
		}

		client = &http.Client{}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{certificate},
				InsecureSkipVerify: InsecureSkipVerify,
			},
		}
	} else {
		return errors.New("no API key or certificate provided")
	}

	b.APIClient, err = apiclient.NewDefaultClient(apiURL, "v1", b.UserAgent, client)
	if err != nil {
		return errors.Wrapf(err, "api client init")
	}

	return nil
}

func (b *LiveBouncer) Get(value string) (*models.GetDecisionsResponse, error) {
	filter := apiclient.DecisionsListOpts{
		IPEquals: &value,
	}

	decision, resp, err := b.APIClient.Decisions.List(context.Background(), filter)
	if err != nil {
		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}
		return &models.GetDecisionsResponse{}, err
	}
	if resp != nil && resp.Response != nil {
		resp.Response.Body.Close()
	}

	return decision, nil
}
