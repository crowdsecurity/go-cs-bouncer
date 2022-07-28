package csbouncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
)

var TotalLAPIError prometheus.Counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "total_lapi_call_failures",
	Help: "The total number of failed calls to CrowdSec LAPI",
},
)

var TotalLAPICalls prometheus.Counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "total_lapi_calls",
	Help: "The total number of calls to CrowdSec LAPI",
},
)

type StreamBouncer struct {
	APIKey             string `yaml:"api_key"`
	APIUrl             string `yaml:"api_url"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"`
	CertPath           string `yaml:"cert_path"`
	KeyPath            string `yaml:"key_path"`
	CAPath             string `yaml:"ca_cert_path"`

	TickerInterval         string   `yaml:"update_frequency"`
	Scopes                 []string `yaml:"scopes"`
	ScenariosContaining    []string `yaml:"scenarios_containing"`
	ScenariosNotContaining []string `yaml:"scenarios_not_containing"`
	Origins                []string `yaml:"origins"`

	TickerIntervalDuration time.Duration
	Stream                 chan *models.DecisionsStreamResponse
	APIClient              *apiclient.ApiClient
	UserAgent              string
	Opts                   apiclient.DecisionsStreamOpts
}

func (b *StreamBouncer) Config(configPath string) error {
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		return errors.Wrapf(err, "unable to read config file '%s': %s", configPath, err)
	}
	err = yaml.Unmarshal(content, b)
	if err != nil {
		return errors.Wrapf(err, "unable to unmarshal config file '%s': %s", configPath, err)
	}

	if b.Scopes != nil {
		b.Opts.Scopes = strings.Join(b.Scopes, ",")
	}

	if b.ScenariosContaining != nil {
		b.Opts.ScenariosContaining = strings.Join(b.ScenariosContaining, ",")
	}

	if b.ScenariosNotContaining != nil {
		b.Opts.ScenariosNotContaining = strings.Join(b.ScenariosNotContaining, ",")
	}

	if b.Origins != nil {
		b.Opts.Origins = strings.Join(b.Origins, ",")
	}

	if b.APIUrl == "" {
		return fmt.Errorf("config does not contain LAPI url")
	}
	if !strings.HasSuffix(b.APIUrl, "/") {
		b.APIUrl += "/"
	}
	if b.APIKey == "" && b.CertPath == "" && b.KeyPath == "" {
		return fmt.Errorf("config does not contain LAPI key or certificate")
	}

	return nil
}

func (b *StreamBouncer) Init() error {
	var err error
	var apiURL *url.URL
	var client *http.Client
	var caCertPool *x509.CertPool

	b.Stream = make(chan *models.DecisionsStreamResponse)

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
		log.Infof("Using cert auth with cert '%s' and key '%s'", b.CertPath, b.KeyPath)
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

	b.TickerIntervalDuration, err = time.ParseDuration(b.TickerInterval)
	if err != nil {
		return errors.Wrapf(err, "unable to parse duration '%s'", b.TickerInterval)
	}
	return nil
}

func (b *StreamBouncer) Run() {
	ticker := time.NewTicker(b.TickerIntervalDuration)

	b.Opts.Startup = true

	getDecisionStream := func() (*models.DecisionsStreamResponse, *apiclient.Response, error) {
		data, resp, err := b.APIClient.Decisions.GetStream(context.Background(), b.Opts)
		TotalLAPICalls.Inc()
		if err != nil {
			TotalLAPIError.Inc()
		}
		return data, resp, err
	}

	data, resp, err := getDecisionStream()

	if resp != nil && resp.Response != nil {
		resp.Response.Body.Close()
	}

	if err != nil {
		log.Errorf(err.Error())
		return
	}

	b.Stream <- data
	b.Opts.Startup = false
	for range ticker.C {
		data, resp, err := getDecisionStream()
		if err != nil {
			if resp != nil && resp.Response != nil {
				resp.Response.Body.Close()
			}
			log.Errorf(err.Error())
			continue
		}
		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}
		b.Stream <- data
	}
}
