package csbouncer

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

var TotalLAPIError = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "lapi_requests_failures_total",
	Help: "The total number of failed calls to CrowdSec LAPI",
})

var TotalLAPICalls = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "lapi_requests_total",
	Help: "The total number of calls to CrowdSec LAPI",
})

type StreamBouncer struct {
	APIKey              string `yaml:"api_key"`
	APIUrl              string `yaml:"api_url"`
	InsecureSkipVerify  *bool  `yaml:"insecure_skip_verify"`
	CertPath            string `yaml:"cert_path"`
	KeyPath             string `yaml:"key_path"`
	CAPath              string `yaml:"ca_cert_path"`
	RetryInitialConnect bool   `yaml:"retry_initial_connect"`

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

	MetricsInterval time.Duration
}

// Config() fills the struct with configuration values from a file. It is not
// aware of .yaml.local files so it is recommended to use ConfigReader() instead.
//
// Deprecated: use ConfigReader() instead.
func (b *StreamBouncer) Config(configPath string) error {
	reader, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file '%s': %w", configPath, err)
	}

	return b.ConfigReader(reader)
}

func (b *StreamBouncer) ConfigReader(configReader io.Reader) error {
	content, err := io.ReadAll(configReader)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	err = yaml.Unmarshal(content, b)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	// the metrics interval is not used direclty but is passed back to the metrics provider,
	// and the minimum can be overridden for testing
	b.MetricsInterval = defaultMetricsInterval

	return nil
}

func (b *StreamBouncer) Init() error {
	var err error

	// validate the configuration

	if b.APIUrl == "" {
		return fmt.Errorf("config does not contain LAPI url")
	}

	if !strings.HasSuffix(b.APIUrl, "/") {
		b.APIUrl += "/"
	}

	if b.APIKey == "" && b.CertPath == "" && b.KeyPath == "" {
		return fmt.Errorf("config does not contain LAPI key or certificate")
	}

	//  scopes, origins, etc.

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

	// update_frequency or however it's called in the .yaml of the specific bouncer

	if b.TickerInterval == "" {
		log.Warningf("lapi update interval is not defined, using default value of 10s")
		b.TickerInterval = "10s"
	}

	b.TickerIntervalDuration, err = time.ParseDuration(b.TickerInterval)
	if err != nil {
		return fmt.Errorf("unable to parse lapi update interval '%s': %w", b.TickerInterval, err)
	}

	if b.TickerIntervalDuration <= 0 {
		return fmt.Errorf("lapi update interval must be positive")
	}

	// prepare the client object for the lapi

	b.Stream = make(chan *models.DecisionsStreamResponse)

	b.APIClient, err = getAPIClient(b.APIUrl, b.UserAgent, b.APIKey, b.CAPath, b.CertPath, b.KeyPath, b.InsecureSkipVerify, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("api client init: %w", err)
	}
	return nil
}

func (b *StreamBouncer) Run(ctx context.Context) {
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

	// Initial connection
	for {
		data, resp, err := getDecisionStream()

		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}

		if err != nil {
			if b.RetryInitialConnect {
				log.Errorf("failed to connect to LAPI, retrying in 10s: %s", err)
				select {
				case <-ctx.Done():
					// context cancellation, possibly a SIGTERM
					return
				case <-time.After(10 * time.Second):
					continue
				}
			}

			log.Error(err)
			// close the stream
			// this may cause the bouncer to exit
			close(b.Stream)
			return
		}

		b.Stream <- data
		break
	}

	b.Opts.Startup = false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, resp, err := getDecisionStream()
			if resp != nil && resp.Response != nil {
				resp.Response.Body.Close()
			}
			if err != nil {
				log.Error(err)
				continue
			}
			b.Stream <- data
		}
	}
}
