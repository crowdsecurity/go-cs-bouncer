package csbouncer

import (
	"context"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
)

type StreamBouncer struct {
	APIKey             string `yaml:"api_key"`
	APIUrl             string `yaml:"api_url"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"`

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

	return nil
}

func (b *StreamBouncer) Init() error {
	var err error
	var apiURL *url.URL

	b.Stream = make(chan *models.DecisionsStreamResponse)

	apiURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return errors.Wrapf(err, "local API Url '%s'", b.APIUrl)
	}
	t := &apiclient.APIKeyTransport{
		APIKey: b.APIKey,
	}

	if b.InsecureSkipVerify == nil {
		apiclient.InsecureSkipVerify = false
	} else {
		apiclient.InsecureSkipVerify = *b.InsecureSkipVerify
	}

	b.APIClient, err = apiclient.NewDefaultClient(apiURL, "v1", b.UserAgent, t.Client())
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
	data, resp, err := b.APIClient.Decisions.GetStream(context.Background(), b.Opts) // true means we just started the bouncer

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
		data, resp, err := b.APIClient.Decisions.GetStream(context.Background(), b.Opts)
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
