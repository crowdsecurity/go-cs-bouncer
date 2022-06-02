package csbouncer

import (
	"context"
	"net/url"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type StreamBouncer struct {
	APIKey                 string
	APIUrl                 string
	TickerInterval         string
	TickerIntervalDuration time.Duration
	Stream                 chan *models.DecisionsStreamResponse
	APIClient              *apiclient.ApiClient
	UserAgent              string
	InsecureSkipVerify     *bool
	Opts                   apiclient.DecisionsStreamOpts
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
