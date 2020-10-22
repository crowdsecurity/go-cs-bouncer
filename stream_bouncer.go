package csbouncer

import (
	"context"
	"log"
	"net/url"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
)

type StreamBouncer struct {
	APIKey                 string
	APIUrl                 string
	TickerInterval         string
	TickerIntervalDuration time.Duration
	Decisions              chan *models.DecisionsStreamResponse
	APIClient              *apiclient.ApiClient
	UserAgent              string
}

func (b *StreamBouncer) Init() error {
	var err error

	b.NewDecision = make(chan models.Decision)
	b.ExpiredDecision = make(chan models.Decision)

	apiclient.BaseURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return errors.Wrapf(err, "local API Url '%s'", b.APIUrl)
	}
	apiclient.UserAgent = b.UserAgent
	t := &apiclient.APIKeyTransport{
		APIKey: b.APIKey,
	}

	b.APIClient = apiclient.NewClient(t.Client())

	b.TickerIntervalDuration, err = time.ParseDuration(b.TickerInterval)
	if err != nil {
		return errors.Wrapf(err, "unable to parse duration '%s'", b.TickerInterval)
	}

	return nil
}

func (b *StreamBouncer) Run() {
	ticker := time.NewTicker(b.TickerIntervalDuration)

	data, _, err := b.APIClient.Decisions.GetStream(context.Background(), true) // true means we just started the bouncer
	if err != nil {
		log.Fatalf(err.Error())
	}

	b.Decisions <- data

	for {
		select {
		case <-ticker.C:
			data, _, err := b.APIClient.Decisions.GetStream(context.Background(), false)
			if err != nil {
				log.Fatalf(err.Error())
			}
			b.Decisions <- data
		}
	}
}
