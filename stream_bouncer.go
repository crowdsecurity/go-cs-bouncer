package csbouncer

import (
	"context"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/pkg/errors"
)

var pullTicker = 30

type StreamBouncer struct {
	APIKey                 string
	APIUrl                 string
	TickerInterval         string
	TickerIntervalDuration time.Duration
	ExpiredDecision        chan models.Decision
	NewDecision            chan models.Decision
	APIClient              *apiclient.ApiClient
}

func (b *StreamBouncer) Init() error {
	var err error

	b.NewDecision = make(chan models.Decision)
	b.ExpiredDecision = make(chan models.Decision)

	apiclient.BaseURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return errors.Wrapf(err, "local API Url '%s'", b.APIUrl)
	}
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

	data, _, err := b.APIClient.Decisions.GetStream(context.Background(), true)
	if err != nil {
		log.Fatalf(err.Error())
	}

	b.Send(data)

	for {
		select {
		case <-ticker.C:
			data, _, err := b.APIClient.Decisions.GetStream(context.Background(), false)
			if err != nil {
				log.Fatalf(err.Error())
			}
			b.Send(data)
		}
	}

}

func (b *StreamBouncer) Send(decisions *models.DecisionsStreamResponse) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, newDecision := range decisions.New {
			b.NewDecision <- *newDecision
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, expiredDecision := range decisions.Deleted {
			b.ExpiredDecision <- *expiredDecision
		}
	}()

	wg.Wait()
}
