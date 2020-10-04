package csbouncer

import (
	"context"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/pkg/errors"
)

type LiveBouncer struct {
	APIKey    string
	APIUrl    string
	APIClient *apiclient.ApiClient
}

func (b *LiveBouncer) Init() error {
	var err error

	apiclient.BaseURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return errors.Wrapf(err, "local API Url '%s'", b.APIUrl)
	}
	t := &apiclient.APIKeyTransport{
		APIKey: b.APIKey,
	}

	b.APIClient = apiclient.NewClient(t.Client())

	return nil
}

func (b *LiveBouncer) Get(value string) (*models.GetDecisionsResponse, error) {
	filter := apiclient.DecisionsListOpts{
		IP_equals: &value,
	}

	decision, _, err := b.APIClient.Decisions.List(context.Background(), filter)
	if err != nil {
		return &models.GetDecisionsResponse{}, err
	}

	return decision, nil
}
