package csbouncer

import (
	"context"
	"io/ioutil"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"gopkg.in/yaml.v2"

	"github.com/pkg/errors"
)

type LiveBouncer struct {
	CommonBouncerConfig `yaml:",inline"`

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
