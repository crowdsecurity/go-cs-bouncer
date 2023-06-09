package csbouncer

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
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

// Config() fills the struct with configuration values from a file. It is not
// aware of .yaml.local files so it is recommended to use ConfigReader() instead.
func (b *LiveBouncer) Config(configPath string) error {
	reader, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file '%s': %w", configPath, err)
	}

	return b.ConfigReader(reader)
}

func (b *LiveBouncer) ConfigReader(configReader io.Reader) error {
	content, err := io.ReadAll(configReader)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	err = yaml.Unmarshal(content, b)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
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

func (b *LiveBouncer) Init() error {
	var err error

	b.APIClient, err = getApiClient(b.APIUrl, b.UserAgent, b.APIKey, b.CAPath, b.CertPath, b.KeyPath, b.InsecureSkipVerify, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("api client init: %w", err)
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
