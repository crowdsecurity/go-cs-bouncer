package csbouncer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"
)

const (
	crowdsecAppsecIPHeader   = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader  = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader     = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent  = "X-Crowdsec-Appsec-User-Agent"
)

type Timeout struct {
	ConnectTimeout        *int `yaml:"connect_timeout"`
	TLSHandshakeTimeout   *int `yaml:"tls_handshake_timeout"`
	ResponseHeaderTimeout *int `yaml:"response_header_timeout"`
}

func (t *Timeout) SetDefaults() {
	if t.ConnectTimeout == nil {
		t.ConnectTimeout = new(int)
		*t.ConnectTimeout = 5
	}
	if t.TLSHandshakeTimeout == nil {
		t.TLSHandshakeTimeout = new(int)
		*t.TLSHandshakeTimeout = 5
	}
	if t.ResponseHeaderTimeout == nil {
		t.ResponseHeaderTimeout = new(int)
		*t.ResponseHeaderTimeout = 5
	}
}

// AppSecConfig is a struct that holds the configuration for the AppSec.
type AppSecConfig struct {
	Url                string   `yaml:"url"`
	InsecureSkipVerify *bool    `yaml:"insecure_skip_verify"`
	CAPath             string   `yaml:"ca_cert_path"`
	ParsedUrl          *url.URL `yaml:"-"`
	Timeout            Timeout  `yaml:"timeout"`
}

// AppSec is a struct that holds the configuration for the AppSec. Inherits the API key from the bouncer config.
type AppSec struct {
	APIKey       string        `yaml:"api_key"`
	AppSecConfig *AppSecConfig `yaml:"appsec_config"`
	Client       *http.Client  `yaml:"-"`
}

type AppSecResponse struct {
	_response  *http.Response
	Action     string `json:"action"`
	HTTPStatus int    `json:"http_status"`
}

// Config() fills the struct with configuration values from a file. It is not
// aware of .yaml.local files so it is recommended to use ConfigReader() instead.
func (w *AppSec) Config(configPath string) error {
	reader, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("unable to read config file '%s': %w", configPath, err)
	}

	return w.ConfigReader(reader)
}

func (w *AppSec) ConfigReader(configReader io.Reader) error {
	content, err := io.ReadAll(configReader)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	err = yaml.Unmarshal(content, w)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	return nil
}

func (w *AppSec) Init() error {
	var err error

	if w.AppSecConfig.Url == "" {
		return fmt.Errorf("config does not contain AppSec url")
	}

	if w.AppSecConfig.ParsedUrl, err = url.Parse(w.AppSecConfig.Url); err != nil {
		return fmt.Errorf("unable to parse AppSec url: %w", err)
	}

	if w.AppSecConfig.InsecureSkipVerify == nil {
		w.AppSecConfig.InsecureSkipVerify = new(bool)
		*w.AppSecConfig.InsecureSkipVerify = false
	}

	w.AppSecConfig.Timeout.SetDefaults()

	caCertPool, err := getCertPool(w.AppSecConfig.CAPath, log.StandardLogger())
	if err != nil {
		return err
	}

	w.Client = &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: time.Duration(*w.AppSecConfig.Timeout.ConnectTimeout) * time.Second,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *w.AppSecConfig.InsecureSkipVerify,
				RootCAs:            caCertPool,
			},
			TLSHandshakeTimeout:   time.Duration(*w.AppSecConfig.Timeout.TLSHandshakeTimeout) * time.Second,
			ResponseHeaderTimeout: time.Duration(*w.AppSecConfig.Timeout.ResponseHeaderTimeout) * time.Second,
		},
	}

	return nil
}

// ParseClientReq parses the client request and returns a new request that is ready to be forwarded to the AppSec.
// You can override the IP address with the ipOverride parameter.
// This function should not be used directly, use Forward() instead.
func (w *AppSec) ParseClientReq(clientReq *http.Request, ipOverride string) (*http.Request, error) {
	var req *http.Request
	if clientReq.Body != nil && clientReq.ContentLength > 0 {
		bodyBytes, err := io.ReadAll(clientReq.Body)
		if err != nil {
			return nil, err
		}
		clientReq.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		req, _ = http.NewRequest(http.MethodPost, w.AppSecConfig.ParsedUrl.String(), bytes.NewBuffer(bodyBytes))
	} else {
		req, _ = http.NewRequest(http.MethodGet, w.AppSecConfig.ParsedUrl.String(), nil)
	}

	for key, headers := range clientReq.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}

	if ipOverride != "" {
		req.Header.Set(crowdsecAppsecIPHeader, ipOverride)
	} else {
		req.Header.Set(crowdsecAppsecIPHeader, clientReq.RemoteAddr)
	}

	req.Header.Set(crowdsecAppsecHeader, w.APIKey)
	req.Header.Set(crowdsecAppsecVerbHeader, clientReq.Method)
	req.Header.Set(crowdsecAppsecHostHeader, clientReq.Host)
	req.Header.Set(crowdsecAppsecURIHeader, clientReq.URL.String())
	req.Header.Set(crowdsecAppsecUserAgent, clientReq.Header.Get("User-Agent"))

	return req, nil
}

// Internal forward function that sends the request to the AppSec and returns the response.
func (w *AppSec) forward(req *http.Request) (*AppSecResponse, error) {
	res, err := w.Client.Do(req)
	if err != nil {
		return &AppSecResponse{_response: res}, fmt.Errorf("appsecQuery %w", err)
	}
	defer res.Body.Close()

	wr := &AppSecResponse{_response: res}

	if res.StatusCode == http.StatusInternalServerError {
		return wr, fmt.Errorf("appsecQuery: unexpected status code %d", res.StatusCode)
	}

	json.NewDecoder(res.Body).Decode(wr)

	return wr, nil
}

// ForwardWithIP forwards the request to the AppSec and returns the response.
// You can override the IP address with the IP parameter.
// You do not need to parse the client request, just pass it as an argument.
func (w *AppSec) ForwardWithIP(clientReq *http.Request, IP string) (*AppSecResponse, error) {
	req, err := w.ParseClientReq(clientReq, IP)

	if err != nil {
		return nil, fmt.Errorf("appsecQuery %w", err)
	}

	return w.forward(req)
}

// Forward forwards the request to the AppSec and returns the response.
// You do not need to parse the client request, just pass it as an argument.
func (w *AppSec) Forward(clientReq *http.Request) (*AppSecResponse, error) {
	req, err := w.ParseClientReq(clientReq, "")

	if err != nil {
		return nil, fmt.Errorf("appsecQuery %w", err)
	}

	return w.forward(req)
}
