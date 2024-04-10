package csbouncer_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

func TestWafConfigReader(t *testing.T) {
	var connectTimeout = 5
	var tlsHandshakeTimeout = 10
	var responseHeaderTimeout = 15
	var tests = []struct {
		name     string
		expected csbouncer.AppSec
		yaml     string
	}{
		{
			name: "Test default values",
			expected: csbouncer.AppSec{
				APIKey: "test",
				AppSecConfig: &csbouncer.AppSecConfig{
					Url: "http://localhost:7422/",
				},
			},
			yaml: `api_key: test
appsec_config:
  url: http://localhost:7422/
`,
		},
		{
			name: "Test inheritance of API key",
			expected: csbouncer.AppSec{
				APIKey: "test",
				AppSecConfig: &csbouncer.AppSecConfig{
					Url: "http://localhost:7422/",
				},
			},
			yaml: `api_key: test
api_url: http://localhost:8080/
appsec_config:
  url: http://localhost:7422/`,
		},
		{
			name: "Test timeout values",
			expected: csbouncer.AppSec{
				APIKey: "test",
				AppSecConfig: &csbouncer.AppSecConfig{
					Url: "http://localhost:7422/",
					Timeout: csbouncer.Timeout{
						ConnectTimeout:        &connectTimeout,
						TLSHandshakeTimeout:   &tlsHandshakeTimeout,
						ResponseHeaderTimeout: &responseHeaderTimeout,
					},
				},
			},
			yaml: `api_key: test
appsec_config:
  url: http://localhost:7422/
  timeout:
    connect_timeout: 5
    tls_handshake_timeout: 10
    response_header_timeout: 15`,
		},
	}

	for _, test := range tests {
		test.expected.Init()
		t.Run(test.name, func(t *testing.T) {
			tt := &csbouncer.AppSec{}
			r := strings.NewReader(test.yaml)
			tt.ConfigReader(r)
			tt.Init()
			if tt.APIKey != test.expected.APIKey {
				t.Errorf("expected %s, got %s", test.expected.APIKey, tt.APIKey)
			}
			if tt.AppSecConfig.Url != test.expected.AppSecConfig.Url {
				t.Errorf("expected %s, got %s", test.expected.AppSecConfig.Url, tt.AppSecConfig.Url)
			}
			if *tt.AppSecConfig.Timeout.ConnectTimeout != *test.expected.AppSecConfig.Timeout.ConnectTimeout {
				t.Errorf("expected %d, got %d", test.expected.AppSecConfig.Timeout.ConnectTimeout, tt.AppSecConfig.Timeout.ConnectTimeout)
			}
			if *tt.AppSecConfig.Timeout.TLSHandshakeTimeout != *test.expected.AppSecConfig.Timeout.TLSHandshakeTimeout {
				t.Errorf("expected %d, got %d", *test.expected.AppSecConfig.Timeout.TLSHandshakeTimeout, tt.AppSecConfig.Timeout.TLSHandshakeTimeout)
			}
			if *tt.AppSecConfig.Timeout.ResponseHeaderTimeout != *test.expected.AppSecConfig.Timeout.ResponseHeaderTimeout {
				t.Errorf("expected %d, got %d", *test.expected.AppSecConfig.Timeout.ResponseHeaderTimeout, tt.AppSecConfig.Timeout.ResponseHeaderTimeout)
			}
		})
	}
}

func TestWafParseClientReq(t *testing.T) {
	var headers = []string{
		"X-Crowdsec-Appsec-Ip",
		"X-Crowdsec-Appsec-Uri",
		"X-Crowdsec-Appsec-Host",
		"X-Crowdsec-Appsec-Verb",
		"X-Crowdsec-Appsec-Api-Key",
		"X-Crowdsec-Appsec-User-Agent",
	}
	var appsec = &csbouncer.AppSec{
		APIKey: "test",
		AppSecConfig: &csbouncer.AppSecConfig{
			Url: "http://localhost:7422/",
		},
	}
	appsec.Init()
	var tests = []struct {
		name     string
		request  *http.Request
		IP       string
		expected *http.Request
	}{
		{
			name: "Test simple request",
			request: &http.Request{
				Header: http.Header{
					"User-Agent": []string{"test"},
				},
				Method: http.MethodGet,
				Host:   "localhost",
				URL: &url.URL{
					Path: "/",
				},
				RemoteAddr: "192.168.1.1",
			},
			IP: "",
		},
		{
			name: "Test query request",
			request: &http.Request{
				Header: http.Header{
					"User-Agent": []string{"test"},
				},
				Method: http.MethodGet,
				Host:   "localhost",
				URL: &url.URL{
					Path:     "/",
					RawQuery: "test=test&url=../../etc/passwd",
				},
				RemoteAddr: "192.168.1.1",
			},
			IP: "",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			req, err := appsec.ParseClientReq(test.request, test.IP)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			// Check if the X-Crowdsec headers are set with a value that is not empty
			for _, header := range headers {
				if req.Header.Get(header) == "" {
					t.Errorf("expected %s to be set", header)
				}
			}

			// Test the api key header is set to the value of the API key
			if req.Header.Get("X-Crowdsec-Appsec-Api-Key") != appsec.APIKey {
				t.Errorf("expected %s, got %s", appsec.APIKey, req.Header.Get("X-Crowdsec-Appsec-Api-Key"))
			}

			// Check if the headers of the original request are set on the parsed request
			for key, headers := range test.request.Header {
				for _, value := range headers {
					if req.Header.Get(key) != value {
						t.Errorf("expected %s, got %s", value, req.Header.Get(key))
					}
				}
			}

			// Check the URL matches the URL of the original request
			if req.Header.Get("X-Crowdsec-Appsec-Uri") != test.request.URL.String() {
				t.Errorf("expected %s, got %s", test.request.URL.String(), req.Header.Get("X-Crowdsec-Appsec-Uri"))
			}
		})
	}
}
