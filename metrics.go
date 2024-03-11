package csbouncer

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
        "github.com/blackfireio/osinfo"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type MetricsUpdater func(*models.RemediationComponentsMetricsItems0)

const (
	minimumMetricsInterval = 15 * time.Minute
	defaultMetricsInterval = 30 * time.Minute
)

func SetMetricsInterval(interval *time.Duration, logger *logrus.Entry) *time.Duration {
	var ret time.Duration

	switch {
	case interval == nil:
		ret = defaultMetricsInterval
		logger.Tracef("metrics_interval is not set, default to %s", ret)
	case *interval == time.Duration(0):
		ret = 0
		logger.Info("metrics_interval is set to 0, disabling metrics")
	case *interval < minimumMetricsInterval:
		ret = minimumMetricsInterval
		logger.Warnf("metrics_interval is too low, setting it to %s", ret)
	default:
		ret = *interval
		logger.Tracef("metrics_interval set to %s", ret)
	}

	return &ret
}

func detectOS() (string, string) {
	if version.System == "docker" {
		return "docker", ""
	}

	osInfo, err := osinfo.GetOSInfo()
	if err != nil {
		return version.System, "???"
	}

	return osInfo.Name, osInfo.Version
}

type MetricsProvider struct {
	APIClient *apiclient.ApiClient
	Interval  time.Duration
	static    staticMetrics
	updater   MetricsUpdater
	logger    *logrus.Entry
}

type staticMetrics struct {
	osName            string
	osVersion         string
	startupTS         int64
	featureFlags      []string
	bouncerType       string
}

// newStaticMetrics should be called once over the lifetime of the program (more if we support hot-reload)
func newStaticMetrics(bouncerType string) staticMetrics {
	osName, osVersion := detectOS()

	return staticMetrics{
		osName:            osName,
		osVersion:         osVersion,
		startupTS:         time.Now().Unix(),
		featureFlags:      []string{},
		bouncerType:       bouncerType,
	}
}

func NewMetricsProvider(client *apiclient.ApiClient, bouncerType string, interval time.Duration, updater MetricsUpdater, logger *logrus.Entry) (*MetricsProvider, error) {
	return &MetricsProvider{
		APIClient: client,
		Interval: interval,
		updater: updater,
		static: newStaticMetrics(bouncerType),
		logger: logger,
	}, nil
}

func (m *MetricsProvider) metricsPayload() *models.AllMetrics {
	now := time.Now().Unix()

	meta := &models.MetricsMeta{
		UtcNowTimestamp: now,
		UtcStartupTimestamp: m.static.startupTS,
		WindowSizeSeconds: int64(m.Interval.Seconds()),
	}

	os := &models.OSversion{
		Name:    m.static.osName,
		Version: m.static.osVersion,
	}

	bouncerVersion := version.String()

	base := &models.BaseMetrics{
		Meta: meta,
		Os: os,
		Version: &bouncerVersion,
		FeatureFlags: m.static.featureFlags,
	}

	item0 := &models.RemediationComponentsMetricsItems0{
		BaseMetrics: *base,
		Type: m.static.bouncerType,
	}

	if m.updater != nil {
		m.updater(item0)
	}

	return &models.AllMetrics{
		RemediationComponents: []models.RemediationComponentsMetrics{{item0}},
	}
}

func (m *MetricsProvider) Run(ctx context.Context) error {
	if m.Interval == 0 {
		m.logger.Infof("usage metrics disabled")
		return nil
	}

	if m.updater == nil {
		m.logger.Warningf("no updater provided, metrics will be static")
	}

	ticker := time.NewTicker(m.Interval)

	m.logger.Tracef("sending usage metrics every %s", m.Interval)

	for {
		select {
		case <-ctx.Done():
			return errors.New("metric provider halted")
		case <-ticker.C:
			met := m.metricsPayload()

			ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			_, resp, err := m.APIClient.UsageMetrics.Add(ctxTime, met)
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				m.logger.Warnf("timeout sending metrics")
				continue
			case err != nil:
				m.logger.Warnf("failed to send metrics: %s", err)
				continue
			}

			if resp.Response.StatusCode != http.StatusCreated {
				m.logger.Warnf("failed to send metrics: %s", resp.Response.Status)
				continue
			}

			m.logger.Tracef("usage metrics sent")
		}
	}
}
