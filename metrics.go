package csbouncer

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/version"
)

type MetricsUpdater func(*models.RemediationComponentsMetrics, time.Duration)

const (
	defaultMetricsInterval = 15 * time.Minute
)

type MetricsProvider struct {
	APIClient *apiclient.ApiClient
	Interval  time.Duration
	static    staticMetrics
	updater   MetricsUpdater
	logger    logrus.FieldLogger
}

type staticMetrics struct {
	osName       string
	osVersion    string
	startupTS    int64
	featureFlags []string
	bouncerType  string
}

// newStaticMetrics should be called once over the lifetime of the program (more if we support hot-reload)
func newStaticMetrics(bouncerType string) staticMetrics {
	osName, osVersion := version.DetectOS()

	return staticMetrics{
		osName:       osName,
		osVersion:    osVersion,
		startupTS:    time.Now().Unix(),
		featureFlags: []string{},
		bouncerType:  bouncerType,
	}
}

func NewMetricsProvider(client *apiclient.ApiClient, bouncerType string, updater MetricsUpdater, logger logrus.FieldLogger) (*MetricsProvider, error) {
	return &MetricsProvider{
		APIClient: client,
		Interval:  defaultMetricsInterval,
		updater:   updater,
		static:    newStaticMetrics(bouncerType),
		logger:    logger,
	}, nil
}

func (m *MetricsProvider) metricsPayload() *models.AllMetrics {
	os := &models.OSversion{
		Name:    &m.static.osName,
		Version: &m.static.osVersion,
	}

	bouncerVersion := version.String()

	base := &models.BaseMetrics{
		Os:                  os,
		Version:             &bouncerVersion,
		FeatureFlags:        m.static.featureFlags,
		Metrics:             make([]*models.DetailedMetrics, 0),
		UtcStartupTimestamp: &m.static.startupTS,
	}

	item0 := &models.RemediationComponentsMetrics{
		BaseMetrics: *base,
		Type:        m.static.bouncerType,
	}

	if m.updater != nil {
		m.updater(item0, m.Interval)
	}

	return &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{item0},
	}
}

func (m *MetricsProvider) sendMetrics(ctx context.Context) {
	ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	met := m.metricsPayload()

	_, resp, err := m.APIClient.UsageMetrics.Add(ctxTime, met)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		m.logger.Warnf("timeout sending metrics")
	case resp != nil && resp.Response != nil && resp.Response.StatusCode == http.StatusNotFound:
		m.logger.Warnf("metrics endpoint not found, older LAPI?")
	case err != nil:
		m.logger.Warnf("failed to send metrics: %s", err)
	case resp.Response.StatusCode != http.StatusCreated:
		m.logger.Warnf("failed to send metrics: %s", resp.Response.Status)
	default:
		m.logger.Debug("usage metrics sent")
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

	for {
		select {
		case <-ctx.Done():
			return errors.New("metric provider halted")
		case <-ticker.C:
			m.sendMetrics(ctx)
		}
	}
}
