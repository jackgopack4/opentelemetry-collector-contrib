// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package datadogfleetautomationextension

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensioncapabilities"
	"go.uber.org/zap"

	"github.com/DataDog/datadog-agent/comp/forwarder/defaultforwarder"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/util/compression"
	"github.com/DataDog/datadog-agent/pkg/util/uuid"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/datadogfleetautomationextension/internal/metadata"
)

type fleetAutomationExtension struct {
	extension.Extension // Embed base Extension for common functionality.

	extensionConfig *Config
	telemetry       component.TelemetrySettings
	collectorConfig *confmap.Conf
	mu              sync.RWMutex

	forwarder  *defaultforwarder.DefaultForwarder
	compressor *compression.Compressor
	serializer *serializer.Serializer
}

var _ extensioncapabilities.ConfigWatcher = (*fleetAutomationExtension)(nil)

// NotifyConfig implements the ConfigWatcher interface, which allows this extension
// to be notified of the Collector's effective configuration. See interface:
// https://github.com/open-telemetry/opentelemetry-collector/blob/d0fde2f6b98f13cbbd8657f8188207ac7d230ed5/extension/extension.go#L46.

// This method is called during the startup process by the Collector's Service right after
// calling Start.
func (e *fleetAutomationExtension) NotifyConfig(_ context.Context, conf *confmap.Conf) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.collectorConfig = conf
	e.telemetry.Logger.Info("Received new collector configuration")
	e.printCollectorConfig()
	var c otelMetadata
	err := e.collectorConfig.Unmarshal(&c)
	if err != nil {
		e.telemetry.Logger.Error("Failed to unmarshal collector configuration", zap.Error(err))
	}
	p := Payload{
		Hostname:  metadata.Type.String(),
		Timestamp: time.Now().UnixNano(),
		Metadata:  c,
		UUID:      uuid.GetUUID(),
	}
	e.telemetry.Logger.Info("Sending fleet automation payload to Datadog backend with:", zap.String("hostname", p.Hostname), zap.Int64("timestamp", p.Timestamp), zap.Any("metadata", p.Metadata), zap.String("uuid", p.UUID))
	err = e.serializer.SendMetadata(&p)
	if err != nil {
		e.telemetry.Logger.Error("Failed to send fleet automation payload to Datadog backend", zap.Error(err))
	}
	return nil
}

func (e *fleetAutomationExtension) printCollectorConfig() {
	configMap := e.collectorConfig.ToStringMap()
	configJSON, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		e.telemetry.Logger.Error(err.Error())
		return
	}
	e.telemetry.Logger.Info("Collector Configuration: ", zap.String("config", string(configJSON)))
}

// Start starts the extension via the component interface.
func (e *fleetAutomationExtension) Start(_ context.Context, _ component.Host) error {
	e.telemetry.Logger.Info("Started Datadog Fleet Automation extension")
	if e.forwarder != nil {
		err := e.forwarder.Start()
		if err != nil {
			e.telemetry.Logger.Error("Failed to start forwarder", zap.Error(err))
		}
	}
	return nil
}

// Shutdown stops the extension via the component interface.
func (e *fleetAutomationExtension) Shutdown(_ context.Context) error {
	e.telemetry.Logger.Info("Stopped Datadog Fleet Automation extension")
	e.forwarder.Stop()
	return nil
}

func newExtension(config *Config, telemetry component.TelemetrySettings) *fleetAutomationExtension {
	cfg := newConfigComponent(telemetry, config)
	log := newLogComponent(telemetry)
	// Initialize forwarder, compressor, and serializer components to forward OTel Inventory to REDAPL backend
	forwarder := newForwarder(cfg, log)
	compressor := newCompressor()
	serializer := newSerializer(forwarder, compressor, cfg)
	return &fleetAutomationExtension{
		extensionConfig: config,
		telemetry:       telemetry,
		collectorConfig: &confmap.Conf{},
		forwarder:       forwarder,
		compressor:      &compressor,
		serializer:      serializer,
	}
}
