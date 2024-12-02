module github.com/open-telemetry/opentelemetry-collector-contrib/processor/deltatocumulativeprocessor

go 1.22.0

require (
	github.com/google/go-cmp v0.6.0
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/exp/metrics v0.114.0
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest v0.114.0
	github.com/stretchr/testify v1.10.0
	go.opentelemetry.io/collector/component v0.114.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/component/componenttest v0.114.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/config/configtelemetry v0.114.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/confmap v1.20.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/consumer v0.114.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/consumer/consumertest v0.114.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/pdata v1.20.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/processor v0.114.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/collector/processor/processortest v0.114.1-0.20241130171227-c52d625647be
	go.opentelemetry.io/otel v1.32.0
	go.opentelemetry.io/otel/metric v1.32.0
	go.opentelemetry.io/otel/sdk/metric v1.32.0
	go.opentelemetry.io/otel/trace v1.32.0
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.0
	golang.org/x/tools v0.26.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/knadh/koanf/providers/confmap v0.1.0 // indirect
	github.com/knadh/koanf/v2 v2.1.2 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil v0.114.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.opentelemetry.io/collector/component/componentstatus v0.114.1-0.20241130171227-c52d625647be // indirect
	go.opentelemetry.io/collector/consumer/consumerprofiles v0.114.1-0.20241130171227-c52d625647be // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.114.1-0.20241130171227-c52d625647be // indirect
	go.opentelemetry.io/collector/pdata/testdata v0.114.1-0.20241130171227-c52d625647be // indirect
	go.opentelemetry.io/collector/pipeline v0.114.1-0.20241130171227-c52d625647be // indirect
	go.opentelemetry.io/collector/processor/processorprofiles v0.114.1-0.20241130171227-c52d625647be // indirect
	go.opentelemetry.io/otel/sdk v1.32.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240822170219-fc7c04adadcd // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
)

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil => ../../pkg/pdatautil

replace github.com/open-telemetry/opentelemetry-collector-contrib/internal/exp/metrics => ../../internal/exp/metrics

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest => ../../pkg/pdatatest

replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden => ../../pkg/golden
