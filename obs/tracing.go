package obs

import (
	"context"
	"fmt"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// InitTracing installs the global OTel tracer provider and W3C trace-context
// propagation, and returns a shutdown function that flushes pending spans.
//
// With a resolvable GCP project (Cloud Run, or GOOGLE_CLOUD_PROJECT set)
// spans export to Cloud Trace. Locally the provider runs without an
// exporter: spans still get real ids — so log lines carry a shared traceId
// across services — but nothing leaves the process.
//
// The sampler records every span. At the current traffic volume full
// fidelity is worth more than the export cost; revisit with a ratio sampler
// when production volume makes it matter.
func InitTracing(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	if projectID == "" {
		projectID = resolveProjectID()
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceNameOr(serviceName))),
	)
	if err != nil {
		return nil, fmt.Errorf("build otel resource: %w", err)
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	}
	if projectID != "" {
		exporter, err := texporter.New(texporter.WithProjectID(projectID))
		if err != nil {
			return nil, fmt.Errorf("build cloud trace exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	provider := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return provider.Shutdown, nil
}
