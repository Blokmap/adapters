use std::time::Duration;

use opentelemetry::trace::TracerProvider;
use opentelemetry::{KeyValue, global};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::tonic_types::metadata::MetadataMap;
use opentelemetry_otlp::{
	LogExporter,
	MetricExporter,
	Protocol,
	SpanExporter,
	WithExportConfig,
	WithTonicConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{
	PeriodicReader,
	SdkMeterProvider,
	Temporality,
};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_semantic_conventions::SCHEMA_URL;
use opentelemetry_semantic_conventions::attribute::SERVICE_NAMESPACE;
use opentelemetry_semantic_conventions::resource::DEPLOYMENT_ENVIRONMENT_NAME;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone, Debug)]
pub struct TelemetryConfig {
	pub log_filter:        EnvFilter,
	pub service_name:      String,
	pub service_namespace: String,
	pub environment:       String,
	pub otlp_url:          String,
	pub auth_token:        String,
}

impl TelemetryConfig {
	/// Create a [`TelemetryConfig`] from env vars
	#[must_use]
	pub fn new(
		log_filter: EnvFilter,
		service_name: String,
		service_namespace: String,
		environment: String,
		otlp_url: String,
		auth_token: String,
	) -> Self {
		Self {
			log_filter,
			service_name,
			service_namespace,
			environment,
			otlp_url,
			auth_token,
		}
	}
}

#[allow(clippy::struct_field_names)]
pub struct InstrumentationProvider {
	tracer_provider: SdkTracerProvider,
	logger_provider: SdkLoggerProvider,
	meter_provider:  SdkMeterProvider,
}

impl InstrumentationProvider {
	/// Initialise the telemetry service
	///
	/// # Panics
	/// Panics if building the span exporter fails
	#[must_use]
	pub fn init(config: &TelemetryConfig) -> InstrumentationProvider {
		let fmt_layer = tracing_subscriber::fmt::layer()
			.pretty()
			.with_thread_names(true)
			.with_target(true);

		let mut otel_meta = MetadataMap::with_capacity(3);
		otel_meta.insert("authorization", config.auth_token.parse().unwrap());
		otel_meta.insert("organization", "default".parse().unwrap());
		otel_meta.insert("stream-name", "default".parse().unwrap());

		let span_exporter = SpanExporter::builder()
			.with_tonic()
			.with_endpoint(config.otlp_url.clone())
			.with_protocol(Protocol::Grpc)
			.with_metadata(otel_meta.clone())
			.build()
			.expect("failed to build OTLP span exporter");

		let log_exporter = LogExporter::builder()
			.with_tonic()
			.with_endpoint(config.otlp_url.clone())
			.with_protocol(Protocol::Grpc)
			.with_metadata(otel_meta.clone())
			.build()
			.expect("failed to build OTLP log exporter");

		let metric_exporter = MetricExporter::builder()
			.with_tonic()
			.with_endpoint(config.otlp_url.clone())
			.with_protocol(Protocol::Grpc)
			.with_metadata(otel_meta.clone())
			.with_temporality(Temporality::Delta)
			.build()
			.expect("failed to build OTLP metric exporter");

		let metric_reader = PeriodicReader::builder(metric_exporter)
			.with_interval(Duration::from_secs(45))
			.build();

		let resource = Resource::builder()
			.with_service_name(config.service_name.clone())
			.with_schema_url(
				[
					KeyValue::new(
						SERVICE_NAMESPACE,
						config.service_namespace.clone(),
					),
					KeyValue::new(
						DEPLOYMENT_ENVIRONMENT_NAME,
						config.environment.clone(),
					),
				],
				SCHEMA_URL,
			)
			.build();

		let tracer_provider = SdkTracerProvider::builder()
			.with_batch_exporter(span_exporter)
			.with_resource(resource.clone())
			.build();

		let logger_provider = SdkLoggerProvider::builder()
			.with_batch_exporter(log_exporter)
			.with_resource(resource.clone())
			.build();

		let meter_provider = SdkMeterProvider::builder()
			.with_reader(metric_reader)
			.with_resource(resource.clone())
			.build();

		global::set_tracer_provider(tracer_provider.clone());
		global::set_meter_provider(meter_provider.clone());

		let tracer = tracer_provider.tracer(config.service_name.clone());

		let otel_tracing_layer =
			tracing_opentelemetry::layer().with_tracer(tracer);
		let otel_logging_layer =
			OpenTelemetryTracingBridge::new(&logger_provider);

		tracing_subscriber::registry()
			.with(config.log_filter.clone())
			.with(fmt_layer)
			.with(otel_tracing_layer)
			.with(otel_logging_layer)
			.init();

		InstrumentationProvider {
			tracer_provider,
			logger_provider,
			meter_provider,
		}
	}
}

impl Drop for InstrumentationProvider {
	fn drop(&mut self) {
		if let Err(err) = self.tracer_provider.shutdown() {
			eprintln!("{err:?}");
		}

		if let Err(err) = self.logger_provider.shutdown() {
			eprintln!("{err:?}");
		}

		if let Err(err) = self.meter_provider.shutdown() {
			eprintln!("{err:?}");
		}
	}
}
