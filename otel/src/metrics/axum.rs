use opentelemetry::global;
use opentelemetry::metrics::{Histogram, UpDownCounter};
use opentelemetry_semantic_conventions::metric::{
	HTTP_SERVER_ACTIVE_REQUESTS,
	HTTP_SERVER_REQUEST_BODY_SIZE,
	HTTP_SERVER_REQUEST_DURATION,
	HTTP_SERVER_RESPONSE_BODY_SIZE,
};

const DURATION_BUCKETS: [f64; 7] =
	[0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 5.000];

const REQ_SIZE_BUCKETS: [f64; 5] =
	[500.0, 1_000.0, 10_000.0, 500_000.0, 3_000_000.0];

const RES_SIZE_BUCKETS: [f64; 5] =
	[500.0, 1_000.0, 10_000.0, 500_000.0, 3_000_000.0];

#[derive(Clone)]
pub struct AxumMetrics {
	pub active_requests:  UpDownCounter<i64>,
	pub request_duration: Histogram<f64>,
	pub request_size:     Histogram<u64>,
	pub response_size:    Histogram<u64>,
}

impl Default for AxumMetrics {
	fn default() -> Self { Self::new("blokmap.metrics.axum") }
}

impl AxumMetrics {
	#[must_use]
	pub fn new(namespace: &'static str) -> Self {
		let meter = global::meter(namespace);

		let active_requests: UpDownCounter<i64> = meter
			.i64_up_down_counter(HTTP_SERVER_ACTIVE_REQUESTS)
			.with_description("Number of active HTTP requests")
			.with_unit("{request}")
			.build();

		let request_duration: Histogram<f64> = meter
			.f64_histogram(HTTP_SERVER_REQUEST_DURATION)
			.with_description("Duration of HTTP server requests")
			.with_unit("s")
			.with_boundaries(DURATION_BUCKETS.to_vec())
			.build();

		let request_size: Histogram<u64> = meter
			.u64_histogram(HTTP_SERVER_REQUEST_BODY_SIZE)
			.with_description("Size of HTTP server request bodies")
			.with_boundaries(REQ_SIZE_BUCKETS.to_vec())
			.with_unit("By")
			.build();

		let response_size: Histogram<u64> = meter
			.u64_histogram(HTTP_SERVER_RESPONSE_BODY_SIZE)
			.with_description("Size of HTTP server response bodies")
			.with_boundaries(RES_SIZE_BUCKETS.to_vec())
			.with_unit("By")
			.build();

		Self { active_requests, request_duration, request_size, response_size }
	}
}
