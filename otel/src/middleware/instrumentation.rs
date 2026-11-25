use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::http::Response;
use http_body::Body;
use opentelemetry::metrics::{Histogram, UpDownCounter};
use tracing::Span;

use crate::middleware::attributes::{
	OtelHttpAttributes,
	PostResponse,
	PreResponse,
};

#[derive(Debug, Clone)]
pub struct PreResponseInstrumentation {
	pub(super) span:       Span,
	pub(super) attributes: OtelHttpAttributes<PreResponse>,

	pub(super) req_start:             Instant,
	pub(super) req_body_size_counter: Arc<AtomicU64>,

	pub(super) req_duration_hist:  Histogram<f64>,
	pub(super) active_requests_ud: UpDownCounter<i64>,
	pub(super) req_body_size_hist: Histogram<u64>,
	pub(super) res_body_size_hist: Histogram<u64>,
}

#[derive(Debug, Clone)]
pub struct PostResponseInstrumentation {
	pub(super) span:       Span,
	pub(super) attributes: OtelHttpAttributes<PostResponse>,

	pub(super) req_start:             Instant,
	pub(super) req_body_size_counter: Arc<AtomicU64>,
	pub(super) res_body_size_counter: u64,

	pub(super) req_duration_hist:  Histogram<f64>,
	pub(super) active_requests_ud: UpDownCounter<i64>,
	pub(super) req_body_size_hist: Histogram<u64>,
	pub(super) res_body_size_hist: Histogram<u64>,
}

impl PreResponseInstrumentation {
	#[allow(clippy::similar_names)]
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		span: Span,
		attributes: OtelHttpAttributes<PreResponse>,
		req_start: Instant,
		req_body_size_counter: Arc<AtomicU64>,
		req_duration_hist: Histogram<f64>,
		active_requests_ud: UpDownCounter<i64>,
		req_body_size_hist: Histogram<u64>,
		res_body_size_hist: Histogram<u64>,
	) -> Self {
		Self {
			span,
			attributes,
			req_start,
			req_body_size_counter,
			req_duration_hist,
			active_requests_ud,
			req_body_size_hist,
			res_body_size_hist,
		}
	}

	pub fn complete<B: Body>(
		self,
		response: &Response<B>,
	) -> PostResponseInstrumentation {
		let completed_attributes = self.attributes.complete(response);
		let completed_span = completed_attributes.complete_span(self.span);

		PostResponseInstrumentation {
			span:                  completed_span,
			attributes:            completed_attributes,
			req_start:             self.req_start,
			req_body_size_counter: self.req_body_size_counter,
			res_body_size_counter: 0,
			req_duration_hist:     self.req_duration_hist,
			active_requests_ud:    self.active_requests_ud,
			req_body_size_hist:    self.req_body_size_hist,
			res_body_size_hist:    self.res_body_size_hist,
		}
	}
}

impl Drop for PostResponseInstrumentation {
	#[allow(clippy::similar_names)]
	fn drop(&mut self) {
		let req_duration_labels = self.attributes.to_req_duration_labels();
		let request_duration = self.req_start.elapsed().as_secs_f64();
		self.req_duration_hist.record(request_duration, &req_duration_labels);

		let active_reqs_labels = self.attributes.to_active_reqs_labels();
		self.active_requests_ud.add(-1, &active_reqs_labels);

		let req_body_size_labels = self.attributes.to_req_body_size_labels();
		let req_body_size = self.req_body_size_counter.load(Ordering::Relaxed);
		self.req_body_size_hist.record(req_body_size, &req_body_size_labels);

		let res_body_size_labels = self.attributes.to_res_body_size_labels();
		let res_body_size = self.res_body_size_counter;
		self.res_body_size_hist.record(res_body_size, &res_body_size_labels);
	}
}
