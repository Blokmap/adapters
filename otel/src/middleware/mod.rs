//! Middleware to add OpenTelemetry semconv compliant HTTP server spans and
//! metrics
//!
//! See <https://opentelemetry.io/docs/specs/semconv/http/http-metrics/> &
//! <https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-server-definitions>

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use axum::extract::Request;
use axum::http::Response;
use http_body::Body;
use opentelemetry_semantic_conventions::trace::EXCEPTION_MESSAGE;
use pin_project::pin_project;
use tower::{Layer, Service};
use tracing::{Level, Span};

mod attributes;
mod instrumentation;
mod request;
mod response;

use attributes::OtelHttpAttributes;
use instrumentation::PreResponseInstrumentation;
use request::InstrumentedRequestBody;
use response::InstrumentedResponseBody;

use crate::metrics::AxumMetrics;

#[derive(Clone)]
pub struct OtelTraceLayer {
	axum_metrics: AxumMetrics,
}

impl OtelTraceLayer {
	#[must_use]
	pub fn new(axum_metrics_namespace: &'static str) -> Self {
		Self { axum_metrics: AxumMetrics::new(axum_metrics_namespace) }
	}
}

impl<S> Layer<S> for OtelTraceLayer {
	type Service = OtelTraceService<S>;

	fn layer(&self, inner: S) -> Self::Service {
		OtelTraceService { inner, metrics: self.axum_metrics.clone() }
	}
}

#[derive(Clone)]
pub struct OtelTraceService<S> {
	inner:   S,
	metrics: AxumMetrics,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for OtelTraceService<S>
where
	S: Service<
			Request<InstrumentedRequestBody<ReqBody>>,
			Response = Response<ResBody>,
		> + Clone
		+ Send
		+ 'static,
	S::Future: Send + 'static,
	S::Error: std::fmt::Display + 'static,
	ReqBody: Body,
	ResBody: Body,
{
	type Error = S::Error;
	type Future = ResponseFuture<S::Future>;
	type Response = Response<InstrumentedResponseBody<ResBody>>;

	fn poll_ready(
		&mut self,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
		let req_start = Instant::now();

		let attributes = OtelHttpAttributes::from(&req);
		let span = Span::from(&attributes);

		let req_body_size_counter = Arc::new(AtomicU64::new(0));
		let req = req.map(|b| {
			InstrumentedRequestBody::new(b, Arc::clone(&req_body_size_counter))
		});

		let active_reqs_labels = attributes.to_active_reqs_labels();
		self.metrics.active_requests.add(1, &active_reqs_labels);

		let inner_res_future = {
			let _guard = span.enter();
			self.inner.call(req)
		};

		let instrumentation = PreResponseInstrumentation::new(
			span.clone(),
			attributes,
			req_start,
			req_body_size_counter,
			self.metrics.request_duration.clone(),
			self.metrics.active_requests.clone(),
			self.metrics.request_size.clone(),
			self.metrics.response_size.clone(),
		);

		ResponseFuture {
			inner: inner_res_future,
			span,
			inst: Some(instrumentation),
		}
	}
}

#[pin_project]
#[repr(C)]
pub struct ResponseFuture<F> {
	#[pin]
	inner: F,
	span:  Span,
	inst:  Option<PreResponseInstrumentation>,
}

impl<F, E, ResBody> Future for ResponseFuture<F>
where
	F: Future<Output = Result<Response<ResBody>, E>>,
	ResBody: Body,
	E: std::fmt::Display + 'static,
{
	type Output = Result<Response<InstrumentedResponseBody<ResBody>>, E>;

	fn poll(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Self::Output> {
		let this = self.as_mut().project();
		let guard = this.span.enter();
		let res_result = ready!(this.inner.poll(cx));

		let res = match res_result {
			Ok(res) => res,
			Err(err) => {
				// The error.type field should be recorded here with
				// `this.span.record(ERROR_TYPE, err)`. However, OTEL specifies
				// that error.type should have low cardinality, which cannot be
				// enforced without restricting the error to a known type,
				// which in turn would break most of the router

				let inst = this.inst.take().unwrap();
				let active_reqs_labels =
					inst.attributes.to_active_reqs_labels();
				inst.active_requests_ud.add(-1, &active_reqs_labels);

				// See <https://opentelemetry.io/docs/specs/semconv/http/http-exceptions/#http-server-request-exception>
				event!(
					name: "http.server.request.exception",
					Level::ERROR,
					{EXCEPTION_MESSAGE} = %err,
				);
				return Poll::Ready(Err(err));
			},
		};

		let inst = this.inst.take().unwrap();
		let completed_inst = inst.complete(&res);

		let new_span = completed_inst.span.clone();
		drop(guard);
		let _guard = new_span.enter();

		let res = res.map(|b| InstrumentedResponseBody::new(b, completed_inst));

		Poll::Ready(Ok(res))
	}
}
