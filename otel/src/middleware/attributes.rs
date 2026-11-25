use std::borrow::Cow;
use std::marker::PhantomData;
use std::str::FromStr;

use axum::extract::MatchedPath;
use axum::http::{Request, Response, Uri};
use http_body::Body;
use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions::trace::{
	CLIENT_ADDRESS,
	ERROR_TYPE,
	HTTP_REQUEST_METHOD,
	HTTP_RESPONSE_STATUS_CODE,
	HTTP_ROUTE,
	SERVER_ADDRESS,
	SERVER_PORT,
	URL_PATH,
	URL_QUERY,
	URL_SCHEME,
	USER_AGENT_ORIGINAL,
};
use reqwest::header::{HOST, USER_AGENT};
use tracing::field::Empty;
use tracing::{Level, Span};

pub trait HttpServerSpanState {}

#[derive(Debug, Clone, Copy)]
pub struct PreResponse;
#[derive(Debug, Clone, Copy)]
pub struct PostResponse;

impl HttpServerSpanState for PreResponse {}
impl HttpServerSpanState for PostResponse {}

#[derive(Debug, Clone)]
pub struct OtelHttpAttributes<S: HttpServerSpanState> {
	http_request_method: String,
	url_path:            String,
	url_scheme:          Cow<'static, str>,

	error_type:                Option<String>,
	http_response_status_code: Option<u16>,

	http_route:          Cow<'static, str>,
	server_port:         Option<u16>,
	url_query:           Option<String>,
	client_address:      Option<String>,
	server_address:      Option<String>,
	user_agent_original: Option<String>,

	_state: PhantomData<S>,
}

impl<B: Body> From<&Request<B>> for OtelHttpAttributes<PreResponse> {
	fn from(request: &Request<B>) -> Self {
		let req_uri = request.uri();
		let host_header_uri = request
			.headers()
			.get(HOST)
			.and_then(|v| v.to_str().ok())
			.and_then(|h| Uri::from_str(h).ok());

		// Required attributes
		let http_route = request
			.extensions()
			.get::<MatchedPath>()
			.map_or(Cow::from("/"), |p| Cow::Owned(p.as_str().to_owned()));
		let http_request_method = request.method().to_owned().to_string();
		let url_path = req_uri.path().to_owned();
		let url_scheme = request
			.headers()
			.get("x-forwarded-proto")
			.and_then(|v| v.to_str().ok())
			.or(req_uri.scheme_str())
			.or(host_header_uri.as_ref().and_then(|u| u.scheme_str()))
			.map_or(Cow::from("http"), |s| Cow::Owned(s.to_owned()));

		// Optional attributes
		let server_port = req_uri
			.port()
			.map(|p| p.as_u16())
			.or(host_header_uri.as_ref().and_then(Uri::port_u16));

		let url_query = req_uri.query().map(ToString::to_string);

		let first_forwarded_for = request
			.headers()
			.get("x-forwarded-for")
			.and_then(|v| v.to_str().ok())
			.and_then(|s| s.split(',').next());
		let real_ip =
			request.headers().get("x-real-ip").and_then(|v| v.to_str().ok());
		let client_address =
			first_forwarded_for.or(real_ip).map(ToOwned::to_owned);

		let server_address =
			req_uri.host().map(ToString::to_string).or(host_header_uri
				.as_ref()
				.and_then(|u| u.host())
				.map(ToString::to_string));

		let user_agent_original = request
			.headers()
			.get(USER_AGENT)
			.and_then(|v| v.to_str().ok())
			.map(ToOwned::to_owned);

		Self {
			http_request_method,
			url_path,
			url_scheme,

			error_type: None,
			http_response_status_code: None,

			http_route,
			server_port,
			url_query,
			client_address,
			server_address,
			user_agent_original,

			_state: PhantomData,
		}
	}
}

impl From<&OtelHttpAttributes<PreResponse>> for Span {
	fn from(attrs: &OtelHttpAttributes<PreResponse>) -> Self {
		let otel_name =
			format!("{} {}", attrs.http_request_method, attrs.http_route);

		let span = tracing::span!(
			target: "routes",
			Level::INFO,
			"request",
			otel.name = %otel_name,
			otel.kind = "server",
			{HTTP_REQUEST_METHOD} = %attrs.http_request_method,
			{URL_PATH} = %attrs.url_path,
			{URL_SCHEME} = %attrs.url_scheme,
			{ERROR_TYPE} = Empty,
			{HTTP_RESPONSE_STATUS_CODE} = Empty,
			{HTTP_ROUTE} = %attrs.http_route,
			{SERVER_PORT} = Empty,
			{URL_QUERY} = Empty,
			{CLIENT_ADDRESS} = Empty,
			{SERVER_ADDRESS} = Empty,
			{USER_AGENT_ORIGINAL} = Empty,
		);

		if let Some(server_port) = attrs.server_port {
			span.record(SERVER_PORT, server_port);
		}
		if let Some(url_query) = &attrs.url_query {
			span.record(URL_QUERY, url_query);
		}
		if let Some(client_address) = &attrs.client_address {
			span.record(CLIENT_ADDRESS, client_address);
		}
		if let Some(server_address) = &attrs.server_address {
			span.record(SERVER_ADDRESS, server_address);
		}
		if let Some(user_agent_original) = &attrs.user_agent_original {
			span.record(USER_AGENT_ORIGINAL, user_agent_original);
		}

		span
	}
}

impl<S: HttpServerSpanState> OtelHttpAttributes<S> {
	/// See <https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserveractive_requests>
	#[inline]
	#[must_use]
	pub fn to_active_reqs_labels(&self) -> Vec<KeyValue> {
		let mut kv = Vec::with_capacity(4);

		kv.extend([
			KeyValue::new(
				HTTP_REQUEST_METHOD,
				self.http_request_method.clone(),
			),
			KeyValue::new(URL_SCHEME, self.url_scheme.clone()),
		]);

		if let Some(server_address) = &self.server_address {
			kv.push(KeyValue::new(SERVER_ADDRESS, server_address.to_owned()));
		}
		if let Some(server_port) = self.server_port {
			kv.push(KeyValue::new(
				SERVER_PORT,
				i64::from(server_port.cast_signed()),
			));
		}

		kv
	}
}

impl OtelHttpAttributes<PreResponse> {
	pub fn complete<B: Body>(
		self,
		response: &Response<B>,
	) -> OtelHttpAttributes<PostResponse> {
		let error_type = response
			.status()
			.canonical_reason()
			.unwrap_or(response.status().as_str())
			.to_owned();
		let http_response_status_code = response.status().as_u16();

		OtelHttpAttributes {
			http_request_method: self.http_request_method,
			url_path:            self.url_path,
			url_scheme:          self.url_scheme,

			error_type:                Some(error_type),
			http_response_status_code: Some(http_response_status_code),

			http_route:          self.http_route,
			server_port:         self.server_port,
			url_query:           self.url_query,
			client_address:      self.client_address,
			server_address:      self.server_address,
			user_agent_original: self.user_agent_original,

			_state: PhantomData,
		}
	}
}

impl OtelHttpAttributes<PostResponse> {
	/// See <https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestduration>
	#[inline]
	#[must_use]
	pub fn to_req_duration_labels(&self) -> Vec<KeyValue> {
		let mut kv = Vec::with_capacity(7);

		kv.extend([
			KeyValue::new(
				HTTP_REQUEST_METHOD,
				self.http_request_method.clone(),
			),
			KeyValue::new(URL_SCHEME, self.url_scheme.clone()),
			KeyValue::new(HTTP_ROUTE, self.http_route.clone()),
		]);

		if let Some(error_type) = &self.error_type {
			kv.push(KeyValue::new(ERROR_TYPE, error_type.to_owned()));
		}
		if let Some(http_response_status_code) = self.http_response_status_code
		{
			kv.push(KeyValue::new(
				HTTP_RESPONSE_STATUS_CODE,
				i64::from(http_response_status_code.cast_signed()),
			));
		}
		if let Some(server_address) = &self.server_address {
			kv.push(KeyValue::new(SERVER_ADDRESS, server_address.to_owned()));
		}
		if let Some(server_port) = self.server_port {
			kv.push(KeyValue::new(
				SERVER_PORT,
				i64::from(server_port.cast_signed()),
			));
		}

		kv
	}

	/// See <https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestbodysize>
	#[inline]
	#[must_use]
	pub fn to_req_body_size_labels(&self) -> Vec<KeyValue> {
		let mut kv = Vec::with_capacity(7);

		kv.extend([
			KeyValue::new(
				HTTP_REQUEST_METHOD,
				self.http_request_method.clone(),
			),
			KeyValue::new(URL_SCHEME, self.url_scheme.clone()),
			KeyValue::new(HTTP_ROUTE, self.http_route.clone()),
		]);

		if let Some(error_type) = &self.error_type {
			kv.push(KeyValue::new(ERROR_TYPE, error_type.to_owned()));
		}
		if let Some(http_response_status_code) = self.http_response_status_code
		{
			kv.push(KeyValue::new(
				HTTP_RESPONSE_STATUS_CODE,
				i64::from(http_response_status_code.cast_signed()),
			));
		}
		if let Some(server_address) = &self.server_address {
			kv.push(KeyValue::new(SERVER_ADDRESS, server_address.to_owned()));
		}
		if let Some(server_port) = self.server_port {
			kv.push(KeyValue::new(
				SERVER_PORT,
				i64::from(server_port.cast_signed()),
			));
		}

		kv
	}

	/// See <https://opentelemetry.io/docs/specs/semconv/http/http-metrics/#metric-httpserverrequestbodysize>
	#[inline]
	#[must_use]
	pub fn to_res_body_size_labels(&self) -> Vec<KeyValue> {
		let mut kv = Vec::with_capacity(7);

		kv.extend([
			KeyValue::new(
				HTTP_REQUEST_METHOD,
				self.http_request_method.clone(),
			),
			KeyValue::new(URL_SCHEME, self.url_scheme.clone()),
			KeyValue::new(HTTP_ROUTE, self.http_route.clone()),
		]);

		if let Some(error_type) = &self.error_type {
			kv.push(KeyValue::new(ERROR_TYPE, error_type.to_owned()));
		}
		if let Some(http_response_status_code) = self.http_response_status_code
		{
			kv.push(KeyValue::new(
				HTTP_RESPONSE_STATUS_CODE,
				i64::from(http_response_status_code.cast_signed()),
			));
		}
		if let Some(server_address) = &self.server_address {
			kv.push(KeyValue::new(SERVER_ADDRESS, server_address.to_owned()));
		}
		if let Some(server_port) = self.server_port {
			kv.push(KeyValue::new(
				SERVER_PORT,
				i64::from(server_port.cast_signed()),
			));
		}

		kv
	}

	pub fn complete_span(&self, span: Span) -> Span {
		let new_span = span;

		if let Some(error_type) = &self.error_type {
			new_span.record(ERROR_TYPE, error_type);
		}
		if let Some(http_response_status_code) = self.http_response_status_code
		{
			new_span
				.record(HTTP_RESPONSE_STATUS_CODE, http_response_status_code);
		}

		new_span
	}
}
