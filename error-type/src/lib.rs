//! Low-cardinality error names for the OpenTelemetry `error.type` attribute.
use std::fmt::Display;

pub use error_type_derive::ErrorType;
use opentelemetry::trace::Status;
use opentelemetry_semantic_conventions::trace::ERROR_TYPE;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// A short, stable identifier for an error, suitable for `error.type`.
///
/// Must not contain runtime data (ids, messages): it is used as a grouping key.
pub trait ErrorType {
	fn error_type(&self) -> &'static str;
}

/// Helper trait to set otel `error.type` values on the current span
pub trait RecordError {
	fn record_err(self) -> Self;
}

impl<E: ErrorType + ?Sized> ErrorType for &E {
	fn error_type(&self) -> &'static str { (**self).error_type() }
}

impl<E: ErrorType + ?Sized> ErrorType for Box<E> {
	fn error_type(&self) -> &'static str { (**self).error_type() }
}

#[cfg(feature = "deadpool-diesel")]
impl ErrorType for deadpool_diesel::PoolError {
	fn error_type(&self) -> &'static str {
		match self {
			Self::Timeout(_) => "database_pool_timeout",
			Self::Backend(_) => "database_pool_backend_error",
			Self::Closed => "database_pool_closed",
			Self::NoRuntimeSpecified => "no_runtime_specified",
			Self::PostCreateHook(_) => "database_pool_post_create_hook_error",
		}
	}
}

impl<T, E: ErrorType + Display> RecordError for Result<T, E> {
	fn record_err(self) -> Self {
		if let Err(e) = &self {
			let span = Span::current();
			span.set_attribute(ERROR_TYPE, e.error_type());
			span.set_status(Status::error(e.to_string()));
		}

		self
	}
}
