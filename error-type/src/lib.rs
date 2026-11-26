//! Low-cardinality error names for the OpenTelemetry `error.type` attribute.
pub use error_type_derive::ErrorType;

/// A short, stable identifier for an error, suitable for `error.type`.
///
/// Must not contain runtime data (ids, messages): it is used as a grouping key.
pub trait ErrorType {
	fn error_type(&self) -> &'static str;
}

impl<E: ErrorType + ?Sized> ErrorType for &E {
	fn error_type(&self) -> &'static str { (**self).error_type() }
}

impl<E: ErrorType + ?Sized> ErrorType for Box<E> {
	fn error_type(&self) -> &'static str { (**self).error_type() }
}

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
