use std::fmt::{Debug, Display};

pub const ROOT_TARGET: &str = "blokmap";

/// The body of an HTTP request
pub const HTTP_REQUEST_BODY: &str = build_attr!("http", "request", "body");

/// Build a static OTEL target string scoped on `blokmap`
#[macro_export]
macro_rules! build_target {
	($($chunk:literal),* $(,)?) => {
		concat!("blokmap", $("::", $chunk),*)
	}
}

/// Build a static OTEL attribute name scoped on `blokmap`
#[macro_export]
macro_rules! build_attr {
	($($chunk:literal),* $(,)?) => {
		concat!("blokmap", $(".", $chunk),*)
	}
}

pub use build_attr;
pub use build_target;

pub struct DisplayOptValue<T: Display>(Option<T>);

pub fn display_opt<T: Display>(t: Option<T>) -> DisplayOptValue<T> {
	DisplayOptValue(t)
}

impl<T: Display> Debug for DisplayOptValue<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		Display::fmt(self, f)
	}
}

impl<T: Display> Display for DisplayOptValue<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match &self.0 {
			Some(t) => t.fmt(f),
			None => write!(f, ""),
		}
	}
}
