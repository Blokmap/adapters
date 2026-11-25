use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use pin_project::pin_project;

#[pin_project]
#[repr(C)]
pub struct InstrumentedRequestBody<B: Body> {
	#[pin]
	body:              B,
	body_size_counter: Arc<AtomicU64>,
}

impl<B: Body> InstrumentedRequestBody<B> {
	pub fn new(body: B, body_size_counter: Arc<AtomicU64>) -> Self {
		Self { body, body_size_counter }
	}
}

impl<B: Body> Body for InstrumentedRequestBody<B> {
	type Data = B::Data;
	type Error = B::Error;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = self.project();
		let buff = ready!(this.body.poll_frame(cx));

		if let Some(Ok(frame)) = &buff
			&& let Some(data) = frame.data_ref()
		{
			this.body_size_counter
				.fetch_add(data.remaining() as u64, Ordering::Relaxed);
		}

		Poll::Ready(buff)
	}

	fn is_end_stream(&self) -> bool { self.body.is_end_stream() }

	fn size_hint(&self) -> SizeHint { self.body.size_hint() }
}
