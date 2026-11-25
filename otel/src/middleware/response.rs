use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use pin_project::pin_project;

use crate::middleware::instrumentation::PostResponseInstrumentation;

#[pin_project]
#[repr(C)]
pub struct InstrumentedResponseBody<B: Body> {
	#[pin]
	body: B,
	inst: PostResponseInstrumentation,
}

impl<B: Body> InstrumentedResponseBody<B> {
	pub fn new(body: B, inst: PostResponseInstrumentation) -> Self {
		Self { body, inst }
	}
}

impl<B: Body> Body for InstrumentedResponseBody<B> {
	type Data = B::Data;
	type Error = B::Error;

	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = self.as_mut().project();
		let buff = ready!(this.body.poll_frame(cx));

		if let Some(Ok(frame)) = &buff
			&& let Some(data) = frame.data_ref()
		{
			this.inst.res_body_size_counter += data.remaining() as u64;
		}

		Poll::Ready(buff)
	}

	fn is_end_stream(&self) -> bool { self.body.is_end_stream() }

	fn size_hint(&self) -> SizeHint { self.body.size_hint() }
}
