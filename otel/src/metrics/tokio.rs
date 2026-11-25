use opentelemetry::{KeyValue, global};
use tokio::runtime::Handle;

const TOKIO_THREAD_UNIT: &str = "{thread}";
const TOKIO_TASK_UNIT: &str = "{task}";

const TOKIO_WORKER_COUNT: &str = "tokio.worker.count";
const TOKIO_BLOCKING_COUNT: &str = "tokio.blocking_thread.count";

const TOKIO_TASK_COUNT: &str = "tokio.task.count";
const TOKIO_BLOCKING_TASK_COUNT: &str = "tokio.blocking_task.count";

const TOKIO_BLOCKING_STATE: &str = "tokio.blocking_thread.state";
const TOKIO_TASK_STATE: &str = "tokio.task.state";

pub struct TokioMetricsService;

impl TokioMetricsService {
	pub fn start() {
		let handle = Handle::current();
		let metrics = handle.metrics();

		let meter = global::meter("blokmap.core.metrics.tokio");

		// The number of worker threads doesn't change after startup
		let worker_meter = meter
			.i64_up_down_counter(TOKIO_WORKER_COUNT)
			.with_description(
				"Number of worker threads used by the tokio runtime",
			)
			.with_unit(TOKIO_TASK_UNIT)
			.build();

		#[allow(clippy::cast_possible_wrap)]
		let workers = metrics.num_workers() as i64;
		worker_meter.add(workers, &[]);

		let thread_handle = handle.clone();
		meter
			.i64_observable_up_down_counter(TOKIO_BLOCKING_COUNT)
			.with_description(
				"Number of threads used by the tokio runtime, by state",
			)
			.with_unit(TOKIO_THREAD_UNIT)
			.with_callback(move |observer| {
				let metrics = thread_handle.metrics();

				#[allow(clippy::cast_possible_wrap)]
				let blocking = metrics.num_blocking_threads() as i64;
				#[allow(clippy::cast_possible_wrap)]
				let idle_blocking = metrics.num_idle_blocking_threads() as i64;

				let active_blocking = blocking - idle_blocking;

				observer.observe(
					active_blocking,
					&[KeyValue::new(TOKIO_BLOCKING_STATE, "active")],
				);
				observer.observe(
					idle_blocking,
					&[KeyValue::new(TOKIO_BLOCKING_STATE, "idle")],
				);
			})
			.build();

		let task_handle = handle.clone();
		meter
			.i64_observable_up_down_counter(TOKIO_TASK_COUNT)
			.with_description("Number tasks in the tokio runtime, by state")
			.with_unit(TOKIO_TASK_UNIT)
			.with_callback(move |observer| {
				let metrics = task_handle.metrics();

				#[allow(clippy::cast_possible_wrap)]
				let alive = metrics.num_alive_tasks() as i64;
				#[allow(clippy::cast_possible_wrap)]
				let pending = metrics.global_queue_depth() as i64;

				observer.observe(
					alive,
					&[KeyValue::new(TOKIO_TASK_STATE, "alive")],
				);
				observer.observe(
					pending,
					&[KeyValue::new(TOKIO_TASK_STATE, "pending")],
				);
			})
			.build();

		let btask_handle = handle.clone();
		meter
			.i64_observable_up_down_counter(TOKIO_BLOCKING_TASK_COUNT)
			.with_description(
				"Number of blocking tasks in the tokio runtime, by state",
			)
			.with_unit(TOKIO_TASK_UNIT)
			.with_callback(move |observer| {
				let metrics = btask_handle.metrics();

				#[allow(clippy::cast_possible_wrap)]
				let btasks = metrics.blocking_queue_depth() as i64;

				observer.observe(
					btasks,
					&[KeyValue::new(TOKIO_TASK_STATE, "pending")],
				);
			})
			.build();
	}
}
