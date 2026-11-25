use std::sync::{Arc, RwLock};
use std::time::Duration;

use opentelemetry::{KeyValue, global};
use opentelemetry_semantic_conventions::attribute::CPU_LOGICAL_NUMBER;
use opentelemetry_semantic_conventions::metric::{
	SYSTEM_CPU_LOGICAL_COUNT,
	SYSTEM_CPU_PHYSICAL_COUNT,
	SYSTEM_CPU_UTILIZATION,
	SYSTEM_MEMORY_LIMIT,
	SYSTEM_MEMORY_USAGE,
	SYSTEM_MEMORY_UTILIZATION,
};
use sysinfo::System;

const TARGET: &str = crate::build_target!("metrics", "host");

#[derive(Clone, Debug)]
pub struct HostMetricsService {
	cpu_physical_cores: i64,
	cpu_logical_cores:  i64,
	per_core_cpu_util:  Vec<f64>,
	memory_util:        f64,
	memory_usage:       i64,
	memory_total:       i64,
}

#[rustfmt::skip]
impl HostMetricsService {
	/// Start collecting host metrics and set up meters to track them
	///
	/// # Panics
	/// Panics if getting the system info fails
	pub fn start() {
		let mut system = System::new_all().unwrap();
		system.refresh_cpu_usage();
		let num_cores = system.cpus().len().max(1);

		let per_core_cpu_usage = vec![0f64; num_cores];

		let metrics = Self {
			cpu_physical_cores: 0,
			cpu_logical_cores:  0,
			per_core_cpu_util:  per_core_cpu_usage,
			memory_util:        0.,
			memory_usage:       0,
			memory_total:       0,
		};
		let metrics = Arc::new(RwLock::new(metrics));

		tokio::spawn(Self::host_metrics_update_worker(Arc::clone(&metrics)));

		Self::build_host_metrics(&metrics);
	}

	#[instrument(skip_all, level = "debug", target = TARGET)]
	#[allow(clippy::too_many_lines)]
	fn build_host_metrics(host_metrics: &Arc<RwLock<Self>>) {
		let mut system = System::new_all().unwrap();
		system.refresh_cpu_usage();
		let num_cores = system.cpus().len().max(1);

		let meter = global::meter("blokmap.core.metrics.host");

		let phys_metrics = Arc::clone(host_metrics);
		let _phys_cores = meter
			.i64_observable_up_down_counter(SYSTEM_CPU_PHYSICAL_COUNT)
			.with_description("Physical CPU Cores")
			.with_unit("{cpu}")
			.with_callback(move |observer| {
				let span = debug_span!(TARGET, "cpu_physical_cores_observer");
				let _enter = span.enter();

				let lock = match phys_metrics.read() {
					Ok(l) => l,
					Err(e) => {
						error!(
							TARGET,
							{"blokmap.metrics.error.message"} = %e,
							"failed to lock host metrics",
						);
						return;
					},
				};

				observer.observe(lock.cpu_physical_cores, &[]);
			})
			.build();

		let log_metrics = Arc::clone(host_metrics);
		let _log_cores = meter
			.i64_observable_up_down_counter(SYSTEM_CPU_LOGICAL_COUNT)
			.with_description("Physical CPU Cores")
			.with_unit("{cpu}")
			.with_callback(move |observer| {
				let span = debug_span!(TARGET, "cpu_physical_cores_observer");
				let _enter = span.enter();

				let lock = match log_metrics.read() {
					Ok(l) => l,
					Err(e) => {
						error!(
							TARGET,
							{"blokmap.metrics.error.message"} = %e,
							"failed to lock host metrics",
						);
						return;
					},
				};

				observer.observe(lock.cpu_logical_cores, &[]);
			})
			.build();

		for i in 0..num_cores {
			let core_metrics = Arc::clone(host_metrics);
			let _per_core = meter
				.f64_observable_gauge(SYSTEM_CPU_UTILIZATION)
				.with_description(format!("CPU Core {i} Utilisation"))
				.with_unit("1")
				.with_callback(move |observer| {
					let span =
						debug_span!(TARGET, "cpu_{i}_utilisation_observer");
					let _enter = span.enter();

					let lock = match core_metrics.read() {
						Ok(l) => l,
						Err(e) => {
							error!(
								TARGET,
								{"blokmap.metrics.error.message"} = %e,
								"failed to lock host metrics",
							);
							return;
						},
					};

					#[allow(clippy::cast_possible_wrap)]
					observer.observe(
						lock.per_core_cpu_util[i],
						&[KeyValue::new(CPU_LOGICAL_NUMBER, i as i64)],
					);
				})
				.build();
		}

		let mem_util_metrics = Arc::clone(host_metrics);
		let _memory_util = meter
			.f64_observable_gauge(SYSTEM_MEMORY_UTILIZATION)
			.with_description("Global Memory Utilisation")
			.with_unit("1")
			.with_callback(move |observer| {
				let span = debug_span!(TARGET, "memory_utilisation_observer");
				let _enter = span.enter();

				let lock = match mem_util_metrics.read() {
					Ok(l) => l,
					Err(e) => {
						error!(
							TARGET,
							{"blokmap.metrics.error.message"} = %e,
							"failed to lock host metrics",
						);
						return;
					},
				};

				observer.observe(lock.memory_util, &[]);
			})
			.build();

		let mem_usage_metrics = Arc::clone(host_metrics);
		let _mem_usage = meter
			.i64_observable_up_down_counter(SYSTEM_MEMORY_USAGE)
			.with_description("Global Memory Usage")
			.with_unit("By")
			.with_callback(move |observer| {
				let span = debug_span!(TARGET, "memory_usage_observer");
				let _enter = span.enter();

				let lock = match mem_usage_metrics.read() {
					Ok(l) => l,
					Err(e) => {
						error!(
							TARGET,
							{"blokmap.metrics.error.message"} = %e,
							"failed to lock host metrics",
						);
						return;
					},
				};

				observer.observe(lock.memory_usage, &[]);
			})
			.build();

		let mem_total_metrics = Arc::clone(host_metrics);
		let _mem_toal = meter
			.i64_observable_up_down_counter(SYSTEM_MEMORY_LIMIT)
			.with_description("Global Memory Available")
			.with_unit("By")
			.with_callback(move |observer| {
				let span = debug_span!(TARGET, "memory_total_observer");
				let _enter = span.enter();

				let lock = match mem_total_metrics.read() {
					Ok(l) => l,
					Err(e) => {
						error!(
							TARGET,
							{"blokmap.metrics.error.message"} = %e,
							"failed to lock host metrics",
						);
						return;
					},
				};

				observer.observe(lock.memory_total, &[]);
			})
			.build();
	}

	#[instrument(skip_all, level = "debug", target = TARGET)]
	async fn host_metrics_update_worker(
		host_metrics: Arc<RwLock<HostMetricsService>>,
	) {
		let mut system = System::new_all().unwrap();
		let mut tick = tokio::time::interval(Duration::from_secs(5));

		system.refresh_cpu_usage();

		#[allow(clippy::cast_possible_wrap)]
		let cpu_physical_cores = System::physical_core_count().unwrap_or(0) as i64;
		#[allow(clippy::cast_possible_wrap)]
		let cpu_logical_cores = system.cpus().len().max(1) as i64;

		loop {
			tick.tick().await;

			system.refresh_cpu_usage();
			system.refresh_memory();

			let per_core_cpu_util = system
				.cpus()
				.iter()
				.map(|cpu| f64::from(cpu.usage()))
				.collect();

			let memory_total = system.total_memory().cast_signed();
			let memory_usage = system.used_memory().cast_signed();
			#[allow(clippy::cast_precision_loss)]
			let memory_util = memory_usage as f64 / memory_total as f64;

			let mut lock = match host_metrics.write() {
				Ok(l) => l,
				Err(e) => {
					error!(
						TARGET,
						{"blokmap.metrics.error.message"} = %e,
						"failed to lock host metrics",
					);
					continue;
				},
			};

			*lock = HostMetricsService {
				cpu_physical_cores,
				cpu_logical_cores,
				per_core_cpu_util,
				memory_util,
				memory_usage,
				memory_total,
			};
		}
	}
}
