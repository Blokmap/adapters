use deadpool_diesel::postgres::Pool;
use opentelemetry::{KeyValue, global};
use opentelemetry_semantic_conventions::attribute::{
	DB_CLIENT_CONNECTION_POOL_NAME,
	DB_CLIENT_CONNECTION_STATE,
};
use opentelemetry_semantic_conventions::metric::{
	DB_CLIENT_CONNECTION_COUNT,
	DB_CLIENT_CONNECTION_MAX,
	DB_CLIENT_CONNECTION_PENDING_REQUESTS,
};

pub struct DatabaseMetricsService {
	pool:      Pool,
	pool_name: String,
}

impl DatabaseMetricsService {
	#[must_use]
	pub fn new(pool: Pool, pool_name: String) -> Self {
		let meter = global::meter("blokmap.core.metrics.database");

		let conn_max_meter = meter
			.i64_up_down_counter(DB_CLIENT_CONNECTION_MAX)
			.with_description("Maximum number of possible database connections")
			.with_unit("{connection}")
			.build();

		// Database pool size is not going to change over time so a single
		// observation is enough
		#[allow(clippy::cast_possible_wrap)]
		let max_pool_size = pool.status().max_size as i64;
		conn_max_meter.add(
			max_pool_size,
			&[KeyValue::new(DB_CLIENT_CONNECTION_POOL_NAME, pool_name.clone())],
		);

		Self { pool, pool_name }
	}

	/// Start collecting database metrics and set up meters to track them
	pub fn start(self) {
		let meter = global::meter("blokmap.core.metrics.database");

		let idle_conn_attrs = vec![
			KeyValue::new(
				DB_CLIENT_CONNECTION_POOL_NAME,
				self.pool_name.clone(),
			),
			KeyValue::new(DB_CLIENT_CONNECTION_STATE, "idle"),
		];
		let used_conn_attrs = vec![
			KeyValue::new(
				DB_CLIENT_CONNECTION_POOL_NAME,
				self.pool_name.clone(),
			),
			KeyValue::new(DB_CLIENT_CONNECTION_STATE, "used"),
		];
		let pool_attrs = vec![KeyValue::new(
			DB_CLIENT_CONNECTION_POOL_NAME,
			self.pool_name.clone(),
		)];

		let conn_count_pool = self.pool.clone();
		meter
			.i64_observable_up_down_counter(DB_CLIENT_CONNECTION_COUNT)
			.with_description("Current database connections by state")
			.with_unit("{connection}")
			.with_callback(move |observer| {
				let status = conn_count_pool.status();

				#[allow(clippy::cast_possible_wrap)]
				let idle = status.available as i64;
				#[allow(clippy::cast_possible_wrap)]
				let used = status.size.saturating_sub(status.available) as i64;

				observer.observe(idle, &idle_conn_attrs);
				observer.observe(used, &used_conn_attrs);
			})
			.build();

		let pending_pool = self.pool.clone();
		meter
			.i64_observable_up_down_counter(
				DB_CLIENT_CONNECTION_PENDING_REQUESTS,
			)
			.with_description("Number of pending connection requests")
			.with_unit("{request}")
			.with_callback(move |observer| {
				let status = pending_pool.status();

				#[allow(clippy::cast_possible_wrap)]
				let waiting = status.waiting as i64;

				observer.observe(waiting, &pool_attrs);
			})
			.build();
	}
}
