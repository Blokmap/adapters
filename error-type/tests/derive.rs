use error_type::ErrorType;

#[derive(Debug, thiserror::Error, ErrorType)]
pub enum QueryError {
    #[error("{entity} not found")]
    NotFound { entity: &'static str },
    #[error("unique constraint `{constraint}` violated")]
    Unique { constraint: String },
    #[error("serialization failure")]
    SerializationFailure,
    #[error("HTTP request failed")]
    HTTPRequestFailed,
}

#[derive(Debug, thiserror::Error, ErrorType)]
pub enum DbInteractionError {
    #[error("could not get a connection")]
    #[error_type = "db_pool_timeout"]
    Pool,
    #[error("database task panicked")]
    #[error_type = "db_task_panicked"]
    Panicked,
    #[error("database task was aborted")]
    #[error_type = "db_task_aborted"]
    Aborted,
    #[error(transparent)]
    #[error_type(transparent)]
    Query(#[from] QueryError),
}

#[derive(Debug, thiserror::Error, ErrorType)]
pub enum ReservationError {
    #[error("this time slot is full")]
    Full,
    #[error(transparent)]
    #[error_type(transparent)]
    Db(#[from] DbInteractionError),
    #[error(transparent)]
    #[error_type(transparent)]
    Boxed { source: Box<QueryError> },
}

#[derive(Debug, thiserror::Error, ErrorType)]
#[error("invalid input")]
pub struct ValidationError;

#[derive(Debug, thiserror::Error, ErrorType)]
#[error("rate limited")]
#[error_type = "too_many_requests"]
pub struct RateLimited { pub retry_after: u64 }

#[derive(Debug, thiserror::Error, ErrorType)]
#[error(transparent)]
#[error_type(transparent)]
pub struct Wrapper(QueryError);

#[derive(Debug, thiserror::Error, ErrorType)]
pub enum Generic<E: std::error::Error + ErrorType + 'static> {
    #[error(transparent)]
    #[error_type(transparent)]
    Inner(E),
    #[error("other")]
    Other,
}

#[test]
fn variant_names_become_snake_case() {
    assert_eq!(QueryError::NotFound { entity: "template" }.error_type(), "not_found");
    assert_eq!(QueryError::Unique { constraint: "x".into() }.error_type(), "unique");
    assert_eq!(QueryError::SerializationFailure.error_type(), "serialization_failure");
    assert_eq!(QueryError::HTTPRequestFailed.error_type(), "http_request_failed");
}

#[test]
fn overrides_win() {
    assert_eq!(DbInteractionError::Panicked.error_type(), "db_task_panicked");
    assert_eq!(DbInteractionError::Pool.error_type(), "db_pool_timeout");
}

#[test]
fn transparent_delegates_through_layers() {
    let e = ReservationError::Db(DbInteractionError::Query(QueryError::Unique { constraint: "x".into() }));
    assert_eq!(e.error_type(), "unique");
    let e = ReservationError::Db(DbInteractionError::Panicked);
    assert_eq!(e.error_type(), "db_task_panicked");
    let e = ReservationError::Boxed { source: Box::new(QueryError::SerializationFailure) };
    assert_eq!(e.error_type(), "serialization_failure");
    assert_eq!(ReservationError::Full.error_type(), "full");
}

#[test]
fn structs() {
    assert_eq!(ValidationError.error_type(), "validation_error");
    assert_eq!(RateLimited { retry_after: 3 }.error_type(), "too_many_requests");
    assert_eq!(Wrapper(QueryError::NotFound { entity: "x" }).error_type(), "not_found");
}

#[test]
fn generics() {
    assert_eq!(Generic::Inner(QueryError::SerializationFailure).error_type(), "serialization_failure");
    assert_eq!(Generic::<QueryError>::Other.error_type(), "other");
}

#[test]
fn compile_errors() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
