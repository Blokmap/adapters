#[derive(error_type::ErrorType)]
enum E {
    #[error_type = "task panicked"]
    A,
}
fn main() {}
