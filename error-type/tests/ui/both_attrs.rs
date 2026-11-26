#[derive(error_type::ErrorType)]
enum E {
    #[error_type = "a"]
    #[error_type(transparent)]
    A(u8),
}
fn main() {}
