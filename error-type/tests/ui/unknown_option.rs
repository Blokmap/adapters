#[derive(error_type::ErrorType)]
enum E {
    #[error_type(skip)]
    A,
}
fn main() {}
