#[derive(error_type::ErrorType)]
enum E {
    #[error_type(transparent)]
    Two(u8, u8),
}
fn main() {}
