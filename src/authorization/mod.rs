//! Shared authorization models and the optional remote authorization client.

mod permissions;
mod principal;
mod scope;
mod service;

pub use permissions::{InstitutionPermissions, LocationPermissions};
pub use principal::AuthorizationPrincipal;
pub use scope::{PermissionScope, TokenScope};
#[cfg(feature = "authorization")]
pub use service::AuthorizationService;
pub use service::{AuthorizationCheck, AuthorizationRequirements};
