//! netprov server library.

pub mod facade;
pub mod key;
pub mod rate_limit;
pub mod session;
pub mod validate;
pub use facade::NetworkFacade;
pub use key::{load_key, KeySource, LoadOptions, LoadedKey, KeyError, DEV_KEY};
pub use session::Session;
pub use validate::validate_static_ipv4;

#[cfg(feature = "mock")]
pub mod facade_mock;
#[cfg(feature = "mock")]
pub use facade_mock::MockFacade;
