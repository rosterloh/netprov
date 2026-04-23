//! netprov server library.

pub mod facade;
pub mod validate;
pub use facade::NetworkFacade;
pub use validate::validate_static_ipv4;

#[cfg(feature = "mock")]
pub mod facade_mock;
#[cfg(feature = "mock")]
pub use facade_mock::MockFacade;
