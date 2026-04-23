//! netprov server library.

pub mod facade;
pub use facade::NetworkFacade;

#[cfg(feature = "mock")]
pub mod facade_mock;
#[cfg(feature = "mock")]
pub use facade_mock::MockFacade;
