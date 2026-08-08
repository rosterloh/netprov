//! netprov server library.

pub mod clock;
pub mod facade;
pub mod key;
pub mod keygen;
pub mod logging;
pub mod rate_limit;
pub mod server_loop;
pub mod session;
pub mod validate;
pub use clock::{ClockError, ClockFacade};
pub use facade::NetworkFacade;
pub use key::{DEV_KEY, KeyError, KeySource, LoadOptions, LoadedKey, load_key};
pub use keygen::{KeygenArgs, KeygenError, run_keygen};
pub use logging::{log_startup_banner, spawn_dev_key_warn_loop};
pub use rate_limit::{RateLimiter, RateLimiterConfig, SystemClock};
pub use server_loop::{ServerConfig, ServerError, run_server};
pub use session::{Session, dispatch};
pub use validate::validate_static_ipv4;

#[cfg(feature = "mock")]
pub mod clock_mock;
#[cfg(feature = "mock")]
pub mod facade_mock;
#[cfg(feature = "mock")]
pub use clock_mock::MockClock;
#[cfg(feature = "mock")]
pub use facade_mock::MockFacade;

#[cfg(feature = "live-nm")]
pub mod facade_nmrs;
#[cfg(feature = "live-nm")]
pub mod facade_timedate;
#[cfg(feature = "live-nm")]
pub use facade_nmrs::NmrsFacade;
#[cfg(feature = "live-nm")]
pub use facade_timedate::TimedateFacade;

#[cfg(feature = "live-ble")]
pub mod ble;
#[cfg(feature = "live-ble")]
pub mod notify;
