//! Pinned BLE service + characteristic UUIDs for netprov.
//!
//! The canonical `u128` values live in `netprov_protocol::uuids`. **Do not
//! change these** — clients discover the service by UUID. Changing a UUID is
//! a breaking protocol change requiring a major-version bump (§7.1).

use bluer::Uuid;
use netprov_protocol::uuids as proto;

pub const SERVICE_UUID: Uuid = Uuid::from_u128(proto::SERVICE_UUID);

pub const INFO_UUID: Uuid = Uuid::from_u128(proto::INFO_UUID);
pub const CHALLENGE_UUID: Uuid = Uuid::from_u128(proto::CHALLENGE_UUID);
pub const AUTH_RESPONSE_UUID: Uuid = Uuid::from_u128(proto::AUTH_RESPONSE_UUID);
pub const REQUEST_UUID: Uuid = Uuid::from_u128(proto::REQUEST_UUID);

/// `Response` is a notify characteristic. We reuse a single UUID ("request"
/// write + "response" notify) by giving it both properties. This matches how
/// the BlueZ layer actually exposes the endpoint: one characteristic, two
/// flows. Clients subscribe to notifications on REQUEST_UUID.
pub const RESPONSE_UUID: Uuid = REQUEST_UUID;
