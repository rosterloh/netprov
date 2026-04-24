//! Pinned BLE service + characteristic UUIDs for netprov.
//!
//! Generated once at Part 2 scaffold time. **Do not change these** — clients
//! discover the service by UUID. Changing a UUID is a breaking protocol change
//! requiring a major-version bump (§7.1).

use bluer::Uuid;

pub const SERVICE_UUID: Uuid = Uuid::from_u128(0x0eebc1ba_773d_4625_babf_5c6cafe82b30);

pub const INFO_UUID: Uuid = Uuid::from_u128(0xc4c47504_92f6_45d0_97b2_24c965499cf8);
pub const CHALLENGE_UUID: Uuid = Uuid::from_u128(0x0107c3c5_a56b_4283_925b_7dd4ec0aafb6);
pub const AUTH_RESPONSE_UUID: Uuid = Uuid::from_u128(0xb78f3640_d56a_487b_b10e_f5dea9facf3c);
pub const REQUEST_UUID: Uuid = Uuid::from_u128(0x6d29f399_aad4_494e_8b0b_b85b9a7fef9e);

/// `Response` is a notify characteristic. We reuse a single UUID ("request"
/// write + "response" notify) by giving it both properties. This matches how
/// the BlueZ layer actually exposes the endpoint: one characteristic, two
/// flows. Clients subscribe to notifications on REQUEST_UUID.
pub const RESPONSE_UUID: Uuid = REQUEST_UUID;
