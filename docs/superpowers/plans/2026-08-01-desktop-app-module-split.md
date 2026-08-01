# Desktop App Module Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the 2,113-line desktop `main.rs` into four cohesive modules without changing behavior.

**Architecture:** `main.rs` retains only Dioxus launch configuration and module declarations. `app.rs` owns discovery and connection lifecycle, `dashboard.rs` owns the connected-device UI, and `operations.rs` owns shared models, validation, convergence, and BLE calls.

**Tech Stack:** Rust 2024, Dioxus 0.7 desktop, Tokio, existing `netprov-protocol` and `netprov-sdk` crates.

## Global Constraints

- Preserve rendered RSX, CSS usage, state transitions, error text, accessibility attributes, and BLE call order exactly.
- Add no dependencies, feature flags, traits, service layers, or re-export modules.
- Use `pub(crate)` only where a moved item crosses a module boundary.
- Treat the existing 18 desktop tests as characterization tests; this refactor adds no behavior requiring a new test.
- Keep every commit compiling and passing the desktop test target.

---

### Task 1: Extract shared models and operations

**Files:**
- Create: `crates/app/src/operations.rs`
- Modify: `crates/app/src/main.rs`

**Interfaces:**
- Produces: crate-local `DeviceSummary`, `DeviceSnapshot`, `InterfaceSnapshot`, `MutationFailure`, `StaticIpv4Invalid`, and `SharedClient`.
- Produces: the existing validation, convergence, snapshot, and BLE functions with their existing signatures.
- Consumes: existing `netprov_protocol` and `netprov_sdk` APIs only.

- [ ] **Step 1: Record the characterization baseline**

Run:

```bash
cargo test -p netprov-app --features desktop
```

Expected: 18 tests pass.

- [ ] **Step 2: Create the operations module and wire it into the crate**

Add to `main.rs`:

```rust
mod operations;

use operations::*;
```

Create `operations.rs` with the imports currently used by the moved definitions. Move these definitions without editing their bodies:

```text
CONVERGENCE_POLL_INTERVAL
CONVERGENCE_TIMEOUT
MutationFailure
StaticIpv4Invalid
DeviceSummary
DeviceSnapshot
InterfaceSnapshot
SharedClient
static_ipv4_invalid_fields
wifi_converged
ip_config_converged
mutation_failure_message
scan_ble_devices
scan_wifi
connect_selected_wifi
sort_wifi_networks
parse_static_ipv4
prepare_ip_change
wifi_credential
apply_ip_config
replace_interface_config
connect_device
load_snapshot
disconnect_device
impl From<BleDevice> for DeviceSummary
```

Give cross-module structs, aliases, fields, and functions `pub(crate)` visibility. Keep constants and helpers private when used only within `operations.rs`.

- [ ] **Step 3: Move the operations characterization tests**

Move these tests unchanged from `main.rs` into `operations.rs` under `#[cfg(test)] mod tests`:

```text
rejects_empty_peer_before_connecting
parses_static_ipv4_form
rejects_invalid_static_ipv4_form
maps_wifi_security_to_credentials
rejects_unsupported_or_short_wifi_credentials
sorts_wifi_by_descending_signal
replaces_only_the_selected_interface_config
pending_ip_change_owns_its_original_interface
static_ipv4_invalid_state_is_field_specific
wifi_convergence_requires_the_requested_ssid
ip_convergence_matches_static_fields_with_unordered_dns
mutation_failure_message_distinguishes_request_and_confirmation
```

Use `use super::*;` plus the same protocol test imports those tests currently use.

- [ ] **Step 4: Format and verify the extraction**

```bash
cargo fmt --all
cargo test -p netprov-app --features desktop
```

Expected: all 18 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/app/src/main.rs crates/app/src/operations.rs
git commit -m "refactor(app): extract provisioning operations"
```

### Task 2: Extract the connected dashboard

**Files:**
- Create: `crates/app/src/dashboard.rs`
- Modify: `crates/app/src/main.rs`

**Interfaces:**
- Consumes: shared models, validation helpers, mutation helpers, and BLE operations from `operations.rs`.
- Produces: crate-local `Dashboard` with the existing generated Dioxus props interface.

- [ ] **Step 1: Create the dashboard module and wire it into the crate**

Add to `main.rs`:

```rust
mod dashboard;

use dashboard::Dashboard;
```

Create `dashboard.rs`, import `dioxus::prelude::*`, the protocol types used by its forms, and required `crate::operations` items. Move these definitions without changing their bodies:

```text
ActiveTab
TabDirection
WifiOperation
adjacent_tab
wifi_status_message
focus_mounted
Dashboard
ipv4_method_label
```

Change only the component visibility:

```rust
#[component]
pub(crate) fn Dashboard(/* retain the existing parameters exactly */) -> Element
```

- [ ] **Step 2: Move the dashboard characterization tests**

Move `tab_navigation_wraps_in_both_directions` and `wifi_operation_status_names_the_active_operation` unchanged into a test module in `dashboard.rs`.

- [ ] **Step 3: Format and verify the extraction**

```bash
cargo fmt --all
cargo test -p netprov-app --features desktop
```

Expected: all 18 tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/app/src/main.rs crates/app/src/dashboard.rs
git commit -m "refactor(app): extract connected dashboard"
```

### Task 3: Extract the root application and reduce main to launch code

**Files:**
- Create: `crates/app/src/app.rs`
- Modify: `crates/app/src/main.rs`

**Interfaces:**
- Consumes: `Dashboard`, shared operations, and `MAIN_CSS`.
- Produces: crate-local `App` for `LaunchBuilder::launch`.

- [ ] **Step 1: Create the root application module**

Create `app.rs` and move these definitions without changing their bodies:

```text
MIN_WINDOW_HEIGHT
SCREEN_MARGIN
target_window_height
ScanState
ConnectionPhase
ConnectedDevice
ConnectionLifecycle
capture_connected_device
allow_window_close
begin_disconnect
App
ScanStatus
DeviceList
```

Import the existing Dioxus, SDK, standard-library, dashboard, and operations items directly. Change only the root component visibility:

```rust
#[component]
pub(crate) fn App() -> Element
```

- [ ] **Step 2: Move the root application characterization tests**

Move these tests unchanged into `app.rs`:

```text
window_height_tracks_content_with_screen_bounds
successful_connection_keeps_the_captured_discovered_identity
manual_connection_captures_the_opaque_peer_with_generic_copy
disconnect_stays_gated_on_error_and_can_be_retried
```

- [ ] **Step 3: Reduce `main.rs` to the launch boundary**

```rust
use dioxus::prelude::*;

mod app;
mod dashboard;
mod operations;

const MAIN_CSS: Asset = asset!("/assets/main.css");

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new()
                .with_close_behaviour(dioxus::desktop::WindowCloseBehaviour::WindowHides),
        )
        .launch(app::App);
}
```

- [ ] **Step 4: Run final verification**

```bash
cargo fmt --all
cargo test -p netprov-app --features desktop
cargo clippy -p netprov-app --all-targets --features desktop -- -D warnings
cargo build -p netprov-app --features desktop
git diff --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all commands exit successfully; the desktop target still reports 18 passing tests.

- [ ] **Step 5: Review the mechanical diff**

```bash
git diff --stat
git diff -- crates/app/src/main.rs crates/app/src/app.rs crates/app/src/dashboard.rs crates/app/src/operations.rs
```

Confirm that function bodies, RSX, strings, and control flow are unchanged apart from module paths and visibility.

- [ ] **Step 6: Commit**

```bash
git add crates/app/src/main.rs crates/app/src/app.rs
git commit -m "refactor(app): extract root application"
```
