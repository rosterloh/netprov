# Desktop App Module Split

## Goal

Split `crates/app/src/main.rs` into a few cohesive Rust modules without changing UI, behavior, dependencies, or public APIs.

## Structure

- `main.rs`: asset declaration, desktop launch configuration, and module declarations.
- `app.rs`: root `App` component, discovery UI, connection lifecycle, window lifecycle, and auto-resizing.
- `dashboard.rs`: connected-device dashboard and its Wi-Fi and interface forms.
- `operations.rs`: shared data models, validation and convergence helpers, and asynchronous BLE operations.

Items will move as existing units. The refactor will not introduce traits, service layers, re-export modules, or one-file-per-component structure. Cross-module items will use `pub(crate)` only when required.

## Data Flow

`app.rs` owns the top-level Dioxus signals and connection lifecycle. Once connected, it passes the existing snapshot, shared client, and callbacks to `dashboard.rs`. Both UI modules call the existing helpers and BLE operations in `operations.rs`; no call order or ownership semantics change.

## Behavior Invariants

- The rendered RSX and CSS asset remain unchanged.
- Discovery, connection, disconnection, close handling, and automatic window sizing remain unchanged.
- Wi-Fi scanning and connection, IPv4 changes, validation messages, and convergence polling remain unchanged.
- Existing error text and accessibility attributes remain unchanged.
- No dependencies or feature flags change.

## Verification

Run the existing desktop app tests before and after extraction as characterization coverage. After the move, run formatting, the full desktop app test target, strict Clippy for the desktop app, and a desktop build. `git diff --check` must remain clean.
