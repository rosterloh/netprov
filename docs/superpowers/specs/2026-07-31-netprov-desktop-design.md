# Netprov Desktop App Design

## Goal

Implement the supplied Open Design desktop interface in the existing Dioxus
app and wire every control to the real BLE provisioning SDK.

## Architecture

The app keeps one authenticated `Netprov<BleClient>` in shared state behind a
Tokio mutex. Discovery remains independent, while connected operations reuse
that secure session instead of reconnecting and authenticating for every
request.

All UI and state remain in `crates/app/src/main.rs`; the visual system remains
in `crates/app/assets/main.css`. No dependency or abstraction is added.

## User Flow

1. Discovery scans for real BLE devices and lets the user select a device or
   enter an opaque peer identifier and PSK path manually.
2. Connect reads and validates the PSK, authenticates, retains the client, and
   loads interfaces, each interface's IP configuration, and Wi-Fi status.
3. The overview tab summarizes the live connection and network state.
4. The Wi-Fi tab scans with `wifi_scan`, accepts credentials appropriate to the
   selected network, calls `connect_wifi`, and refreshes Wi-Fi status.
5. The interfaces tab selects an interface, edits DHCP or static IPv4 fields,
   confirms the potentially disruptive change, calls `set_dhcp` or
   `set_static_ipv4`, and refreshes that interface.
6. Disconnect closes the BLE connection and resets connected state.

## State and Errors

The Dioxus component owns selected device, active tab, operation busy state,
scan results, live snapshots, form values, and inline error/success feedback.
Only one SDK operation runs at a time through the retained client mutex.

Connection failures remain on discovery. Wi-Fi and IP failures remain in their
respective panels. Invalid static IPv4, gateway, DNS, and protected-network
password input is rejected before an SDK request. Controls are disabled while
their operation is active.

## Presentation and Accessibility

The Dioxus markup follows the supplied discovery card, connected header, tabs,
overview panels, Wi-Fi picker, interface editor, confirmation dialog, and toast
patterns. It uses the supplied brand tokens, keyboard-focus treatment,
44-pixel controls, semantic status regions, reduced-motion handling, and
responsive single-column layouts.

## Testing and Verification

Pure input conversion is covered test-first: static IPv4 parsing and Wi-Fi
credential selection. Existing protocol and SDK tests continue to cover wire
operations. Verification runs formatting, app tests, desktop-feature Clippy,
and the desktop build.

Hardware BLE behavior is not faked in unit tests; final end-to-end confirmation
requires a reachable netprov device and valid PSK.
