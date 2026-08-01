# Introduction

netprov provides BLE-provisioned network configuration for headless embedded
Linux. A systemd service, `netprovd`, advertises a GATT service that a paired
client can use to list interfaces, read IP configuration, scan Wi-Fi, and set
DHCP, static IPv4, and Wi-Fi credentials.

The server is written in Rust and talks to NetworkManager over D-Bus. The
companion `netprov` CLI speaks the same protocol over BLE in production or TCP
loopback during development. A Dioxus desktop client provides the same BLE
workflow through a graphical interface.

Start with [Installation](./getting-started/installation.md), or use the
[Development](./getting-started/development.md) guide to run the complete
request/response flow without BLE hardware or NetworkManager.

netprov is licensed under MIT OR Apache-2.0.
