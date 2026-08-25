//! The "Advanced connection" values, persisted between runs and overridable on
//! the command line.
//!
//! Retyping an opaque `PeerId` and a PSK path on every launch is the whole
//! friction this removes: on macOS the peer is a per-host UUID nobody can
//! recall, and the PSK rarely lives at the packaged default. Only the *path* is
//! stored, never key bytes, so this file is not a secret.

use std::path::{Path, PathBuf};

const FILE_NAME: &str = "connection.conf";

/// Where `netprovd` installs the PSK, and so the right guess for a device
/// image built by this project.
const DEFAULT_KEY_PATH: &str = "/etc/netprov/key";

/// Must match `[bundle] identifier` in `Dioxus.toml` — macOS keys the support
/// directory by bundle id, and a mismatch would silently orphan the file.
const APP_ID: &str = "com.rosterloh.NetprovApp";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Connection {
    pub(crate) peer: String,
    pub(crate) key_path: String,
}

/// The stored values, with `--key-path` taking precedence and the packaged
/// default filling in a missing path.
pub(crate) fn load() -> Connection {
    let mut connection = settings_dir().map(read).unwrap_or_default();
    if let Some(over_ride) = key_path_arg() {
        connection.key_path = over_ride;
    }
    if connection.key_path.is_empty() {
        connection.key_path = DEFAULT_KEY_PATH.to_string();
    }
    connection
}

/// Best-effort: a read-only home or a full disk must not break provisioning,
/// which is why the error here is discarded rather than surfaced.
pub(crate) fn save(peer: &str, key_path: &str) {
    if let Some(dir) = settings_dir() {
        let _ = write(&dir, peer, key_path);
    }
}

/// A missing or unreadable file is simply "nothing stored yet".
fn read(dir: PathBuf) -> Connection {
    std::fs::read_to_string(dir.join(FILE_NAME))
        .map(|contents| parse(&contents))
        .unwrap_or_default()
}

fn write(dir: &Path, peer: &str, key_path: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(FILE_NAME), render(peer, key_path))
}

fn render(peer: &str, key_path: &str) -> String {
    format!("peer = {}\nkey_path = {}\n", peer.trim(), key_path.trim())
}

/// `key = value` per line. Deliberately not TOML: two strings do not justify a
/// parser dependency, and hand-rolled quoting is the bug TOML would introduce.
/// A value therefore cannot contain a newline; paths that do are not supported.
fn parse(contents: &str) -> Connection {
    let mut connection = Connection::default();
    for line in contents.lines() {
        // `split_once` keeps any later `=` in the value, so paths containing
        // one round-trip.
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim() {
            "peer" => connection.peer = value,
            "key_path" => connection.key_path = value,
            _ => {}
        }
    }
    connection
}

/// `-k`/`--key-path`, matching the `netprov` CLI's flag. Hand-rolled rather
/// than pulling `clap` into a GUI crate for one optional argument.
fn key_path_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--key-path=") {
            return Some(value.to_string());
        }
        if arg == "--key-path" || arg == "-k" {
            return args.next();
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn settings_dir() -> Option<PathBuf> {
    Some(
        std::env::home_dir()?
            .join("Library/Application Support")
            .join(APP_ID),
    )
}

#[cfg(not(target_os = "macos"))]
fn settings_dir() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|base| !base.is_empty()) {
        return Some(PathBuf::from(base).join("netprov"));
    }
    Some(std::env::home_dir()?.join(".config/netprov"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_values() {
        let connection = parse("peer = opaque-peer\nkey_path = /tmp/key\n");

        assert_eq!(connection.peer, "opaque-peer");
        assert_eq!(connection.key_path, "/tmp/key");
    }

    #[test]
    fn ignores_blank_and_unknown_lines() {
        let connection = parse("\n# a comment\nunknown = x\npeer = only-peer\n");

        assert_eq!(connection.peer, "only-peer");
        assert_eq!(connection.key_path, "");
    }

    #[test]
    fn keeps_equals_signs_inside_a_value() {
        let connection = parse("key_path = /tmp/od=d/key");

        assert_eq!(connection.key_path, "/tmp/od=d/key");
    }

    #[test]
    fn render_round_trips_through_parse() {
        let rendered = render("  opaque-peer  ", "  /tmp/key  ");

        assert_eq!(
            parse(&rendered),
            Connection {
                peer: "opaque-peer".into(),
                key_path: "/tmp/key".into(),
            }
        );
    }

    #[test]
    fn missing_file_parses_to_empty() {
        assert_eq!(parse(""), Connection::default());
    }

    /// The real on-disk path, since `save`/`load` discard their errors and a
    /// broken write would otherwise be silent.
    #[test]
    fn write_then_read_round_trips_on_disk() {
        // A nested leaf also proves `create_dir_all` runs.
        let dir = std::env::temp_dir()
            .join(format!("netprov-settings-{}", std::process::id()))
            .join("nested");
        let _ = std::fs::remove_dir_all(&dir);

        write(&dir, "opaque-peer", "/tmp/key").expect("settings should be writable");

        assert_eq!(
            read(dir.clone()),
            Connection {
                peer: "opaque-peer".into(),
                key_path: "/tmp/key".into(),
            }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_of_a_missing_directory_is_empty() {
        let dir = std::env::temp_dir().join("netprov-settings-absent");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(read(dir), Connection::default());
    }
}
