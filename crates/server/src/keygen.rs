use base64::prelude::{BASE64_STANDARD, Engine};
use netprov_protocol::PSK_LEN;
use qrcode::{QrCode, render::unicode::Dense1x2};
use rand::Rng;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("QR rendering failed: {0}")]
    Qr(String),
}

pub struct KeygenArgs {
    pub install: bool,
    pub install_path: PathBuf,
}

impl Default for KeygenArgs {
    fn default() -> Self {
        Self {
            install: false,
            install_path: "/etc/netprov/key".into(),
        }
    }
}

pub fn run_keygen(args: KeygenArgs, out: &mut dyn std::io::Write) -> Result<(), KeygenError> {
    let mut psk = [0u8; PSK_LEN];
    rand::rng().fill_bytes(&mut psk);

    let b64 = BASE64_STANDARD.encode(psk);
    writeln!(out, "Generated PSK ({PSK_LEN} bytes, base64):")?;
    writeln!(out, "{b64}")?;
    writeln!(out)?;

    let qr = QrCode::new(b64.as_bytes()).map_err(|e| KeygenError::Qr(e.to_string()))?;
    let ascii = qr
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Dark)
        .light_color(Dense1x2::Light)
        .build();
    writeln!(out, "{ascii}")?;

    if args.install {
        if let Some(parent) = args.install_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        install_key(&args.install_path, &psk)?;
        writeln!(
            out,
            "Installed to: {} (0600 root:root)",
            args.install_path.display()
        )?;
    }
    Ok(())
}

/// Writes `psk` to `path` with mode 0600, replacing whatever was there.
///
/// Goes via a temp file in the same directory and renames over the target,
/// rather than opening the target directly. `OpenOptions::mode` only applies
/// when the file is *created*, so writing straight into a pre-existing key
/// left its old permissions untouched while keygen still reported `0600` — a
/// fresh key could sit world-readable behind a message saying otherwise (#20).
/// A newly created temp file always gets the mode, and the rename is atomic,
/// so an interrupted run also can't leave a truncated key behind and strand
/// the device.
fn install_key(path: &Path, psk: &[u8]) -> std::io::Result<()> {
    let tmp = match path.file_name() {
        Some(name) => path.with_file_name(format!(".{}.tmp", name.to_string_lossy())),
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "install path has no file name",
            ));
        }
    };

    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        // Explicit, because `mode` above is a no-op if a temp file survived an
        // earlier interrupted run.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        std::io::Write::write_all(&mut f, psk)?;
        // The key is worthless if it doesn't survive a power cut mid-install.
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    };

    let result = write();
    if result.is_err() {
        // Don't leave key material lying around under a name nobody reads.
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn generates_and_prints() {
        let mut buf = Vec::new();
        run_keygen(KeygenArgs::default(), &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Generated PSK"));
    }

    #[test]
    fn install_writes_0600_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k");
        let mut buf = Vec::new();
        run_keygen(
            KeygenArgs {
                install: true,
                install_path: path.clone(),
            },
            &mut buf,
        )
        .unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.len(), PSK_LEN as u64);
    }

    /// #20: `OpenOptions::mode` only applies on create, so installing over a
    /// key an admin had already created loose left it loose — while keygen
    /// printed "0600".
    #[test]
    fn install_tightens_permissions_on_a_pre_existing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k");
        std::fs::write(&path, b"stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        run_keygen(
            KeygenArgs {
                install: true,
                install_path: path.clone(),
            },
            &mut Vec::new(),
        )
        .unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600, "must not inherit 0644");
        assert_eq!(meta.len(), PSK_LEN as u64, "stale contents must be gone");
    }

    /// The temp file the atomic install goes through must not be left behind.
    #[test]
    fn install_leaves_no_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k");
        run_keygen(
            KeygenArgs {
                install: true,
                install_path: path.clone(),
            },
            &mut Vec::new(),
        )
        .unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "k")
            .collect();
        assert!(leftovers.is_empty(), "unexpected files: {leftovers:?}");
    }
}
