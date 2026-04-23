use base64::prelude::{Engine, BASE64_STANDARD};
use netprov_protocol::PSK_LEN;
use qrcode::{render::unicode::Dense1x2, QrCode};
use rand::RngCore;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

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
    rand::thread_rng().fill_bytes(&mut psk);

    let b64 = BASE64_STANDARD.encode(psk);
    writeln!(out, "Generated PSK ({PSK_LEN} bytes, base64):")?;
    writeln!(out, "{b64}")?;
    writeln!(out)?;

    let qr = QrCode::new(b64.as_bytes()).map_err(|e| KeygenError::Qr(e.to_string()))?;
    let ascii = qr.render::<Dense1x2>().dark_color(Dense1x2::Dark).light_color(Dense1x2::Light).build();
    writeln!(out, "{ascii}")?;

    if args.install {
        if let Some(parent) = args.install_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&args.install_path)?;
        std::io::Write::write_all(&mut f, &psk)?;
        writeln!(out, "Installed to: {} (0600 root:root)", args.install_path.display())?;
    }
    Ok(())
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
        run_keygen(KeygenArgs {
            install: true,
            install_path: path.clone(),
        }, &mut buf).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.len(), PSK_LEN as u64);
    }
}
