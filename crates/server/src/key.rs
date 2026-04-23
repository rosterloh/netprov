use netprov_protocol::{Psk, PSK_LEN};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DEV_KEY: &[u8] = include_bytes!("../../../packaging/dev-key.bin");

const _: () = {
    assert!(
        DEV_KEY.len() == PSK_LEN,
        "dev-key.bin must be exactly PSK_LEN bytes"
    );
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    EnvPath(PathBuf),
    DefaultPath(PathBuf),
    EmbeddedDev,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key path {path} not readable: {source}")]
    NotReadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("key at {path} has insecure permissions (mode {mode:#o}); must be owner-only")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("key at {path} has wrong length {got}, expected {expected}")]
    WrongLength {
        path: PathBuf,
        got: usize,
        expected: usize,
    },
    #[error("production mode enabled but no key found")]
    NoKeyInProduction,
}

pub struct LoadOptions {
    pub env_path: Option<PathBuf>,
    pub default_path: PathBuf,
    pub production: bool,
}

#[derive(Debug)]
pub struct LoadedKey {
    pub psk: Psk,
    pub source: KeySource,
}

pub fn load_key(opts: LoadOptions) -> Result<LoadedKey, KeyError> {
    if let Some(p) = &opts.env_path {
        return read_key_file(p).map(|psk| LoadedKey {
            psk,
            source: KeySource::EnvPath(p.clone()),
        });
    }
    match read_key_file(&opts.default_path) {
        Ok(psk) => Ok(LoadedKey {
            psk,
            source: KeySource::DefaultPath(opts.default_path.clone()),
        }),
        Err(KeyError::NotReadable { .. }) => {
            if opts.production {
                return Err(KeyError::NoKeyInProduction);
            }
            let mut psk = [0u8; PSK_LEN];
            psk.copy_from_slice(DEV_KEY);
            Ok(LoadedKey {
                psk,
                source: KeySource::EmbeddedDev,
            })
        }
        Err(e) => Err(e),
    }
}

fn read_key_file(path: &Path) -> Result<Psk, KeyError> {
    let meta = std::fs::metadata(path).map_err(|e| KeyError::NotReadable {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(KeyError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    let bytes = std::fs::read(path).map_err(|e| KeyError::NotReadable {
        path: path.to_path_buf(),
        source: e,
    })?;
    if bytes.len() != PSK_LEN {
        return Err(KeyError::WrongLength {
            path: path.to_path_buf(),
            got: bytes.len(),
            expected: PSK_LEN,
        });
    }
    let mut psk = [0u8; PSK_LEN];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tempkey(bytes: &[u8], mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        let mut perms = f.as_file().metadata().unwrap().permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(f.path(), perms).unwrap();
        f
    }

    #[test]
    fn falls_back_to_embedded_dev_key_when_default_missing() {
        let loaded = load_key(LoadOptions {
            env_path: None,
            default_path: "/definitely/does/not/exist".into(),
            production: false,
        })
        .unwrap();
        assert_eq!(loaded.source, KeySource::EmbeddedDev);
        assert_eq!(loaded.psk.as_slice(), DEV_KEY);
    }

    #[test]
    fn production_mode_rejects_missing_key() {
        let e = load_key(LoadOptions {
            env_path: None,
            default_path: "/definitely/does/not/exist".into(),
            production: true,
        })
        .unwrap_err();
        assert!(matches!(e, KeyError::NoKeyInProduction));
    }

    #[test]
    fn insecure_permissions_rejected() {
        let f = tempkey(&[0u8; PSK_LEN], 0o644);
        let e = load_key(LoadOptions {
            env_path: None,
            default_path: f.path().to_path_buf(),
            production: false,
        })
        .unwrap_err();
        assert!(matches!(e, KeyError::InsecurePermissions { .. }));
    }

    #[test]
    fn wrong_length_rejected() {
        let f = tempkey(&[0u8; PSK_LEN - 1], 0o600);
        let e = load_key(LoadOptions {
            env_path: None,
            default_path: f.path().to_path_buf(),
            production: false,
        })
        .unwrap_err();
        assert!(matches!(e, KeyError::WrongLength { .. }));
    }

    #[test]
    fn valid_key_loads() {
        let bytes: [u8; PSK_LEN] = [0xab; PSK_LEN];
        let f = tempkey(&bytes, 0o600);
        let loaded = load_key(LoadOptions {
            env_path: None,
            default_path: f.path().to_path_buf(),
            production: false,
        })
        .unwrap();
        assert!(matches!(loaded.source, KeySource::DefaultPath(_)));
        assert_eq!(loaded.psk, bytes);
    }

    #[test]
    fn env_path_takes_precedence() {
        let bytes: [u8; PSK_LEN] = [0xcd; PSK_LEN];
        let f_env = tempkey(&bytes, 0o600);
        let f_default = tempkey(&[0x00; PSK_LEN], 0o600);
        let loaded = load_key(LoadOptions {
            env_path: Some(f_env.path().to_path_buf()),
            default_path: f_default.path().to_path_buf(),
            production: false,
        })
        .unwrap();
        assert!(matches!(loaded.source, KeySource::EnvPath(_)));
        assert_eq!(loaded.psk, bytes);
    }
}
