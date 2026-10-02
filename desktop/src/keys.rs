//! Shared secret and device identity files.
//!
//! Key file: `~/.config/clipcast/key`, base64 of 32 random bytes, mode 0600.
//! The daemon refuses to start if the permissions are looser than 0600.
//! Device id: `~/.local/state/clipcast/device_id`, 16 random bytes, written
//! once on first use.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::Engine as _;

use crate::crypto::{self, DEVICE_ID_LEN, KEY_LEN, KeyBytes};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key file {path} does not exist; run `clipcast keygen` first")]
    Missing { path: String },
    #[error("key file {path} has mode {mode:04o}; group/other bits must be cleared (chmod 600)")]
    LoosePermissions { path: String, mode: u32 },
    #[error("cannot read key file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("key file {path} is not valid base64: {message}")]
    Base64 { path: String, message: String },
    #[error("key file {path} decodes to {got} bytes; expected {KEY_LEN}")]
    WrongLength { path: String, got: usize },
}

/// Read and validate the key file. Refuses group/other permissions.
pub fn read_key(path: &Path) -> Result<KeyBytes, KeyError> {
    let shown = path.display().to_string();
    let meta = std::fs::metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            KeyError::Missing {
                path: shown.clone(),
            }
        } else {
            KeyError::Io {
                path: shown.clone(),
                source,
            }
        }
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyError::LoosePermissions { path: shown, mode });
    }
    let text = std::fs::read_to_string(path).map_err(|source| KeyError::Io {
        path: shown.clone(),
        source,
    })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|e| KeyError::Base64 {
            path: shown.clone(),
            message: e.to_string(),
        })?;
    if bytes.len() != KEY_LEN {
        return Err(KeyError::WrongLength {
            path: shown,
            got: bytes.len(),
        });
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceIdError {
    #[error("cannot read device id {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("device id {path} has {got} bytes; expected {DEVICE_ID_LEN} (delete it to regenerate)")]
    WrongLength { path: String, got: usize },
}

/// Load the persisted device id, creating it (mode 0600) on first use.
pub fn load_or_create_device_id(path: &Path) -> Result<[u8; DEVICE_ID_LEN], DeviceIdError> {
    let shown = path.display().to_string();
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != DEVICE_ID_LEN {
                return Err(DeviceIdError::WrongLength {
                    path: shown,
                    got: bytes.len(),
                });
            }
            let mut id = [0u8; DEVICE_ID_LEN];
            id.copy_from_slice(&bytes);
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = crypto::generate_device_id();
            write_device_id(path, &id)?;
            Ok(id)
        }
        Err(source) => Err(DeviceIdError::Io {
            path: shown,
            source,
        }),
    }
}

fn write_device_id(path: &Path, id: &[u8; DEVICE_ID_LEN]) -> Result<(), DeviceIdError> {
    let shown = path.display().to_string();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| DeviceIdError::Io {
            path: shown.clone(),
            source,
        })?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    std::fs::write(path, id).map_err(|source| DeviceIdError::Io {
        path: shown.clone(),
        source,
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        DeviceIdError::Io {
            path: shown,
            source,
        }
    })
}

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("key file {path} already exists; pass --force to overwrite")]
    Exists { path: String },
    #[error("cannot write key file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Create the key file (mode 0600). Refuses to overwrite an existing key
/// unless `force` is set.
pub fn generate_key_file(path: &Path, force: bool) -> Result<KeyBytes, KeygenError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let shown = path.display().to_string();
    if !force && path.exists() {
        return Err(KeygenError::Exists { path: shown });
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| KeygenError::Io {
            path: shown.clone(),
            source,
        })?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let key = crypto::generate_key();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| KeygenError::Io {
            path: shown.clone(),
            source,
        })?;
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|source| KeygenError::Io {
            path: shown.clone(),
            source,
        })?;
    // Re-assert mode: a pre-existing file keeps its old mode under truncate.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        KeygenError::Io {
            path: shown.clone(),
            source,
        }
    })?;
    Ok(key)
}

/// One-line status of the key file for `doctor`.
pub fn key_status(path: &Path) -> String {
    match read_key(path) {
        Ok(_) => match std::fs::metadata(path) {
            Ok(m) => format!("ok (mode {:04o})", m.permissions().mode() & 0o777),
            Err(_) => "ok".to_string(),
        },
        Err(KeyError::Missing { .. }) => "missing (run `clipcast keygen`)".to_string(),
        Err(e) => format!("ERROR: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_key_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("clipcast-keys-test").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn read_key_round_trip() {
        let dir = temp_key_dir("roundtrip");
        let path = dir.join("key");
        let key = crypto::generate_key();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        std::fs::write(&path, &b64).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key(&path).unwrap(), key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_key_is_reported() {
        let dir = temp_key_dir("missing");
        let err = read_key(&dir.join("nokey")).unwrap_err();
        assert!(matches!(err, KeyError::Missing { .. }), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loose_permissions_are_refused() {
        let dir = temp_key_dir("perms");
        let path = dir.join("key");
        let key = crypto::generate_key();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        std::fs::write(&path, &b64).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_key(&path).unwrap_err();
        assert!(matches!(err, KeyError::LoosePermissions { .. }), "{err}");
        // 0600 and stricter (0400) are fine.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_key(&path).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_length_key_is_reported() {
        let dir = temp_key_dir("length");
        let path = dir.join("key");
        std::fs::write(
            &path,
            base64::engine::general_purpose::STANDARD.encode([1u8; 31]),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = read_key(&path).unwrap_err();
        assert!(
            matches!(err, KeyError::WrongLength { got: 31, .. }),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_id_persists_across_calls() {
        let dir = temp_key_dir("device");
        let path = dir.join("device_id");
        let first = load_or_create_device_id(&path).unwrap();
        let second = load_or_create_device_id(&path).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, [0u8; DEVICE_ID_LEN], "randomly generated");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keygen_creates_readable_0600_key() {
        let dir = temp_key_dir("keygen-create");
        let path = dir.join("key");
        let key = generate_key_file(&path, false).unwrap();
        assert_eq!(read_key(&path).unwrap(), key);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keygen_refuses_overwrite_without_force() {
        let dir = temp_key_dir("keygen-refuse");
        let path = dir.join("key");
        let first = generate_key_file(&path, false).unwrap();
        let err = generate_key_file(&path, false).unwrap_err();
        assert!(matches!(err, KeygenError::Exists { .. }), "{err}");
        assert_eq!(read_key(&path).unwrap(), first, "key unchanged");
        let second = generate_key_file(&path, true).unwrap();
        assert_eq!(read_key(&path).unwrap(), second, "force overwrites");
        assert_ne!(first, second, "fresh key material");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_device_id_is_reported() {
        let dir = temp_key_dir("corrupt");
        let path = dir.join("device_id");
        std::fs::write(&path, b"short").unwrap();
        let err = load_or_create_device_id(&path).unwrap_err();
        assert!(
            matches!(err, DeviceIdError::WrongLength { got: 5, .. }),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
