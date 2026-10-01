//! Configuration file (`~/.config/clipcast/config.toml`) with defaults.

use std::path::Path;

use serde::Deserialize;

pub const DEFAULT_PORT: u16 = 47474;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 1200;
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 300;

/// Clipboard backend selection. `Auto` picks from the session environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackendOverride {
    #[default]
    Auto,
    X11,
    Wayland,
    Polling,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    pub max_text_bytes: usize,
    pub poll_interval_ms: u64,
    pub skip_sensitive: bool,
    pub backend: BackendOverride,
    /// Informational only; sent nowhere in v1.
    pub device_name: String,
    /// Non-empty allow list restricts to matching interface names.
    pub interface_allow: Vec<String>,
    pub interface_deny: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
            skip_sensitive: true,
            backend: BackendOverride::Auto,
            device_name: default_device_name(),
            interface_allow: Vec::new(),
            interface_deny: vec![
                "lo".to_string(),
                "docker*".to_string(),
                "br-*".to_string(),
                "veth*".to_string(),
                "virbr*".to_string(),
                "tun*".to_string(),
                "tap*".to_string(),
            ],
        }
    }
}

fn default_device_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot parse config {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

impl Config {
    /// Load the config file; a missing file means defaults.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|source| ConfigError::Parse {
                path: path.display().to_string(),
                source,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Load from the default location, falling back to defaults if the
    /// config directory cannot be determined.
    pub fn load_default() -> Result<(Self, std::path::PathBuf), ConfigError> {
        let path = crate::paths::config_file();
        match path {
            Some(p) => {
                let cfg = Self::load(&p)?;
                Ok((cfg, p))
            }
            None => Ok((Self::default(), std::path::PathBuf::from("<no HOME>"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_match_spec() {
        let c = Config::default();
        assert_eq!(c.port, 47474);
        assert_eq!(c.max_text_bytes, 1200);
        assert_eq!(c.poll_interval_ms, 300);
        assert!(c.skip_sensitive);
        assert_eq!(c.backend, BackendOverride::Auto);
        assert!(c.interface_allow.is_empty());
        assert!(c.interface_deny.contains(&"lo".to_string()));
        assert!(c.interface_deny.contains(&"docker*".to_string()));
        assert!(c.interface_deny.contains(&"veth*".to_string()));
    }

    #[test]
    fn missing_file_yields_defaults() {
        let cfg = Config::load(Path::new("/nonexistent/clipcast-config.toml")).unwrap();
        assert_eq!(cfg.port, DEFAULT_PORT);
    }

    #[test]
    fn parses_partial_config_with_defaults_for_rest() {
        let dir = std::env::temp_dir().join("clipcast-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "port = 50000\nbackend = \"polling\"\n").unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.port, 50000);
        assert_eq!(cfg.backend, BackendOverride::Polling);
        assert_eq!(cfg.max_text_bytes, DEFAULT_MAX_TEXT_BYTES);
        assert_eq!(cfg.poll_interval_ms, DEFAULT_POLL_INTERVAL_MS);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_invalid_config() {
        let dir = std::env::temp_dir().join("clipcast-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "port = \"not-a-number\"\n").unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn backend_override_names() {
        for (text, want) in [
            ("\"auto\"", BackendOverride::Auto),
            ("\"x11\"", BackendOverride::X11),
            ("\"wayland\"", BackendOverride::Wayland),
            ("\"polling\"", BackendOverride::Polling),
        ] {
            let cfg: Config = toml::from_str(&format!("backend = {text}")).unwrap();
            assert_eq!(cfg.backend, want, "{text}");
        }
    }
}
