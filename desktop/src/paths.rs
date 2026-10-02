//! XDG-ish path resolution: config in `$XDG_CONFIG_HOME/clipcast`,
//! state in `$XDG_STATE_HOME/clipcast`. Both respect the environment so
//! parallel instances can be isolated with `XDG_CONFIG_HOME`/`XDG_STATE_HOME`.

use std::path::PathBuf;

/// `$HOME` (no external crate; Linux only target).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

fn xdg_dir(var: &str, fallback: &str) -> Option<PathBuf> {
    if let Some(v) = std::env::var_os(var)
        && !v.is_empty()
    {
        return Some(PathBuf::from(v));
    }
    home_dir().map(|h| h.join(fallback))
}

/// `~/.config/clipcast`
pub fn config_dir() -> Option<PathBuf> {
    xdg_dir("XDG_CONFIG_HOME", ".config").map(|d| d.join("clipcast"))
}

/// `~/.local/state/clipcast`
pub fn state_dir() -> Option<PathBuf> {
    xdg_dir("XDG_STATE_HOME", ".local/state").map(|d| d.join("clipcast"))
}

pub fn config_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config.toml"))
}

pub fn key_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join("key"))
}

pub fn device_id_file() -> Option<PathBuf> {
    state_dir().map(|d| d.join("device_id"))
}

/// `~/.local/state/clipcast/images` — temporary sender-side image cache.
pub fn image_cache_dir() -> Option<PathBuf> {
    state_dir().map(|d| d.join("images"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var mutation serializes process-wide state between tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn config_dir_respects_xdg_config_home() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", "/tmp/opencode/xdg-test-cfg") };
        assert_eq!(
            config_dir().unwrap(),
            PathBuf::from("/tmp/opencode/xdg-test-cfg/clipcast")
        );
        assert_eq!(
            key_file().unwrap(),
            PathBuf::from("/tmp/opencode/xdg-test-cfg/clipcast/key")
        );
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn state_dir_respects_xdg_state_home() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("XDG_STATE_HOME", "/tmp/opencode/xdg-test-state") };
        assert_eq!(
            device_id_file().unwrap(),
            PathBuf::from("/tmp/opencode/xdg-test-state/clipcast/device_id")
        );
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }
}
