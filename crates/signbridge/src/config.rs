//! Runtime configuration for embedding apps.

use crate::allowlist::OriginAllowlist;
use crate::error::{Error, Result};
use crate::profiles;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// App-level config loaded from JSON or constructed in code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    /// Which web origins may call into a host that uses this config.
    pub allowlist: OriginAllowlist,
    /// PKCS#11 module paths to probe, in order.
    pub pkcs11_modules: Vec<PathBuf>,
    /// Optional default PIN for automated tests only. Never ship with this set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_pin: Option<String>,
    /// When true, skip origin checks (CLI / trusted local tools).
    #[serde(default)]
    pub skip_origin_check: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            allowlist: OriginAllowlist::hunchbite_defaults(),
            pkcs11_modules: default_pkcs11_modules(),
            test_pin: None,
            skip_origin_check: false,
        }
    }
}

impl AppConfig {
    /// Load JSON from `path`, or return [`Self::default`] if missing / `None`.
    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        let mut cfg: Self = serde_json::from_str(&text)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
        // Merge regional profile modules that exist on disk (explicit paths win).
        cfg.pkcs11_modules = profiles::merge_modules(&cfg.pkcs11_modules);
        Ok(cfg)
    }

    /// Config for CLI / synthetic tests: SoftHSM module if present, origin checks off.
    pub fn for_cli() -> Self {
        Self {
            allowlist: OriginAllowlist::hunchbite_defaults(),
            pkcs11_modules: default_pkcs11_modules(),
            test_pin: None,
            skip_origin_check: true,
        }
    }

    /// Ensure profile-discovered modules are included (idempotent).
    pub fn with_profile_modules(mut self) -> Self {
        self.pkcs11_modules = profiles::merge_modules(&self.pkcs11_modules);
        self
    }
}

/// Best-effort defaults: India + Spain + EU + SoftHSM profiles that exist on disk.
pub fn default_pkcs11_modules() -> Vec<PathBuf> {
    profiles::present_modules()
}
