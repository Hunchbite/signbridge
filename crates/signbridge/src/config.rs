//! Runtime configuration for embedding apps.

use crate::allowlist::OriginAllowlist;
use crate::error::{Error, Result};
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
        serde_json::from_str(&text)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))
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
}

/// Best-effort defaults for common Indian DSC stacks + SoftHSM for local tests.
pub fn default_pkcs11_modules() -> Vec<PathBuf> {
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/opt/homebrew/lib/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
            "/Library/OpenSC/lib/opensc-pkcs11.so",
            "/usr/local/lib/libcastle.1.0.0.dylib",
            "/Library/Frameworks/ePass2003_PKCS11.framework/ePass2003_PKCS11",
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            r"C:\Windows\System32\opensc-pkcs11.dll",
            r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
            r"C:\Windows\System32\eps2003csp11.dll",
            r"C:\Windows\System32\Watchdata\Watchdata India USB Token\WDICP11_FF.dll",
        ]
    } else {
        &[
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/opensc-pkcs11.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        ]
    };

    candidates
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}
