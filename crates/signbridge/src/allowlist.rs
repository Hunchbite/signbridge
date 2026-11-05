//! Origin allowlists for embedding apps (browser hosts, HTTP gateways, …).

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Exact-origin allowlist with optional localhost escape hatch for development.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginAllowlist {
    /// Exact origins, e.g. `https://sign.hunchbite.com`.
    #[serde(default)]
    pub origins: HashSet<String>,
    /// When true, `http://localhost`, `127.0.0.1`, and `[::1]` (any port) are allowed.
    #[serde(default)]
    pub allow_localhost: bool,
}

impl OriginAllowlist {
    /// Defaults useful for Hunchbite Documenso + local dev.
    pub fn hunchbite_defaults() -> Self {
        let mut origins = HashSet::new();
        origins.insert("https://sign.hunchbite.com".into());
        origins.insert("https://documenso-production-471d.up.railway.app".into());
        Self {
            origins,
            allow_localhost: true,
        }
    }

    /// Allow every origin (only for trusted local tooling — never ship this).
    pub fn allow_all() -> Self {
        Self {
            origins: HashSet::new(),
            allow_localhost: true,
        }
    }

    /// Returns `Ok(())` if `origin` may request a signature.
    pub fn check(&self, origin: &str) -> Result<()> {
        let origin = origin.trim();
        if origin.is_empty() {
            return Err(Error::OriginDenied("(empty)".into()));
        }
        // Empty origins set + allow_localhost alone is NOT allow-all; require explicit entry
        // or localhost. For CLI/tools that skip origin checks, don't call this.
        if self.origins.contains(origin) {
            return Ok(());
        }
        if self.allow_localhost && is_localhost(origin) {
            return Ok(());
        }
        Err(Error::OriginDenied(origin.to_string()))
    }
}

fn is_localhost(origin: &str) -> bool {
    origin
        .strip_prefix("http://localhost")
        .or_else(|| origin.strip_prefix("http://127.0.0.1"))
        .or_else(|| origin.strip_prefix("http://[::1]"))
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(':') || rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_listed() {
        OriginAllowlist::hunchbite_defaults()
            .check("https://sign.hunchbite.com")
            .unwrap();
    }

    #[test]
    fn allows_localhost_port() {
        OriginAllowlist::hunchbite_defaults()
            .check("http://localhost:3000")
            .unwrap();
    }

    #[test]
    fn denies_unknown() {
        assert!(OriginAllowlist::hunchbite_defaults()
            .check("https://evil.example")
            .is_err());
    }
}
