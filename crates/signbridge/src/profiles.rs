//! Regional PKCS#11 module catalogues (India DSC, Spain, EU, SoftHSM).
//!
//! Drivers stay outside the crate; we only know where they usually live.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A known PKCS#11 module location for a region / product.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleCandidate {
    /// Human label (`OpenSC`, `ePass2003`, …).
    pub name: String,
    /// Region tag (`india`, `spain`, `eu`, `test`).
    pub region: String,
    /// Absolute path that may or may not exist.
    pub path: PathBuf,
    /// Short note for `doctor`.
    pub notes: String,
}

/// All built-in candidates for this OS.
pub fn all_candidates() -> Vec<ModuleCandidate> {
    let mut v = Vec::new();
    v.extend(india());
    v.extend(spain());
    v.extend(eu());
    v.extend(test_modules());
    v
}

/// Paths that exist on disk right now (deduplicated, profile order preserved).
pub fn present_modules() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for c in all_candidates() {
        if c.path.exists() && !out.iter().any(|e| e == &c.path) {
            out.push(c.path);
        }
    }
    out
}

/// Indian DSC tokens (ePass2003, ProxKey, OpenSC, eMudhra stacks).
pub fn india() -> Vec<ModuleCandidate> {
    #[cfg(target_os = "macos")]
    {
        return vec![
            cand("OpenSC", "india", "/opt/homebrew/lib/opensc-pkcs11.so", "brew install opensc — best for ePass2003"),
            cand("OpenSC onepin", "india", "/opt/homebrew/lib/onepin-opensc-pkcs11.so", "Single-PIN OpenSC variant"),
            cand("OpenSC", "india", "/usr/local/lib/opensc-pkcs11.so", "Intel Homebrew / manual OpenSC"),
            cand("OpenSC", "india", "/Library/OpenSC/lib/opensc-pkcs11.so", "OpenSC.pkg"),
            cand("ePass2003 (Feitian)", "india", "/usr/local/lib/libcastle.1.0.0.dylib", "Vendor middleware"),
            cand("ePass2003 libcastle", "india", "/usr/local/lib/libcastle.dylib", "Symlink / alternate Feitian install"),
            cand("ePass2003 framework", "india", "/Library/Frameworks/ePass2003_PKCS11.framework/ePass2003_PKCS11", "Vendor framework"),
            cand("eMudhra / emBridge libs", "india", "/usr/local/lib/libcastle.1.0.0.dylib", "Sometimes installed with emBridge"),
            cand("ProxKey / Watchdata", "india", "/usr/local/lib/libwdpkcs.dylib", "Watchdata India Mac driver (if present)"),
            cand("ProxKey WDICP", "india", "/usr/local/lib/libwdi_pkcs11.dylib", "Alternate Watchdata module name"),
        ];
    }
    #[cfg(target_os = "windows")]
    {
        return vec![
            cand("OpenSC", "india", r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll", "OpenSC installer — preferred for ePass2003"),
            cand("OpenSC System32", "india", r"C:\Windows\System32\opensc-pkcs11.dll", ""),
            cand("ePass2003", "india", r"C:\Windows\System32\eps2003csp11.dll", "Feitian / eMudhra vendor CSP"),
            cand("ePass2003 64", "india", r"C:\Windows\System32\eps2003csp1164.dll", "64-bit Feitian module"),
            cand("ePass2003 (x86)", "india", r"C:\Windows\SysWOW64\eps2003csp11.dll", ""),
            cand("ProxKey Watchdata", "india", r"C:\Windows\System32\Watchdata\Watchdata India USB Token\WDICP11_FF.dll", "Watchdata ProxKey (common India DSC)"),
            cand("ProxKey WDICP11", "india", r"C:\Windows\System32\WDICP11_FF.dll", "Alternate ProxKey install path"),
            cand("mToken", "india", r"C:\Windows\System32\mToken\mTokenPKCS11.dll", "Longmai / similar"),
            cand("SafeNet", "india", r"C:\Windows\System32\eTPKCS11.dll", "Some Capricorn / SafeNet tokens"),
            cand("TrustKey / Capricorn", "india", r"C:\Windows\System32\wdpkcs.dll", "Older Watchdata stacks"),
            cand("eMudhra emBridge", "india", r"C:\Program Files\eMudhra\emBridge\pkcs11.dll", "If emBridge left a module behind"),
        ];
    }
    #[cfg(target_os = "linux")]
    {
        return vec![
            cand("OpenSC", "india", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", "apt install opensc"),
            cand("OpenSC", "india", "/usr/lib/opensc-pkcs11.so", ""),
            cand("OpenSC", "india", "/usr/lib64/opensc-pkcs11.so", ""),
            cand("ePass2003", "india", "/usr/lib/libcastle.so.1.0.0", "Vendor Linux middleware"),
        ];
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        vec![]
    }
}

/// Spain — DNIe / FNMT CERES PKCS#11 modules when installed.
pub fn spain() -> Vec<ModuleCandidate> {
    #[cfg(target_os = "macos")]
    {
        return vec![
            cand("DNIe", "spain", "/Library/Frameworks/DNIePKCS11.framework/DNIePKCS11", "Spanish eID card"),
            cand("FNMT CERES", "spain", "/usr/local/lib/libpkcs11-fnmt.dylib", "FNMT middleware if installed"),
            cand("OpenSC (DNIe)", "spain", "/opt/homebrew/lib/opensc-pkcs11.so", "OpenSC also drives many EU cards"),
        ];
    }
    #[cfg(target_os = "windows")]
    {
        return vec![
            cand("DNIe", "spain", r"C:\Windows\System32\Asn1Module.dll", "Often bundled with DNIe middleware"),
            cand("FNMT CERES", "spain", r"C:\Windows\System32\FNPKCS11.dll", "FNMT"),
            cand("OpenSC", "spain", r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll", ""),
        ];
    }
    #[cfg(target_os = "linux")]
    {
        return vec![
            cand("DNIe", "spain", "/usr/lib/libpkcs11-dnie.so", "libpkcs11-dnie"),
            cand("OpenSC", "spain", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", ""),
        ];
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        vec![]
    }
}

/// Broader EU eID PKCS#11 (Web eID tier-2 style).
pub fn eu() -> Vec<ModuleCandidate> {
    #[cfg(target_os = "macos")]
    {
        return vec![
            cand("OpenSC", "eu", "/opt/homebrew/lib/opensc-pkcs11.so", "Latvian / Finnish / many EU cards via OpenSC"),
            cand("EstEID / ID-software", "eu", "/Library/Open-EID/opensc-pkcs11.so", "Estonian ID-software"),
            cand("Web eID / one-eid", "eu", "/usr/local/lib/onepin-opensc-pkcs11.so", "Some Open-eID installs"),
        ];
    }
    #[cfg(target_os = "windows")]
    {
        return vec![
            cand("OpenSC", "eu", r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll", ""),
            cand("EstEID", "eu", r"C:\Program Files\Open-EID\opensc-pkcs11.dll", "Estonian ID-software"),
        ];
    }
    #[cfg(target_os = "linux")]
    {
        return vec![
            cand("OpenSC", "eu", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", ""),
            cand("EstEID", "eu", "/usr/lib/x86_64-linux-gnu/onepin-opensc-pkcs11.so", ""),
        ];
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        vec![]
    }
}

/// SoftHSM for synthetic tests.
pub fn test_modules() -> Vec<ModuleCandidate> {
    vec![
        cand("SoftHSM2", "test", "/opt/homebrew/lib/softhsm/libsofthsm2.so", "brew install softhsm"),
        cand("SoftHSM2", "test", "/usr/local/lib/softhsm/libsofthsm2.so", ""),
        cand("SoftHSM2", "test", "/usr/lib/softhsm/libsofthsm2.so", ""),
        cand("SoftHSM2", "test", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "apt install softhsm2"),
    ]
}

fn cand(name: &str, region: &str, path: &str, notes: &str) -> ModuleCandidate {
    ModuleCandidate {
        name: name.into(),
        region: region.into(),
        path: PathBuf::from(path),
        notes: notes.into(),
    }
}

/// Machine diagnostic for `doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    /// OS family.
    pub os: String,
    /// Modules found on disk.
    pub modules_found: Vec<ModuleCandidate>,
    /// Suggested modules that are missing (by region).
    pub modules_missing_sample: Vec<ModuleCandidate>,
    /// Whether OpenSC-looking module is present (India baseline).
    pub opensc_present: bool,
    /// Hints for the user.
    pub hints: Vec<String>,
}

/// Probe the machine for signing middleware.
pub fn doctor() -> DoctorReport {
    let all = all_candidates();
    let found: Vec<_> = all.iter().filter(|c| c.path.exists()).cloned().collect();
    let missing: Vec<_> = all
        .iter()
        .filter(|c| !c.path.exists() && (c.region == "india" || c.region == "spain"))
        .take(8)
        .cloned()
        .collect();
    let opensc_present = found.iter().any(|c| {
        c.name.contains("OpenSC")
            || c.path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|n| n.contains("opensc"))
    });

    let mut hints = Vec::new();
    if found.is_empty() {
        hints.push("No PKCS#11 modules found. For India: brew install opensc (Mac) or install ePass2003 middleware.".into());
    }
    if !opensc_present {
        hints.push("OpenSC not detected — ePass2003 on Mac usually needs `brew install opensc`.".into());
    }
    if !found.iter().any(|c| c.region == "spain") {
        hints.push("No Spain-specific modules found. FNMT soft certs will need Keychain/Windows backends (planned); DNIe needs official middleware.".into());
    }
    hints.push("Drivers are never bundled — SignBridge only loads modules you install.".into());
    hints.push("Run SoftHSM tests with: cargo test -p signbridge --features testing".into());

    DoctorReport {
        os: std::env::consts::OS.into(),
        modules_found: found,
        modules_missing_sample: missing,
        opensc_present,
        hints,
    }
}

/// Merge profile defaults with any explicit config paths (explicit first).
pub fn merge_modules(explicit: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = explicit.to_vec();
    for p in present_modules() {
        if !out.iter().any(|e| e == &p) {
            out.push(p);
        }
    }
    out.retain(|p| Path::new(p).exists());
    out
}
