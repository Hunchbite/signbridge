//! Synthetic SoftHSM fixtures for integration tests and local demos.
//!
//! Enabled with `--features testing`. Creates an isolated token directory so
//! tests never touch the user's real SoftHSM config.
//!
//! ## Synthetic Indian DSC
//!
//! SoftHSM is **not** a USB token, but it speaks the same PKCS#11 API that
//! OpenSC / ePass2003 / ProxKey expose. The fixture imports:
//!
//! - RSA-2048 private + public key
//! - Matching X.509 certificate (`CN=Synthetic Indian DSC`, `C=IN`)
//!
//! That covers list-with-DER, Web eID certificate matching, DigestInfo RSA
//! sign, and openssl verify — everything SignBridge does on a real DSC
//! **except** PC/SC, vendor middleware quirks, and hardware PIN pads.
//!
//! Setup uses `softhsm2-util` + `openssl` + `pkcs11-tool` in subprocesses so
//! this process only loads PKCS#11 **once** (SoftHSM is unhappy with
//! finalize/re-init).

use crate::error::{Error, Result};
use crate::pkcs11::Pkcs11Backend;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tempfile::TempDir;

/// Default SoftHSM user PIN used by fixtures.
pub const FIXTURE_USER_PIN: &str = "1234";
/// Default SoftHSM SO PIN used by fixtures.
pub const FIXTURE_SO_PIN: &str = "5678";
/// Default key / cert label (DSC-like object label).
pub const FIXTURE_KEY_LABEL: &str = "SyntheticSigner";
/// Default token label.
pub const FIXTURE_TOKEN_LABEL: &str = "SignBridgeTest";
/// Object CKA_ID (hex) shared by key + cert.
pub const FIXTURE_OBJECT_ID: &str = "02";

static SOFTHSM_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Guard that serialises SoftHSM fixture use inside one process.
pub struct SoftHsmLock(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

/// Acquire the process-wide SoftHSM lock (integration tests must call this).
pub fn lock_softhsm() -> SoftHsmLock {
    SoftHsmLock(
        SOFTHSM_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    )
}

/// Locate `libsofthsm2.so` on this machine.
pub fn find_softhsm_module() -> Option<PathBuf> {
    [
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// An isolated SoftHSM token with one RSA signing key **and** X.509 certificate
/// (synthetic Indian DSC stand-in).
pub struct SoftHsmFixture {
    /// Keeps the temp dir alive (token files + conf).
    _dir: TempDir,
    /// Path to SoftHSM module.
    pub module: PathBuf,
    /// Slot id of the initialized token.
    pub slot_id: u64,
    /// Key / certificate label.
    pub label: String,
    /// User PIN.
    pub pin: String,
    /// Path to softhsm2.conf used for this fixture.
    pub conf_path: PathBuf,
    /// Public key PEM (from the cert) for openssl verify.
    pub public_pem: PathBuf,
    /// Leaf certificate PEM (`CN=Synthetic Indian DSC`).
    pub certificate_pem: PathBuf,
}

impl SoftHsmFixture {
    /// Create a fresh token + RSA-2048 key + matching X.509 cert.
    ///
    /// Mimics what a Class-2/3 Indian DSC exposes over PKCS#11: a private key
    /// that never leaves the module, plus an X.509 object with the same CKA_ID.
    pub fn create() -> Result<Self> {
        let module = find_softhsm_module().ok_or_else(|| {
            Error::Config(
                "SoftHSM module not found — brew install softhsm / apt install softhsm2".into(),
            )
        })?;

        let dir = TempDir::new().map_err(|e| Error::Other(e.into()))?;
        let tokens = dir.path().join("tokens");
        std::fs::create_dir_all(&tokens).map_err(|e| Error::Other(e.into()))?;
        let conf_path = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf_path,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = INFO\n",
                tokens.display()
            ),
        )
        .map_err(|e| Error::Other(e.into()))?;

        // Generate key + self-signed cert outside the token, then import —
        // same objects a real DSC would present (privkey + pubkey + X.509).
        let key_pem = dir.path().join("key.pem");
        let cert_pem = dir.path().join("cert.pem");
        let key_der = dir.path().join("key.der");
        let pub_der = dir.path().join("pub.der");
        let cert_der = dir.path().join("cert.der");
        let public_pem = dir.path().join("pub.pem");

        run(Command::new("openssl").args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_pem.to_str().unwrap(),
            "-out",
            cert_pem.to_str().unwrap(),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/C=IN/ST=KA/O=Hunchbite Synthetic CA/CN=Synthetic Indian DSC",
        ]))?;
        run(Command::new("openssl").args([
            "rsa",
            "-in",
            key_pem.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            key_der.to_str().unwrap(),
        ]))?;
        run(Command::new("openssl").args([
            "rsa",
            "-in",
            key_pem.to_str().unwrap(),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            pub_der.to_str().unwrap(),
        ]))?;
        run(Command::new("openssl").args([
            "x509",
            "-in",
            cert_pem.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            cert_der.to_str().unwrap(),
        ]))?;
        run(Command::new("openssl").args([
            "x509",
            "-in",
            cert_pem.to_str().unwrap(),
            "-pubkey",
            "-noout",
            "-out",
            public_pem.to_str().unwrap(),
        ]))?;

        run(Command::new("softhsm2-util")
            .env("SOFTHSM2_CONF", &conf_path)
            .args([
                "--init-token",
                "--free",
                "--label",
                FIXTURE_TOKEN_LABEL,
                "--pin",
                FIXTURE_USER_PIN,
                "--so-pin",
                FIXTURE_SO_PIN,
            ]))?;

        let slot_id = resolve_slot(&conf_path, FIXTURE_TOKEN_LABEL)?;
        let mod_s = module.to_str().unwrap();

        run(Command::new("pkcs11-tool")
            .env("SOFTHSM2_CONF", &conf_path)
            .args([
                "--module",
                mod_s,
                "--login",
                "--pin",
                FIXTURE_USER_PIN,
                "--write-object",
                key_der.to_str().unwrap(),
                "--type",
                "privkey",
                "--label",
                FIXTURE_KEY_LABEL,
                "--id",
                FIXTURE_OBJECT_ID,
                "--usage-sign",
            ]))?;
        run(Command::new("pkcs11-tool")
            .env("SOFTHSM2_CONF", &conf_path)
            .args([
                "--module",
                mod_s,
                "--login",
                "--pin",
                FIXTURE_USER_PIN,
                "--write-object",
                pub_der.to_str().unwrap(),
                "--type",
                "pubkey",
                "--label",
                FIXTURE_KEY_LABEL,
                "--id",
                FIXTURE_OBJECT_ID,
            ]))?;
        run(Command::new("pkcs11-tool")
            .env("SOFTHSM2_CONF", &conf_path)
            .args([
                "--module",
                mod_s,
                "--login",
                "--pin",
                FIXTURE_USER_PIN,
                "--write-object",
                cert_der.to_str().unwrap(),
                "--type",
                "cert",
                "--label",
                FIXTURE_KEY_LABEL,
                "--id",
                FIXTURE_OBJECT_ID,
            ]))?;

        std::env::set_var("SOFTHSM2_CONF", &conf_path);

        Ok(Self {
            _dir: dir,
            module,
            slot_id,
            label: FIXTURE_KEY_LABEL.into(),
            pin: FIXTURE_USER_PIN.into(),
            conf_path,
            public_pem,
            certificate_pem: cert_pem,
        })
    }

    /// Activate this fixture's SoftHSM config in the process environment.
    pub fn activate(&self) {
        std::env::set_var("SOFTHSM2_CONF", &self.conf_path);
    }

    /// PKCS#11 certificate id for the synthetic key.
    pub fn certificate_id(&self) -> String {
        crate::pkcs11::CertificateId::format(&self.module, self.slot_id, &self.label)
    }

    /// Backend pointed only at this SoftHSM module.
    pub fn backend(&self) -> Pkcs11Backend {
        self.activate();
        Pkcs11Backend::new(vec![self.module.clone()])
    }

    /// Path to the SoftHSM conf file.
    pub fn conf(&self) -> &Path {
        &self.conf_path
    }
}

fn run(cmd: &mut Command) -> Result<()> {
    let output = cmd
        .output()
        .map_err(|e| Error::Config(format!("spawn {:?}: {e}", cmd)))?;
    if !output.status.success() {
        return Err(Error::Config(format!(
            "command failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        )));
    }
    Ok(())
}

fn resolve_slot(conf: &Path, label: &str) -> Result<u64> {
    let output = Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", conf)
        .arg("--show-slots")
        .output()
        .map_err(|e| Error::Config(format!("show-slots: {e}")))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut current_slot: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Slot ") {
            if let Some(num) = rest.split_whitespace().next() {
                if let Ok(id) = num.parse::<u64>() {
                    current_slot = Some(id);
                }
            }
        }
        if let Some(rest) = line.strip_prefix("Label:") {
            let lab = rest.trim();
            if lab == label {
                return current_slot
                    .ok_or_else(|| Error::Config("slot label found without slot id".into()));
            }
        }
    }
    Err(Error::Config(format!(
        "token label {label} not found in softhsm slots:\n{text}"
    )))
}
