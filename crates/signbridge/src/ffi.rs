//! C ABI — JSON in, JSON out — for any language that can call C.
//!
//! ```c
//! SignBridge *sb = signbridge_new(NULL);
//! char *out = signbridge_request(sb, "{\"id\":\"1\",\"method\":\"ping\"}");
//! signbridge_string_free(out);
//! signbridge_free(sb);
//! ```

use crate::config::AppConfig;
use crate::ipc::handle_bytes;
use crate::service::{AutoConfirm, SignService};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// Opaque handle for C callers.
pub struct SignBridgeHandle {
    service: SignService<AutoConfirm>,
}

fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

fn to_c_string(s: impl Into<String>) -> *mut c_char {
    CString::new(s.into())
        .unwrap_or_else(|_| CString::new("{\"ok\":false,\"error\":{\"code\":\"internal\",\"message\":\"nul\"}}").unwrap())
        .into_raw()
}

/// Create a SignBridge instance.
///
/// `config_json` may be null (defaults) or a JSON object matching [`AppConfig`].
/// `pin` may be null; otherwise used as the token PIN (automation / tests).
///
/// # Safety
/// `config_json` and `pin` must be null or valid UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn signbridge_new(
    config_json: *const c_char,
    pin: *const c_char,
) -> *mut SignBridgeHandle {
    let mut config = if let Some(raw) = cstr_to_str(config_json) {
        match serde_json::from_str::<AppConfig>(raw) {
            Ok(c) => c,
            Err(_) => return ptr::null_mut(),
        }
    } else {
        AppConfig::for_cli()
    };
    config.skip_origin_check = true;
    if let Some(p) = cstr_to_str(pin) {
        config.test_pin = Some(p.to_string());
    }
    let pin_owned = config.test_pin.clone();
    let handle = SignBridgeHandle {
        service: SignService::new(config, AutoConfirm { pin: pin_owned }),
    };
    Box::into_raw(Box::new(handle))
}

/// Free a handle from [`signbridge_new`].
///
/// # Safety
/// `handle` must be null or a pointer from [`signbridge_new`].
#[no_mangle]
pub unsafe extern "C" fn signbridge_free(handle: *mut SignBridgeHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Run one JSON protocol request; returns a heap JSON string (free with
/// [`signbridge_string_free`]).
///
/// # Safety
/// `handle` from [`signbridge_new`]; `request_json` valid UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn signbridge_request(
    handle: *mut SignBridgeHandle,
    request_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return to_c_string(
            r#"{"id":"0","ok":false,"error":{"code":"internal","message":"null handle"}}"#,
        );
    }
    let Some(req) = cstr_to_str(request_json) else {
        return to_c_string(
            r#"{"id":"0","ok":false,"error":{"code":"protocol","message":"invalid utf-8"}}"#,
        );
    };
    let out = handle_bytes(&(*handle).service, req.as_bytes());
    match String::from_utf8(out) {
        Ok(s) => to_c_string(s),
        Err(_) => to_c_string(
            r#"{"id":"0","ok":false,"error":{"code":"internal","message":"non-utf8"}}"#,
        ),
    }
}

/// Free a string returned by [`signbridge_request`].
///
/// # Safety
/// `s` must be null or a pointer from [`signbridge_request`].
#[no_mangle]
pub unsafe extern "C" fn signbridge_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Library semver as a static C string.
#[no_mangle]
pub extern "C" fn signbridge_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
