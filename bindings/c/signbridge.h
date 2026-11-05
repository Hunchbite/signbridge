#ifndef SIGNBRIDGE_H
#define SIGNBRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * Opaque SignBridge instance (JSON protocol, PKCS#11 backends).
 *
 * Build: cargo build -p signbridge --features ffi --release
 * Library: target/release/libsignbridge.{dylib,so,dll}
 */
typedef struct SignBridgeHandle SignBridge;

/**
 * Create a handle.
 * @param config_json  NULL for defaults, or AppConfig JSON.
 * @param pin          NULL, or token PIN for automation.
 * @return handle or NULL on bad config JSON.
 */
SignBridge *signbridge_new(const char *config_json, const char *pin);

/** Destroy a handle from signbridge_new. */
void signbridge_free(SignBridge *handle);

/**
 * Run one protocol request (see docs/PROTOCOL.md).
 * @return malloc'd JSON response string; free with signbridge_string_free.
 */
char *signbridge_request(SignBridge *handle, const char *request_json);

/** Free a string from signbridge_request. */
void signbridge_string_free(char *s);

/** Static NUL-terminated semver string. */
const char *signbridge_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SIGNBRIDGE_H */
