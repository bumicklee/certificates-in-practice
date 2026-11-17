/*
 * cert-lab: shared declarations.
 * Course-only teaching firmware. All log lines use the tag CERTLAB so that
 * `idf.py monitor | grep CERTLAB` shows the story of each demo.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"

#define LAB_TAG "CERTLAB"

// ============================================
// EMBEDDED PEM FILES (from demo-pki/embed, NUL-terminated by EMBED_TXTFILES)
// ============================================
extern const char lab_root_pem[]          asm("_binary_lab_root_crt_start");
extern const char lab_client_crt_pem[]    asm("_binary_client_crt_start");
extern const char lab_client_key_pem[]    asm("_binary_client_key_start");
extern const char lab_expired_crt_pem[]   asm("_binary_expired_client_crt_start");
extern const char lab_expired_key_pem[]   asm("_binary_expired_client_key_start");

// ============================================
// lab_util.c
// ============================================
/** Log free heap, minimum-ever free heap and largest free block with a label. */
void lab_log_heap(const char *label);

/** Decode a TLS failure: esp_err name, Mbed TLS error (hex + text), certificate verify flags (hex + text). */
void lab_log_tls_error(const char *what, esp_err_t err, int tls_code, int tls_flags);

/** Log the current system time as ISO-8601 UTC with a label and whether it counts as valid. */
void lab_log_time(const char *label);

/** Returns the Kconfig-selected PC server URL, e.g. https://<PC_LAN_IP>:8443/hello (buffer must be >= 96 bytes). */
void lab_server_url(char *buf, size_t len, int port, const char *path);

// ============================================
// lab_wifi.c
// ============================================
/** Start Wi-Fi station; reconnects forever with exponential backoff (1 s .. 30 s). Non-blocking. */
esp_err_t lab_wifi_start(void);

/** Wait until an IP address is held. Returns true if connected within timeout_ms. */
bool lab_wifi_wait_connected(uint32_t timeout_ms);
bool lab_wifi_is_connected(void);

// ============================================
// lab_time.c
// ============================================
/** True when the system clock is past LAB_MIN_VALID_EPOCH. */
bool lab_time_is_valid(void);

/** Force the clock to the UNIX epoch (1970) so the "no time" failure is reproducible. */
void lab_time_force_epoch0(void);

/** Run SNTP (retry with backoff, max_attempts). Logs time before and after. Returns true when the clock became valid. */
bool lab_time_sync(uint32_t per_attempt_ms, uint8_t max_attempts);

// ============================================
// Demo entry points (each creates its own FreeRTOS task and returns)
// ============================================
void lab_tls_check_start(void);   // 13-1
void lab_mqtt_start(void);        // 13-2
void lab_ota_start(void);         // 13-3

/** Logs running partition, version, OTA state. Returns true if the app is in PENDING_VERIFY. */
bool lab_ota_report_boot(void);
