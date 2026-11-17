#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "sdkconfig.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "lab_common.h"

void lab_log_heap(const char *label)
{
    ESP_LOGI(LAB_TAG, "[HEAP] %-28s free=%" PRIu32 " min_free=%" PRIu32 " largest_block=%u",
             label, esp_get_free_heap_size(), esp_get_minimum_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
}

void lab_log_tls_error(const char *what, esp_err_t err, int tls_code, int tls_flags)
{
    char code_txt[100] = "-";
    char flag_txt[256] = "-";

    if (tls_code != 0) {
        mbedtls_strerror(tls_code, code_txt, sizeof(code_txt));
    }
    if (tls_flags != 0) {
        // one line per failed check, e.g. "The certificate is not correctly signed by the trusted CA"
        int n = mbedtls_x509_crt_verify_info(flag_txt, sizeof(flag_txt), "", (uint32_t)tls_flags);
        while (n > 0 && (flag_txt[n - 1] == '\n' || flag_txt[n - 1] == ' ')) {
            flag_txt[--n] = '\0';
        }
        for (char *p = flag_txt; *p; p++) {
            if (*p == '\n') *p = '|';
        }
    }
    ESP_LOGE(LAB_TAG, "[TLS-FAIL] %s: esp_err=%s(0x%x) mbedtls_code=-0x%04X (%s) cert_flags=0x%04X (%s)",
             what, esp_err_to_name(err), (unsigned)err, (unsigned)(-tls_code), code_txt,
             (unsigned)tls_flags, flag_txt);
}

void lab_log_time(const char *label)
{
    time_t now = 0;
    time(&now);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    ESP_LOGI(LAB_TAG, "[TIME] %-22s %s epoch=%lld valid=%s", label, buf, (long long)now,
             lab_time_is_valid() ? "yes" : "NO");
}

void lab_server_url(char *buf, size_t len, int port, const char *path)
{
    snprintf(buf, len, "https://%s:%d%s", CONFIG_LAB_SERVER_IP, port, path);
}
