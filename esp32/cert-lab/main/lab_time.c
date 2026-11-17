/*
 * Clock handling. A board that just powered on believes it is 1970-01-01:
 * every certificate is then "not yet valid" (X509 flag FUTURE).
 */
#include <sys/time.h>
#include <time.h>
#include "sdkconfig.h"
#include "esp_netif_sntp.h"
#include "lab_common.h"

#define SNTP_BACKOFF_MAX_MS  16000U

bool lab_time_is_valid(void)
{
    time_t now = 0;
    time(&now);
    return now >= (time_t)CONFIG_LAB_MIN_VALID_EPOCH;
}

void lab_time_force_epoch0(void)
{
    struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
    settimeofday(&tv, NULL);
    ESP_LOGW(LAB_TAG, "[TIME] clock forced to the UNIX epoch to reproduce a freshly powered board");
}

bool lab_time_sync(uint32_t per_attempt_ms, uint8_t max_attempts)
{
    lab_log_time("before sync");
#if CONFIG_LAB_SKIP_SNTP
    ESP_LOGW(LAB_TAG, "[TIME] LAB_SKIP_SNTP is set: time sync skipped on purpose");
    return false;
#else
    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(CONFIG_LAB_NTP_SERVER);
    esp_err_t err = esp_netif_sntp_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(LAB_TAG, "[TIME] sntp init failed: %s", esp_err_to_name(err));
        return false;
    }
    uint32_t backoff_ms = 1000;
    bool ok = false;
    for (uint8_t attempt = 1; attempt <= max_attempts && !ok; attempt++) {
        ESP_LOGI(LAB_TAG, "[TIME] SNTP attempt %u/%u (server %s)", attempt, max_attempts, CONFIG_LAB_NTP_SERVER);
        if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(per_attempt_ms)) == ESP_OK && lab_time_is_valid()) {
            ok = true;
        } else {
            ESP_LOGW(LAB_TAG, "[TIME] SNTP not synced yet, wait %" PRIu32 " ms", backoff_ms);
            vTaskDelay(pdMS_TO_TICKS(backoff_ms));
            backoff_ms = (backoff_ms * 2 > SNTP_BACKOFF_MAX_MS) ? SNTP_BACKOFF_MAX_MS : backoff_ms * 2;
        }
    }
    lab_log_time("after sync");
    return ok;
#endif
}
