/*
 * 13-3: signed OTA + rollback.
 *
 * - Images carry an ECDSA signature block (CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT). The running app holds the
 *   public key; esp_ota_end() (called by esp_https_ota_finish()) verifies the block, so an image signed with
 *   another key is refused with ESP_ERR_OTA_VALIDATE_FAILED. No eFuse is involved.
 * - CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE: a freshly OTA-booted app is PENDING_VERIFY. It marks itself valid only
 *   after a self-test; if the self-test fails the app marks itself invalid and the bootloader returns to the old slot.
 * - TLS to the OTA server uses the embedded lab root (transport security is a separate thing from image signing).
 */
#include <string.h>
#include "sdkconfig.h"
#include "esp_app_desc.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "lab_common.h"

#define WIFI_WAIT_MS            20000
#define SNTP_ATTEMPT_MS         8000
#define SNTP_MAX_ATTEMPTS       5
#define SELFTEST_MIN_HEAP       60000U
#define SELFTEST_WIFI_MS        15000
#define OTA_HTTP_TIMEOUT_MS     10000
#define OTA_RETRY_MIN_MS        5000U
#define OTA_RETRY_MAX_MS        60000U
#define OTA_MAX_ATTEMPTS        5
#define REBOOT_DELAY_MS         3000
#define OTA_TASK_STACK          8192
#define OTA_TASK_PRIO           5

static const char *state_name(esp_ota_img_states_t s)
{
    switch (s) {
    case ESP_OTA_IMG_NEW:            return "NEW";
    case ESP_OTA_IMG_PENDING_VERIFY: return "PENDING_VERIFY";
    case ESP_OTA_IMG_VALID:          return "VALID";
    case ESP_OTA_IMG_INVALID:        return "INVALID";
    case ESP_OTA_IMG_ABORTED:        return "ABORTED";
    case ESP_OTA_IMG_UNDEFINED:      return "UNDEFINED";
    default:                         return "?";
    }
}

bool lab_ota_report_boot(void)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st = ESP_OTA_IMG_UNDEFINED;
    esp_ota_get_state_partition(run, &st);
    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(LAB_TAG, "[BOOT] running slot=%s offset=0x%x version=%s state=%s",
             run->label, (unsigned)run->address, app->version, state_name(st));

    const esp_partition_t *bad = esp_ota_get_last_invalid_partition();
    if (bad != NULL) {
        esp_app_desc_t bad_desc;
        if (esp_ota_get_partition_description(bad, &bad_desc) == ESP_OK) {
            ESP_LOGW(LAB_TAG, "[ROLLBACK] last invalid slot=%s version=%s (this boot is the result of a rollback)",
                     bad->label, bad_desc.version);
        }
    }
    return st == ESP_OTA_IMG_PENDING_VERIFY;
}

/** Self-test of a freshly updated app. Returns true when everything the app needs works. */
static bool run_selftest(void)
{
    bool ok = true;

    uint32_t heap = esp_get_free_heap_size();
    bool heap_ok = heap >= SELFTEST_MIN_HEAP;
    ESP_LOGI(LAB_TAG, "[SELFTEST] heap %" PRIu32 " >= %u : %s", heap, SELFTEST_MIN_HEAP, heap_ok ? "pass" : "FAIL");
    ok &= heap_ok;

    bool wifi_ok = lab_wifi_wait_connected(SELFTEST_WIFI_MS);
    ESP_LOGI(LAB_TAG, "[SELFTEST] wifi got IP : %s", wifi_ok ? "pass" : "FAIL");
    ok &= wifi_ok;

#if CONFIG_LAB_SELFTEST_FORCE_FAIL
    ESP_LOGE(LAB_TAG, "[SELFTEST] forced failure (this is the BAD build used to trigger rollback)");
    ok = false;
#endif
    return ok;
}

/** true when `candidate` is the version we already run or one that was rolled back before. */
static bool version_should_be_skipped(const char *candidate)
{
    const esp_app_desc_t *run = esp_app_get_description();
    if (strcmp(candidate, run->version) == 0) {
        ESP_LOGI(LAB_TAG, "[OTA] server offers %s = running version, nothing to do", candidate);
        return true;
    }
    const esp_partition_t *bad = esp_ota_get_last_invalid_partition();
    esp_app_desc_t bad_desc;
    if (bad != NULL && esp_ota_get_partition_description(bad, &bad_desc) == ESP_OK &&
        strcmp(candidate, bad_desc.version) == 0) {
        ESP_LOGW(LAB_TAG, "[OTA] server offers %s which already failed its self-test: skipping", candidate);
        return true;
    }
    return false;
}

typedef enum { OTA_DONE, OTA_RETRY, OTA_REJECTED } ota_result_t;

static ota_result_t try_ota_once(void)
{
    char url[96];
    lab_server_url(url, sizeof(url), CONFIG_LAB_OTA_PORT, CONFIG_LAB_OTA_PATH);
    ESP_LOGI(LAB_TAG, "[OTA] checking %s", url);

    esp_http_client_config_t http = {
        .url = url,
        .cert_pem = lab_root_pem,
        .timeout_ms = OTA_HTTP_TIMEOUT_MS,
        .keep_alive_enable = true,
    };
    esp_https_ota_config_t ota_cfg = { .http_config = &http };
    esp_https_ota_handle_t h = NULL;

    esp_err_t err = esp_https_ota_begin(&ota_cfg, &h);
    if (err != ESP_OK) {
        ESP_LOGE(LAB_TAG, "[OTA] begin failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
        return OTA_RETRY;
    }
    esp_app_desc_t new_desc;
    err = esp_https_ota_get_img_desc(h, &new_desc);
    if (err != ESP_OK) {
        ESP_LOGE(LAB_TAG, "[OTA] cannot read image header: %s", esp_err_to_name(err));
        esp_https_ota_abort(h);
        return OTA_REJECTED;
    }
    ESP_LOGI(LAB_TAG, "[OTA] offered image: version=%s project=%s", new_desc.version, new_desc.project_name);
    if (version_should_be_skipped(new_desc.version)) {
        esp_https_ota_abort(h);
        return OTA_DONE;
    }

    while ((err = esp_https_ota_perform(h)) == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
        // esp_https_ota_perform() reads one chunk per call; log progress occasionally
        static int last_pct = -10;
        int len = esp_https_ota_get_image_len_read(h);
        int total = esp_https_ota_get_image_size(h);
        int pct = total > 0 ? (int)((int64_t)len * 100 / total) : 0;
        if (pct >= last_pct + 10) {
            last_pct = pct;
            ESP_LOGI(LAB_TAG, "[OTA] downloaded %d bytes (%d%%)", len, pct);
        }
    }
    if (err != ESP_OK) {
        ESP_LOGE(LAB_TAG, "[OTA] download failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
        esp_https_ota_abort(h);
        return OTA_RETRY;
    }
    if (!esp_https_ota_is_complete_data_received(h)) {
        ESP_LOGE(LAB_TAG, "[OTA] incomplete data received");
        esp_https_ota_abort(h);
        return OTA_RETRY;
    }

    // esp_https_ota_finish() -> esp_ota_end(): image hash + signature block are verified here.
    err = esp_https_ota_finish(h);
    if (err == ESP_OK) {
        ESP_LOGI(LAB_TAG, "[OTA-OK] signature verified, image written. Rebooting into the new slot in %d ms", REBOOT_DELAY_MS);
        vTaskDelay(pdMS_TO_TICKS(REBOOT_DELAY_MS));
        esp_restart();
    }
    if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
        ESP_LOGE(LAB_TAG, "[OTA-REJECTED] image validation/signature verification FAILED: %s (0x%x). "
                          "The running slot is untouched.", esp_err_to_name(err), (unsigned)err);
        return OTA_REJECTED;
    }
    ESP_LOGE(LAB_TAG, "[OTA] finish failed: %s (0x%x)", esp_err_to_name(err), (unsigned)err);
    return OTA_RETRY;
}

static void ota_task(void *arg)
{
    while (!lab_wifi_wait_connected(WIFI_WAIT_MS)) {
        ESP_LOGW(LAB_TAG, "[WIFI] still waiting for an IP address...");
    }

    // 1) PENDING_VERIFY: self-test, then confirm or roll back
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st = ESP_OTA_IMG_UNDEFINED;
    esp_ota_get_state_partition(run, &st);
    if (st == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGI(LAB_TAG, "[SELFTEST] new image is PENDING_VERIFY: running self-test");
        if (run_selftest()) {
            esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
            ESP_LOGI(LAB_TAG, "[VALID] self-test passed, image marked valid (rollback cancelled): %s", esp_err_to_name(e));
        } else {
            ESP_LOGE(LAB_TAG, "[ROLLBACK] self-test FAILED: marking image invalid and rebooting into the previous slot in %d ms", REBOOT_DELAY_MS);
            vTaskDelay(pdMS_TO_TICKS(REBOOT_DELAY_MS));
            esp_ota_mark_app_invalid_rollback_and_reboot();   // does not return on success
            ESP_LOGE(LAB_TAG, "[ROLLBACK] rollback call returned (no previous valid slot?)");
        }
    }

#if CONFIG_LAB_OTA_CHECK_AT_BOOT
    // 2) clock first: the board checks the OTA server certificate dates
    if (!lab_time_sync(SNTP_ATTEMPT_MS, SNTP_MAX_ATTEMPTS)) {
        ESP_LOGE(LAB_TAG, "[OTA] clock not valid, TLS to the OTA server would fail; giving up");
        vTaskDelete(NULL);
        return;
    }
    // 3) ask the server; retry with exponential backoff on network trouble, never on a signature failure
    uint32_t backoff = OTA_RETRY_MIN_MS;
    for (int attempt = 1; attempt <= OTA_MAX_ATTEMPTS; attempt++) {
        lab_log_heap("before OTA");
        ota_result_t r = try_ota_once();
        if (r != OTA_RETRY) {
            break;
        }
        ESP_LOGW(LAB_TAG, "[OTA] attempt %d/%d failed, retry in %" PRIu32 " ms", attempt, OTA_MAX_ATTEMPTS, backoff);
        vTaskDelay(pdMS_TO_TICKS(backoff));
        backoff = (backoff * 2 > OTA_RETRY_MAX_MS) ? OTA_RETRY_MAX_MS : backoff * 2;
    }
#else
    ESP_LOGI(LAB_TAG, "[OTA] this build does not check for updates (LAB_OTA_CHECK_AT_BOOT off)");
#endif
    ESP_LOGI(LAB_TAG, "==== 13-3 idle: version=%s ====", esp_app_get_description()->version);
    vTaskDelete(NULL);
}

void lab_ota_start(void)
{
    xTaskCreate(ota_task, "ota", OTA_TASK_STACK, NULL, OTA_TASK_PRIO, NULL);
}
