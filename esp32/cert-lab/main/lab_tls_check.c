/*
 * 13-1: server certificate check.
 *
 * One boot runs these cases against the PC lab server (https_server.py), all trusting ONLY the lab root:
 *   E  no time        : good server, but the clock is still 1970            -> FUTURE flag
 *   B  private root   : good server, clock synced                           -> success
 *   C  wrong hostname : lab-signed cert whose SAN does not name this host   -> CN_MISMATCH flag
 *   D  unknown root   : server chain from a root the board does not know    -> NOT_TRUSTED flag
 * With LAB_SKIP_SNTP the clock never gets synced, so B/C/D fail with the 1970 error as well.
 * (A public-CA test with esp_crt_bundle is intentionally not part of this lab.)
 */
#include <string.h>
#include "sdkconfig.h"
#include "esp_http_client.h"
#include "lab_common.h"

#define HTTP_TIMEOUT_MS         8000
#define WIFI_WAIT_MS            20000
#define SNTP_ATTEMPT_MS         8000
#define SNTP_MAX_ATTEMPTS       5
#define BODY_MAX                127
#define TLS_TASK_STACK          8192
#define TLS_TASK_PRIO           5

typedef struct {
    const char *id;
    const char *description;
    int port;
} lab_case_t;

static void run_case(const lab_case_t *c)
{
    char url[96];
    lab_server_url(url, sizeof(url), c->port, "/hello");
    ESP_LOGI(LAB_TAG, "---- case %s: %s -> %s", c->id, c->description, url);
    lab_log_time("clock at request");
    lab_log_heap("before TLS");

    esp_http_client_config_t cfg = {
        .url = url,
        .cert_pem = lab_root_pem,           // trust exactly one root: the lab root
        .timeout_ms = HTTP_TIMEOUT_MS,
        .keep_alive_enable = false,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        ESP_LOGE(LAB_TAG, "[RESULT] case=%s http client init failed", c->id);
        return;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err == ESP_OK) {
        int64_t len = esp_http_client_fetch_headers(client);
        int status = esp_http_client_get_status_code(client);
        char body[BODY_MAX + 1] = { 0 };
        int n = esp_http_client_read(client, body, BODY_MAX);
        (void)len;
        ESP_LOGI(LAB_TAG, "[TLS-OK] server certificate accepted; HTTP %d, body: %.*s", status, n > 0 ? n : 0, body);
        ESP_LOGI(LAB_TAG, "[RESULT] case=%s TRUSTED", c->id);
    } else {
        int tls_code = 0, tls_flags = 0;
        esp_http_client_get_and_clear_last_tls_error(client, &tls_code, &tls_flags);
        lab_log_tls_error(c->id, err, tls_code, tls_flags);
        ESP_LOGE(LAB_TAG, "[RESULT] case=%s REJECTED", c->id);
    }
    esp_http_client_cleanup(client);
    lab_log_heap("after TLS");
}

static void tls_check_task(void *arg)
{
    const lab_case_t case_no_time   = { "E-no-time", "good server, clock is 1970", CONFIG_LAB_PORT_GOOD };
    const lab_case_t case_private   = { "B-private-root", "good server, lab root embedded", CONFIG_LAB_PORT_GOOD };
    const lab_case_t case_wrongname = { "C-wrong-hostname", "lab-signed cert with another name", CONFIG_LAB_PORT_WRONGNAME };
    const lab_case_t case_unknown   = { "D-unknown-root", "chain from a root the board does not know", CONFIG_LAB_PORT_ROGUE };

    while (!lab_wifi_wait_connected(WIFI_WAIT_MS)) {
        ESP_LOGW(LAB_TAG, "[WIFI] still waiting for an IP address...");
    }

    lab_time_force_epoch0();
    lab_log_time("after boot");

    run_case(&case_no_time);                       // clock is 1970 -> must fail with FUTURE

    bool synced = lab_time_sync(SNTP_ATTEMPT_MS, SNTP_MAX_ATTEMPTS);
    ESP_LOGI(LAB_TAG, "[TIME] clock valid after sync step: %s", synced ? "yes" : "NO");

    run_case(&case_private);
    run_case(&case_wrongname);
    run_case(&case_unknown);

    ESP_LOGI(LAB_TAG, "==== 13-1 finished (reset the board to run again) ====");
    vTaskDelete(NULL);
}

void lab_tls_check_start(void)
{
    // Single-core ESP32-C5: no core pinning, the Wi-Fi stack tasks have higher priority anyway.
    xTaskCreate(tls_check_task, "tls_check", TLS_TASK_STACK, NULL, TLS_TASK_PRIO, NULL);
}
