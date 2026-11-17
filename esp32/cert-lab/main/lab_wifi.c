/*
 * Wi-Fi station with event-driven reconnect (exponential backoff, no blocking delays).
 */
#include <string.h>
#include "sdkconfig.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"
#include "lab_common.h"

#define WIFI_CONNECTED_BIT      BIT0
#define WIFI_BACKOFF_MIN_MS     1000U
#define WIFI_BACKOFF_MAX_MS     30000U

static EventGroupHandle_t s_events;
static esp_timer_handle_t s_retry_timer;
static uint32_t s_backoff_ms = WIFI_BACKOFF_MIN_MS;

static void retry_timer_cb(void *arg)
{
    ESP_LOGI(LAB_TAG, "[WIFI] reconnecting...");
    esp_wifi_connect();
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *ev = data;
        xEventGroupClearBits(s_events, WIFI_CONNECTED_BIT);
        ESP_LOGW(LAB_TAG, "[WIFI] disconnected (reason=%d), retry in %" PRIu32 " ms", ev->reason, s_backoff_ms);
        esp_timer_start_once(s_retry_timer, (uint64_t)s_backoff_ms * 1000ULL);
        s_backoff_ms = (s_backoff_ms * 2 > WIFI_BACKOFF_MAX_MS) ? WIFI_BACKOFF_MAX_MS : s_backoff_ms * 2;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *ev = data;
        ESP_LOGI(LAB_TAG, "[WIFI] got IP " IPSTR, IP2STR(&ev->ip_info.ip));
        s_backoff_ms = WIFI_BACKOFF_MIN_MS;
        xEventGroupSetBits(s_events, WIFI_CONNECTED_BIT);
    }
}

esp_err_t lab_wifi_start(void)
{
    if (strcmp(CONFIG_LAB_WIFI_SSID, "CHANGE_ME_SSID") == 0) {
        ESP_LOGE(LAB_TAG, "[WIFI] SSID is still the placeholder: set LAB_WIFI_SSID/PASSWORD (menuconfig or WIFI_SSID/WIFI_PASS env for build_all.sh)");
    }
    s_events = xEventGroupCreate();
    if (s_events == NULL) return ESP_ERR_NO_MEM;

    const esp_timer_create_args_t targs = { .callback = retry_timer_cb, .name = "wifi_retry" };
    ESP_ERROR_CHECK(esp_timer_create(&targs, &s_retry_timer));

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL));

    wifi_config_t wc = { 0 };
    strlcpy((char *)wc.sta.ssid, CONFIG_LAB_WIFI_SSID, sizeof(wc.sta.ssid));
    strlcpy((char *)wc.sta.password, CONFIG_LAB_WIFI_PASSWORD, sizeof(wc.sta.password));
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wc.sta.pmf_cfg.capable = true;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);
    ESP_LOGI(LAB_TAG, "[WIFI] started, SSID=%s", CONFIG_LAB_WIFI_SSID);
    return ESP_OK;
}

bool lab_wifi_wait_connected(uint32_t timeout_ms)
{
    EventBits_t b = xEventGroupWaitBits(s_events, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(timeout_ms));
    return (b & WIFI_CONNECTED_BIT) != 0;
}

bool lab_wifi_is_connected(void)
{
    return s_events && (xEventGroupGetBits(s_events) & WIFI_CONNECTED_BIT);
}
