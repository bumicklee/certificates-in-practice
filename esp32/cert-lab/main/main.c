/*
 * cert-lab: teaching firmware for "TLS/PKI from server to ESP32".
 * LAB_MODE (menuconfig -> Cert Lab) selects the demo: 13-1 / 13-2 / 13-3.
 * app_main only initialises the system and hands over to the demo task; it does not block.
 */
#include "sdkconfig.h"
#include "esp_app_desc.h"
#include "nvs_flash.h"
#include "lab_common.h"

void app_main(void)
{
    const esp_app_desc_t *app = esp_app_get_description();
    ESP_LOGI(LAB_TAG, "==== cert-lab start: version=%s idf=%s ====", app->version, app->idf_ver);
    lab_log_heap("boot");

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    lab_ota_report_boot();
    ESP_ERROR_CHECK(lab_wifi_start());

#if CONFIG_LAB_MODE_SERVER_CHECK
    ESP_LOGI(LAB_TAG, "mode: 13-1 server certificate check");
    lab_tls_check_start();
#elif CONFIG_LAB_MODE_MTLS_MQTT
    ESP_LOGI(LAB_TAG, "mode: 13-2 mTLS MQTT");
    lab_mqtt_start();
#elif CONFIG_LAB_MODE_SIGNED_OTA
    ESP_LOGI(LAB_TAG, "mode: 13-3 signed OTA + rollback");
    lab_ota_start();
#endif
}
