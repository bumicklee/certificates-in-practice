/* QEMU-only course demo: prints what the running app sees about Secure Boot / flash encryption.
 * Based on examples/get-started/hello_world. Never flash the images built here to a real board. */
#include <stdio.h>
#include "esp_log.h"
#include "esp_secure_boot.h"
#include "esp_flash_encrypt.h"

static const char *TAG = "qemu_sb";

void app_main(void)
{
    static const char *fe_mode[] = {"DISABLED", "DEVELOPMENT", "RELEASE"};
    esp_flash_enc_mode_t mode = esp_get_flash_encryption_mode();
    ESP_LOGI(TAG, "app started (QEMU esp32c3, course demo)");
    ESP_LOGI(TAG, "secure boot: %s", esp_secure_boot_enabled() ? "ON" : "off");
    ESP_LOGI(TAG, "flash encryption: %s", (mode <= ESP_FLASH_ENC_MODE_RELEASE) ? fe_mode[mode] : "?");
}
