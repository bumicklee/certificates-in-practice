/*
 * 13-2: mutual-TLS MQTT to the local Mosquitto (mqtts, port 8883) and heap measurement.
 * The board verifies the broker with the lab root and presents its own client certificate.
 * Reconnects are scheduled by an esp_timer with exponential backoff (no blocking loops).
 */
#include <string.h>
#include "sdkconfig.h"
#include "esp_timer.h"
#include "mqtt_client.h"
#include "esp_tls.h"
#include "lab_common.h"

#define MQTT_CLIENT_ID          "dev-001"
#define MQTT_TOPIC_HELLO        "certlab/dev-001/hello"
#define MQTT_TOPIC_CMD          "certlab/dev-001/cmd"
#define MQTT_BACKOFF_MIN_MS     2000U
#define MQTT_BACKOFF_MAX_MS     60000U
#define WIFI_WAIT_MS            20000
#define SNTP_ATTEMPT_MS         8000
#define SNTP_MAX_ATTEMPTS       5
#define MQTT_TASK_STACK         6144
#define MQTT_TASK_PRIO          5

static esp_mqtt_client_handle_t s_client;
static esp_timer_handle_t s_reconnect_timer;
static uint32_t s_backoff_ms = MQTT_BACKOFF_MIN_MS;
static uint32_t s_heap_before_connect;
static int64_t s_connect_start_us;

static void reconnect_timer_cb(void *arg)
{
    ESP_LOGI(LAB_TAG, "[MQTT] reconnecting...");
    esp_mqtt_client_reconnect(s_client);
}

static void schedule_reconnect(void)
{
    ESP_LOGW(LAB_TAG, "[MQTT] retry in %" PRIu32 " ms", s_backoff_ms);
    esp_timer_start_once(s_reconnect_timer, (uint64_t)s_backoff_ms * 1000ULL);
    s_backoff_ms = (s_backoff_ms * 2 > MQTT_BACKOFF_MAX_MS) ? MQTT_BACKOFF_MAX_MS : s_backoff_ms * 2;
}

static void mqtt_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    esp_mqtt_event_handle_t ev = data;
    switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_BEFORE_CONNECT:
        s_heap_before_connect = esp_get_free_heap_size();
        s_connect_start_us = esp_timer_get_time();
        lab_log_heap("before TLS handshake");
        break;
    case MQTT_EVENT_CONNECTED: {
        uint32_t after = esp_get_free_heap_size();
        lab_log_heap("after TLS handshake");
        ESP_LOGI(LAB_TAG, "[MQTT-OK] connected with mTLS in %lld ms; heap used by TLS+MQTT = %" PRId32 " bytes",
                 (long long)((esp_timer_get_time() - s_connect_start_us) / 1000),
                 (int32_t)s_heap_before_connect - (int32_t)after);
        s_backoff_ms = MQTT_BACKOFF_MIN_MS;
        esp_mqtt_client_subscribe(s_client, MQTT_TOPIC_CMD, 1);
        char msg[64];
        snprintf(msg, sizeof(msg), "hello from cert-lab, min_free=%" PRIu32, esp_get_minimum_free_heap_size());
        esp_mqtt_client_publish(s_client, MQTT_TOPIC_HELLO, msg, 0, 1, 0);
        break;
    }
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(LAB_TAG, "[MQTT] disconnected");
        lab_log_heap("after disconnect");
        schedule_reconnect();
        break;
    case MQTT_EVENT_ERROR:
        if (ev->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            lab_log_tls_error("mqtt-transport", ev->error_handle->esp_tls_last_esp_err,
                              ev->error_handle->esp_tls_stack_err, ev->error_handle->esp_tls_cert_verify_flags);
            ESP_LOGE(LAB_TAG, "[MQTT] transport errno=%d", ev->error_handle->esp_transport_sock_errno);
        } else if (ev->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
            ESP_LOGE(LAB_TAG, "[MQTT] broker refused the connection, code=%d", ev->error_handle->connect_return_code);
        }
        lab_log_heap("after error");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(LAB_TAG, "[MQTT] subscribed to %s", MQTT_TOPIC_CMD);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(LAB_TAG, "[MQTT] published hello (msg_id=%d)", ev->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(LAB_TAG, "[MQTT] data on %.*s: %.*s", ev->topic_len, ev->topic, ev->data_len, ev->data);
        break;
    default:
        break;
    }
}

static void mqtt_task(void *arg)
{
    while (!lab_wifi_wait_connected(WIFI_WAIT_MS)) {
        ESP_LOGW(LAB_TAG, "[WIFI] still waiting for an IP address...");
    }
    // Server certificate dates are checked on the board, so it needs a valid clock first.
    lab_time_sync(SNTP_ATTEMPT_MS, SNTP_MAX_ATTEMPTS);
    lab_log_heap("baseline (before mqtt init)");

    char uri[64];
    snprintf(uri, sizeof(uri), "mqtts://%s:%d", CONFIG_LAB_SERVER_IP, CONFIG_LAB_MQTT_PORT);

    const char *crt = NULL, *key = NULL;
#if CONFIG_LAB_MQTT_CERT_VALID
    crt = lab_client_crt_pem; key = lab_client_key_pem;
    ESP_LOGI(LAB_TAG, "[MQTT] presenting client cert: dev-001 (valid)");
#elif CONFIG_LAB_MQTT_CERT_EXPIRED
    crt = lab_expired_crt_pem; key = lab_expired_key_pem;
    ESP_LOGI(LAB_TAG, "[MQTT] presenting client cert: dev-expired (EXPIRED)");
#else
    ESP_LOGW(LAB_TAG, "[MQTT] presenting NO client certificate");
#endif

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = uri,
        .broker.verification.certificate = lab_root_pem,
        .credentials.client_id = MQTT_CLIENT_ID,
        .credentials.authentication.certificate = crt,
        .credentials.authentication.key = key,
        .network.disable_auto_reconnect = true,     // we back off ourselves
        .network.timeout_ms = 10000,
    };
    s_client = esp_mqtt_client_init(&cfg);
    if (s_client == NULL) {
        ESP_LOGE(LAB_TAG, "[MQTT] client init failed");
        vTaskDelete(NULL);
        return;
    }
    const esp_timer_create_args_t targs = { .callback = reconnect_timer_cb, .name = "mqtt_retry" };
    ESP_ERROR_CHECK(esp_timer_create(&targs, &s_reconnect_timer));
    ESP_ERROR_CHECK(esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL));
    ESP_LOGI(LAB_TAG, "[MQTT] connecting to %s", uri);
    ESP_ERROR_CHECK(esp_mqtt_client_start(s_client));
    vTaskDelete(NULL);   // the esp-mqtt task and esp_timer drive everything from here
}

void lab_mqtt_start(void)
{
    xTaskCreate(mqtt_task, "mqtt_boot", MQTT_TASK_STACK, NULL, MQTT_TASK_PRIO, NULL);
}
