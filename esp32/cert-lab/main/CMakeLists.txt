# Embedded PEMs come from the demo PKI made by ../../make_pki.sh (run it BEFORE building).
set(PKI_EMBED "${CMAKE_CURRENT_LIST_DIR}/../../demo-pki/embed")
foreach(f lab_root.crt client.crt client.key expired_client.crt expired_client.key)
    if(NOT EXISTS "${PKI_EMBED}/${f}")
        message(FATAL_ERROR "Missing ${PKI_EMBED}/${f}. Run ./make_pki.sh <PC_LAN_IP> first.")
    endif()
endforeach()

idf_component_register(
    SRCS "main.c" "lab_util.c" "lab_wifi.c" "lab_time.c"
         "lab_tls_check.c" "lab_mqtt.c" "lab_ota.c"
    INCLUDE_DIRS "."
    REQUIRES nvs_flash esp_wifi esp_netif esp_event esp_timer esp_http_client esp_https_ota
             esp-tls mqtt mbedtls app_update esp_app_format esp_system
    EMBED_TXTFILES
        "${PKI_EMBED}/lab_root.crt"
        "${PKI_EMBED}/client.crt"
        "${PKI_EMBED}/client.key"
        "${PKI_EMBED}/expired_client.crt"
        "${PKI_EMBED}/expired_client.key"
)
