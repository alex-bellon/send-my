#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "nvs_flash.h"
#include "esp_partition.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatt_defs.h"
#include "esp_bt_main.h"
#include "esp_bt_defs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "driver/uart.h"
#include "driver/gpio.h"
#include "sdkconfig.h"

#include "uECC.h"

#include <esp_wifi.h>
#include <esp_http_server.h>
#include "esp_system.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_tls_crypto.h"
#include <sys/param.h>

#define CHECK_BIT(var,pos) ((var) & (1<<(7-pos)))

#define TEST_RTS (18)
#define TEST_CTS (18)

#define UART_PORT_NUM      (0)
#define UART_BAUD_RATE     (115200)
#define TASK_STACK_SIZE    (2048)

#define BUF_SIZE (1024)

#define EXAMPLE_ESP_WIFI_SSID      "pascal"
#define EXAMPLE_ESP_WIFI_PASS      "ilikecode"
#define EXAMPLE_ESP_MAXIMUM_RETRY  5


#if CONFIG_ESP_WIFI_AUTH_OPEN
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_OPEN
#elif CONFIG_ESP_WIFI_AUTH_WEP
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WEP
#elif CONFIG_ESP_WIFI_AUTH_WPA_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WAPI_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WAPI_PSK
#else
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD WIFI_AUTH_WPA2_PSK
#endif

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;


/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG = "wifi station";

static int s_retry_num = 0;


// Set custom modem id before flashing:
static uint32_t modem_id = 0xcafe0000;

static const char* LOG_TAG = "findmy_modem";

/** Callback function for BT events */
static void esp_gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param);

/** Random device address */
static esp_bd_addr_t rnd_addr = { 0xFF, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

/** Advertisement payload */
static uint8_t adv_data[31] = {
    0x1e, /* Length (30) */
    0xff, /* Manufacturer Specific Data (type 0xff) */
    0x4c, 0x00, /* Company ID (Apple) */
    0x12, 0x19, /* Offline Finding type and length */
    0x00, /* State */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, /* First two bits */
    0x00, /* Hint (0x00) */
};

uint8_t start_addr[20] = {
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00 
};

uint8_t curr_addr[20];  
uint32_t current_message_id = 0;

uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
};

/* https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/bluetooth/esp_gap_ble.html#_CPPv420esp_ble_adv_params_t */
static esp_ble_adv_params_t ble_adv_params = {
    // Advertising min interval:
    // Minimum advertising interval for undirected and low duty cycle
    // directed advertising. Range: 0x0020 to 0x4000 Default: N = 0x0800
    // (1.28 second) Time = N * 0.625 msec Time Range: 20 ms to 10.24 sec
    .adv_int_min        = 0x0640, 
    // Advertising max interval:
    // Maximum advertising interval for undirected and low duty cycle
    // directed advertising. Range: 0x0020 to 0x4000 Default: N = 0x0800
    // (1.28 second) Time = N * 0.625 msec Time Range: 20 ms to 10.24 sec
    .adv_int_max        = 0x0C80, 
    // Advertisement type
    .adv_type           = ADV_TYPE_NONCONN_IND,
    // Use the random address
    .own_addr_type      = BLE_ADDR_TYPE_RANDOM,
    // All channels
    .channel_map        = ADV_CHNL_ALL,
    // Allow both scan and connection requests from anyone. 
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static void esp_gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    esp_err_t err;

    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
            esp_ble_gap_start_advertising(&ble_adv_params);
            break;

        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            // is it running?
            if ((err = param->adv_start_cmpl.status) != ESP_BT_STATUS_SUCCESS) {
                ESP_LOGE(LOG_TAG, "advertising start failed: %s", esp_err_to_name(err));
            } else {
                ESP_LOGI(LOG_TAG, "advertising started");
            }
            break;

        case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
            if ((err = param->adv_stop_cmpl.status) != ESP_BT_STATUS_SUCCESS){
                ESP_LOGE(LOG_TAG, "adv stop failed: %s", esp_err_to_name(err));
            }
            else {
                ESP_LOGI(LOG_TAG, "advertising stopped");
            }
            break;
        default:
            break;
    }
}

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .password = EXAMPLE_ESP_WIFI_PASS,
            /* Authmode threshold resets to WPA2 as default if password matches WPA2 standards (pasword len => 8).
             * If you want to connect the device to deprecated WEP/WPA networks, Please set the threshold value
             * to WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK and set the password with length and format matching to
       * WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK standards.
             */
            .threshold.authmode = ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap SSID:%s password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to SSID:%s, password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }
}

int is_valid_pubkey(uint8_t *pub_key_compressed) {
   uint8_t with_sign_byte[29];
   uint8_t pub_key_uncompressed[128];
   const struct uECC_Curve_t * curve = uECC_secp224r1();
   with_sign_byte[0] = 0x02;
   memcpy(&with_sign_byte[1], pub_key_compressed, 28);
   uECC_decompress(with_sign_byte, pub_key_uncompressed, curve);
   if(!uECC_valid_public_key(pub_key_uncompressed, curve)) {
       //ESP_LOGW(LOG_TAG, "Generated public key tested as invalid");
       return 0;
   }
   return 1;
}

void pub_from_priv(uint8_t *pub_compressed, uint8_t *priv) {
   const struct uECC_Curve_t * curve = uECC_secp224r1();
   uint8_t pub_key_tmp[128];
   uECC_compute_public_key(priv, pub_key_tmp, curve);
   uECC_compress(pub_key_tmp, pub_compressed, curve);
}

void set_addr_from_key(esp_bd_addr_t addr, uint8_t *public_key) {
    addr[0] = public_key[0] | 0b11000000;
    addr[1] = public_key[1];
    addr[2] = public_key[2];
    addr[3] = public_key[3];
    addr[4] = public_key[4];
    addr[5] = public_key[5];
}

void set_payload_from_key(uint8_t *payload, uint8_t *public_key) {
    /* copy last 22 bytes */
    memcpy(&payload[7], &public_key[6], 22);
    /* append two bits of public key */
    payload[29] = public_key[0] >> 6;
}

void copy_4b_big_endian(uint8_t *dst, uint8_t *src) {
    dst[0] = src[3]; dst[1] = src[2]; dst[2] = src[1]; dst[3] = src[0];
}

void copy_2b_big_endian(uint8_t *dst, uint8_t *src) {
    dst[0] = src[1]; dst[1] = src[0];
}

// index as first part of payload to have an often changing MAC address
// [2 byte magic] [4 byte modem_id] [2 byte tweak] [20 byte payload]
void set_addr_and_payload_for_byte(uint32_t index, uint32_t msg_id, uint8_t val, uint32_t chunk_len) {
    uint16_t valid_key_counter = 0;
    static uint8_t public_key[28] = {0};
    public_key[0] = 0xBA; // magic value
    public_key[1] = 0xBE;
    copy_4b_big_endian(&public_key[2], &modem_id);
    public_key[6] = 0x00;
    public_key[7] = 0x00;
    if (index) {
        memcpy(&public_key[8], &curr_addr, 20);
    } else {
        memcpy(&public_key[8], &start_addr, 20);
    }

    uint32_t offset = (chunk_len * (index + 1)) % (8 * chunk_len * (20 / chunk_len)); // mod the offset correctly
    uint32_t remain = 8 - ((chunk_len * index) % 8);
    
    if (remain == chunk_len) {
        uint8_t xor_val = val << (8 - remain);
        public_key[28 - (offset/8)] ^= xor_val;
    } else if (remain > chunk_len) {
        uint8_t xor_val = val << (8 - remain);
        public_key[28 - ((offset/8) + 1)] ^= xor_val;
    } else { 
        uint8_t xor_val_lo = val << (8 - remain);
        uint8_t xor_val_hi = val >> remain;
        public_key[28 - ((offset/8))] ^= xor_val_lo;
        public_key[28 - ((offset/8) + 1)] ^= xor_val_hi;
    }

    memcpy(&curr_addr, &public_key[8], 20);

    do {
      copy_2b_big_endian(&public_key[6], &valid_key_counter);
	    valid_key_counter++;
    } while (!is_valid_pubkey(public_key));

    ESP_LOGI(LOG_TAG, "  pub key to use (%d. try): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", valid_key_counter, public_key[0], public_key[1], public_key[2], public_key[3], public_key[4], public_key[5], public_key[6], public_key[7], public_key[8], public_key[9], public_key[10], public_key[11], public_key[12], public_key[13],public_key[14], public_key[15],public_key[16],public_key[17],public_key[18], public_key[19], public_key[20], public_key[21], public_key[22], public_key[23], public_key[24], public_key[25], public_key[26],  public_key[27]);

    set_addr_from_key(rnd_addr, public_key);
    set_payload_from_key(adv_data, public_key);
}

// No error handling yet
uint8_t* read_line_or_dismiss(int* len) {
    uint8_t *line = (uint8_t *) malloc(BUF_SIZE);
    int size;
    uint8_t *ptr = line;
    while(1) {
        size = uart_read_bytes(UART_PORT_NUM, (unsigned char *)ptr, 1, 20 / portTICK_PERIOD_MS);
        if (size == 1) {
            if (*ptr == '\n') {
                *ptr = 0;
                *len = ptr-line;
                return line;
            }
            ptr++;
        }
        else { free(line); ESP_LOGI(LOG_TAG, "Dismissing line"); return 0; }
    }
}
void reset_advertising() {
    esp_err_t status;
    esp_ble_gap_stop_advertising();
    if ((status = esp_ble_gap_set_rand_addr(rnd_addr)) != ESP_OK) {
        ESP_LOGE(LOG_TAG, "couldn't set random address: %s", esp_err_to_name(status));
        return;
    }
    if ((esp_ble_gap_config_adv_data_raw((uint8_t*)&adv_data, sizeof(adv_data))) != ESP_OK) {
        ESP_LOGE(LOG_TAG, "couldn't configure BLE adv: %s", esp_err_to_name(status));
        return;
    }
}

void send_data_once_blocking(uint8_t* data_to_send, uint32_t len, uint32_t chunk_len, uint32_t msg_id) {
    ESP_LOGI(LOG_TAG, "Data to send (msg_id: %d): %s", msg_id, data_to_send);
    ESP_LOGI(LOG_TAG, "Length %d", len);

    int num_chunks = ((len * 8) / chunk_len);
    ESP_LOGI(LOG_TAG, "Num chunks %d", num_chunks);
    if ((len * 8) % chunk_len) { num_chunks++; }
    
    uint8_t mask = 0xff >> (8 - chunk_len);

    uint8_t* data = data_to_send;
    uint32_t end = len - 1;   

    for (int chunk_i = 0; chunk_i < num_chunks; chunk_i++) {
        uint8_t val = 0;

        uint32_t offset = chunk_i * chunk_len;
        uint32_t remain = offset % 8;

        
        bool overlap = ((chunk_len * (chunk_i + 1)) / 8) != ((chunk_len * chunk_i) / 8);
    
        if (!overlap) {
            val = data_to_send[end - (offset/8)] >> remain;
            val &= mask;
        } else { 
            uint8_t val_hi = data_to_send[end - (offset/8) - 1];
            val_hi = val_hi << (8 - remain);
            val_hi &= mask; 
            uint8_t val_lo = data_to_send[end - (offset/8)];
            val_lo = val_lo >> remain;
            val_lo &= mask;
            val = val_lo ^ val_hi;
        }


        set_addr_and_payload_for_byte(chunk_i, msg_id, val, chunk_len);
        ESP_LOGD(LOG_TAG, "    resetting. Will now use device address: %02x %02x %02x %02x %02x %02x", rnd_addr[0], rnd_addr[1], rnd_addr[2], rnd_addr[3], rnd_addr[4], rnd_addr[5]);
        reset_advertising();
        vTaskDelay(2);    
    }
    esp_ble_gap_stop_advertising();
}

void init_serial() {
    uart_config_t uart_config = {
        .baud_rate = UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    int intr_alloc_flags = 0;

    ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, BUF_SIZE * 2, 0, 0, NULL, intr_alloc_flags));
    ESP_ERROR_CHECK(uart_param_config(UART_PORT_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT_NUM, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE, TEST_RTS, TEST_CTS));
}

static esp_err_t send_post_handler(httpd_req_t *req)
{
    char buf[100];
    uint8_t payload[100];
    int ret, remaining = req->content_len;

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                        MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
        
        ESP_LOGI(TAG, "%d", ret); 
        
        int payload_len = ret - 9;
        memcpy(payload, &buf[7], payload_len); 
        ESP_LOGI(TAG, "%s", payload);
        
        ESP_LOGI(TAG, "Advertising with message ID %d", current_message_id);
        for (int i = 0; i < 50; i++) {
            send_data_once_blocking(payload, payload_len, 4, current_message_id);
        }
    }    
    current_message_id++;
    modem_id++;

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t send = {
    .uri       = "/send",
    .method    = HTTP_POST,
    .handler   = send_post_handler,
    .user_ctx  = NULL
};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &send);
        #if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
        #endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

void app_main(void)
{
    static httpd_handle_t server = NULL;
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    esp_bt_controller_init(&bt_cfg);
    esp_bt_controller_enable(ESP_BT_MODE_BLE);

    esp_bluedroid_init();
    esp_bluedroid_enable();

    esp_err_t status;
    //register the scan callback function to the gap module
    if ((status = esp_ble_gap_register_callback(esp_gap_cb)) != ESP_OK) {
        ESP_LOGE(LOG_TAG, "gap register error: %s", esp_err_to_name(status));
        return;
    }

    ESP_LOGI(TAG, "ESP_WIFI_MODE_STA");
    wifi_init_sta();
 
    ESP_LOGI(LOG_TAG, "Entering serial modem mode");
    init_serial();

    server = start_webserver();

    esp_ble_gap_stop_advertising();
}

