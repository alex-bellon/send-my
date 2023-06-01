#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>

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
#include "freertos/timers.h"

#include "driver/uart.h"
#include "driver/gpio.h"
#include "sdkconfig.h"

#include "uECC.h"
#include "w25q64.h"

#define CHECK_BIT(var,pos) ((var) & (1<<(7-pos)))

#define TEST_RTS (18)
#define TEST_CTS (18)

#define UART_PORT_NUM      (0)
#define UART_BAUD_RATE     (115200)
#define TASK_STACK_SIZE    (2048)

#define BUF_SIZE (1024)

// #define TAG "W25Q64"
#define PAYLOADSIZE 16
#define READNUMBYTES 256

// Set custom modem id before flashing:
#define TIMEINTERVAL 15000
static const uint32_t modem_id = 0xd3ad1003;

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

uint8_t data[2];

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
    ESP_LOGI(LOG_TAG, "  PAYLOAD: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11], payload[12], payload[13], payload[14], payload[15], payload[16], payload[17], payload[18], payload[19], payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27], payload[28], payload[29], payload[30]);
}

void copy_4b_big_endian(uint8_t *dst, uint8_t *src) {
    dst[0] = src[3]; dst[1] = src[2]; dst[2] = src[1]; dst[3] = src[0];
}

void copy_2b_big_endian(uint8_t *dst, uint8_t *src) {
    dst[0] = src[1]; dst[1] = src[0];
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

 
void send_data_once_blocking(uint8_t* data_to_send, uint32_t len) {

 	uint16_t valid_key_counter = 0;
    static uint8_t public_key[28] = {0};
    public_key[0] = 0xBA; // magic value
    public_key[1] = 0xBE;
    copy_4b_big_endian(&public_key[2], &modem_id);
    public_key[6] = 0x00;
    public_key[7] = 0x00;
    
    for (int i = 0; i < len; i++) {
        public_key[27 - i] = data_to_send[i];
    } 

    do {
      copy_2b_big_endian(&public_key[6], &valid_key_counter);
	    valid_key_counter++;
    } while (!is_valid_pubkey(public_key));


    set_addr_from_key(rnd_addr, public_key);
    set_payload_from_key(adv_data, public_key);

    ESP_LOGI(LOG_TAG, "  pub key to use (%d. try): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", valid_key_counter, public_key[0], public_key[1], public_key[2], public_key[3], public_key[4], public_key[5], public_key[6], public_key[7], public_key[8], public_key[9], public_key[10], public_key[11], public_key[12], public_key[13],public_key[14], public_key[15],public_key[16],public_key[17],public_key[18], public_key[19], public_key[20], public_key[21], public_key[22], public_key[23], public_key[24], public_key[25], public_key[26],  public_key[27]);
    ESP_LOGI(LOG_TAG, " ADDR: %02x %02x %02x %02x %02x %02x", rnd_addr[0], rnd_addr[1], rnd_addr[2], rnd_addr[3], rnd_addr[4], rnd_addr[5]);
    vTaskDelay(2);

    reset_advertising();
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

//
// Data dump list
// dt(in):Data to dump
// n(in) :Number of bytes of data
//
// for debugging flash mem
//
void dump(uint8_t *dt, int n)
{
	uint16_t clm = 0;
	uint8_t data;
	uint8_t sum;
	uint8_t vsum[16];
	uint8_t total =0;
	uint32_t saddr =0;
	uint32_t eaddr =n-1;

	printf("----------------------------------------------------------\n");
	uint16_t i;
	for (i=0;i<16;i++) vsum[i]=0;  
	uint32_t addr;
	for (addr = saddr; addr <= eaddr; addr++) {
		data = dt[addr];
		if (clm == 0) {
			sum =0;
			printf("%05"PRIx32": ",addr);
		}

		sum+=data;
		vsum[addr % 16]+=data;

		printf("%02x ",data);
		clm++;
		if (clm == 16) {
			printf("|%02x \n",sum);
			clm = 0;
		}
	}
	printf("----------------------------------------------------------\n");
	printf("       ");
	for (i=0; i<16;i++) {
		total+=vsum[i];
		printf("%02x ",vsum[i]);
	}
	printf("|%02x \n\n",total);
}


void app_main(void)
{
    W25Q64_t dev;
	W25Q64_init(&dev);

	// Get Status Register1
	uint8_t reg1;
	esp_err_t ret;
	ret = W25Q64_readStatusReg1(&dev, &reg1);
	if (ret != ESP_OK) {
		ESP_LOGE(LOG_TAG, "readStatusReg1 fail %d",ret);
		while(1) { vTaskDelay(1); }
	} 
	ESP_LOGI(LOG_TAG, "readStatusReg1 : %x", reg1);
	
	// Get Status Register2
	uint8_t reg2;
	ret = W25Q64_readStatusReg2(&dev, &reg2);
	if (ret != ESP_OK) {
		ESP_LOGE(LOG_TAG, "readStatusReg2 fail %d",ret);
		while(1) { vTaskDelay(1); }
	}
	ESP_LOGI(LOG_TAG, "readStatusReg2 : %x", reg2);

	// Get Unique ID
	uint8_t uid[8];
	ret = W25Q64_readUniqieID(&dev, uid);
	if (ret != ESP_OK) {
		ESP_LOGE(LOG_TAG, "readUniqieID fail %d",ret);
		while(1) { vTaskDelay(1); }
	}
	ESP_LOGI(LOG_TAG, "readUniqieID : %x-%x-%x-%x-%x-%x-%x-%x",
		 uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7]);

	// Get JEDEC ID
	uint8_t jid[3];
	ret = W25Q64_readManufacturer(&dev, jid);
	if (ret != ESP_OK) {
		ESP_LOGE(LOG_TAG, "readManufacturer fail %d",ret);
		while(1) { vTaskDelay(1); }
	}
	ESP_LOGI(LOG_TAG, "readManufacturer : %x-%x-%x",
		 jid[0], jid[1], jid[2]);

    uint8_t payload_data[PAYLOADSIZE];

    uint16_t sect_no, inaddr, last_sect_no, last_inaddr;
    uint32_t modemID;
    uint8_t addr_buf[8];

    uint16_t count = 0;

    // checking if memory initialized properly
    memset(addr_buf, 0, 8);
    W25Q64_read(&dev, 0, addr_buf, 8);
    W25Q32_readLast(addr_buf, &sect_no, &inaddr, &modemID); // get the address to write at

    printf("sect_no, inaddr, and modemID\n");
    printf("sect_no: %d\n", sect_no);
    printf("inaddr: %d\n", inaddr);
    printf("modemID: %x\n", modemID);

    uint32_t last_addr, last_modem, last_time;
    uint16_t last_count;

    // read last address at sect_0, inaddr 1; if all f's, then that means first init
    last_addr = 0; //sect_no 0
    last_addr<<=12;
    last_addr += 16; //inaddr 16; go to next 16 bytes

    memset(addr_buf, 0, 8);
    W25Q64_read(&dev, last_addr, addr_buf, 8);
    W25Q32_readLast(addr_buf, &last_sect_no, &last_inaddr, &modemID);

    // last_sect_no and last_inaddr will be all f's if only initLogging happened
    // get the last count here
    printf("last_sect_no: %x\n", last_sect_no);
    printf("last_inaddr: %x\n", last_inaddr);
    if(last_sect_no != 0xffff && last_inaddr != 0xffff){
        // reusing last_addr variable to get address of data that was last written to
        last_addr = last_sect_no;
        last_addr<<=12;
        last_addr += last_inaddr;
        memset(payload_data, 0, PAYLOADSIZE);
        W25Q32_readData(&dev, last_addr, payload_data, PAYLOADSIZE, &last_count, &last_modem, &last_time);
        count = last_count + 1;
    }

    // get next address to write at!!
    memset(addr_buf, 0, 8);
    W25Q64_read(&dev, 0, addr_buf, 8);
    W25Q32_readLast(addr_buf, &sect_no, &inaddr, &modemID); // get the address to write at

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

    uint32_t current_message_id = 0;
   
    // ESP_LOGI(LOG_TAG, "Entering serial modem mode");
    // init_serial();

    union {
        uint8_t arr[2];
        uint16_t val;
    } counter;
    counter.val = count;
    
    uint8_t rbuf[READNUMBYTES];

    int16_t write_result;
    int len;
    uint32_t time_past;

    uint32_t unix_time = (uint32_t)time(NULL);
    printf("Unix time: %u\n", unix_time);


    // for reading the first sector if only init (ONLY FOR DEBUGGING)
    uint32_t addr = 1;
	addr<<=12;
	addr += 0;
    while (1) {

        memset(payload_data, 0, PAYLOADSIZE);
        time_past = xTaskGetTickCount();
        TagAlongPayload(payload_data, 0, counter.val, modem_id, 0, time_past);
        write_result = W25Q32_writePayload(&dev, payload_data, PAYLOADSIZE);

        // get next address to write at; just for debugging
        memset(addr_buf, 0, 8);
        W25Q64_read(&dev, 0, addr_buf, 8);
        W25Q32_readLast(addr_buf, &sect_no, &inaddr, &modemID); // get the address to write at

        ESP_LOGI(LOG_TAG, "sect_no: %u", sect_no);
        ESP_LOGI(LOG_TAG, "inaddr: %u", inaddr);
        ESP_LOGI(LOG_TAG, "modemID: %u", modemID);
        ESP_LOGI(LOG_TAG, "count: %d", counter.val);

        send_data_once_blocking(counter.arr, sizeof(counter.arr));
        vTaskDelay(TIMEINTERVAL);
        // vTaskDelay(60000);

        counter.val++;
       
/* 
        // debugging!!
        memset(rbuf, 0, READNUMBYTES);
        printf("fast read\n");
        printf("fast read\n");
        printf("fast read\n");
        len =  W25Q64_fastread(&dev, addr, rbuf, READNUMBYTES);
        if (len != READNUMBYTES) {
            ESP_LOGE("W25Q32", "fastread fail");
            while(1) { vTaskDelay(1); }
        }
        ESP_LOGI("W25Q32", "Fast Read Data: len=%d", len);
        dump(rbuf, READNUMBYTES);
        // end debugging
*/
    }
    esp_ble_gap_stop_advertising();
}

