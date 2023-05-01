#include <string.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <driver/spi_master.h>
#include <driver/gpio.h>
#include "esp_log.h"

#include "w25q64.h"

#define TAG "W25Q64"
#define _DEBUG_	0

#define CONFIG_GPIO_RANGE_MAX 33
#define CONFIG_MISO_GPIO 19
#define CONFIG_MOSI_GPIO 23
#define CONFIG_SCLK_GPIO 18
#define CONFIG_CS_GPIO 5
#define CONFIG_SPI2_HOST 1

// SPI Stuff
#if CONFIG_SPI2_HOST
#define HOST_ID SPI2_HOST
#elif CONFIG_SPI3_HOST
#define HOST_ID SPI3_HOST
#endif

//static const int SPI_Command_Mode = 0;
//static const int SPI_Data_Mode = 1;
static const int SPI_Frequency = 1000000;

void W25Q64_dump(char *id, int ret, uint8_t *data, int len)
{
	int i;
	printf("[%s] = %d\n",id, ret);
	for(i=0;i<len;i++) {
		printf("%0x ",data[i]);
		if ( (i % 10) == 9) printf("\n");
	}
	printf("\n");
}


void W25Q64_init(W25Q64_t * dev)
{
  ESP_LOGI(TAG, "MISO_GPIO=%d", CONFIG_MISO_GPIO);
  ESP_LOGI(TAG, "MOSI_GPIO=%d", CONFIG_MOSI_GPIO);
  ESP_LOGI(TAG, "SCLK_GPIO=%d", CONFIG_SCLK_GPIO);
  ESP_LOGI(TAG, "CS_GPIO=%d", CONFIG_CS_GPIO);

	esp_err_t ret;

	//gpio_pad_select_gpio( CONFIG_CS_GPIO );
	gpio_reset_pin( CONFIG_CS_GPIO );
	gpio_set_direction( CONFIG_CS_GPIO, GPIO_MODE_OUTPUT );
	gpio_set_level( CONFIG_CS_GPIO, 0 );

	spi_bus_config_t spi_bus_config = {
		.sclk_io_num = CONFIG_SCLK_GPIO,
		.mosi_io_num = CONFIG_MOSI_GPIO,
		.miso_io_num = CONFIG_MISO_GPIO,
		.quadwp_io_num = -1,
		.quadhd_io_num = -1
	};

	ret = spi_bus_initialize( HOST_ID, &spi_bus_config, SPI_DMA_CH_AUTO );
	if(_DEBUG_)ESP_LOGI(TAG, "spi_bus_initialize=%d",ret);
	assert(ret==ESP_OK);

	spi_device_interface_config_t devcfg;
	memset( &devcfg, 0, sizeof( spi_device_interface_config_t ) );
	devcfg.clock_speed_hz = SPI_Frequency;
	devcfg.spics_io_num = CONFIG_CS_GPIO;
	devcfg.queue_size = 7;
	devcfg.mode = 0;

	spi_device_handle_t handle;
	ret = spi_bus_add_device( HOST_ID, &devcfg, &handle);
	if(_DEBUG_)ESP_LOGI(TAG, "spi_bus_add_device=%d",ret);
	assert(ret==ESP_OK);
	dev->_SPIHandle = handle;
	dev->_4bmode = false;
#if CONFIG_4B_MODE
	ESP_LOGW(TAG, "4-Byte Address Mode");
	dev->_4bmode = true;
#endif
}

//
// Get status register 1
// reg1(out):Value of status register 1
//
esp_err_t W25Q64_readStatusReg1(W25Q64_t * dev, uint8_t * reg1)
{
	spi_transaction_t SPITransaction;
	uint8_t data[2];
	data[0] = CMD_READ_STATUS_R1;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 2 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if(_DEBUG_)ESP_LOGI(TAG, "W25Q64_readStatusReg1=%x",data[1]);
	*reg1 = data[1];
	return ret;
}

//
// Get status register 2
// reg2(out):Value of status register 2
//
esp_err_t W25Q64_readStatusReg2(W25Q64_t * dev, uint8_t * reg2)
{
	spi_transaction_t SPITransaction;
	uint8_t data[2];
	data[0] = CMD_READ_STATUS_R2;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 2 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if(_DEBUG_)ESP_LOGI(TAG, "W25Q64_readStatusReg2=%x",data[1]);
	*reg2 = data[1];
	return ret;
}

//
// Get Unique ID
// id(out):Unique ID 8 bytes	
//
esp_err_t W25Q64_readUniqieID(W25Q64_t * dev, uint8_t * id)
{
	spi_transaction_t SPITransaction;
	uint8_t data[13];
	data[0] = CMD_READ_UNIQUE_ID;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 13 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if(_DEBUG_)W25Q64_dump("readUniqieID", ret, data, 13);
	memcpy(id, &data[5], 8);
	return ret ;
}

//
// Get JEDEC ID(Manufacture, Memory Type,Capacity)
// d(out):Stores 3 bytes of Manufacture, Memory Type, Capacity
//
esp_err_t W25Q64_readManufacturer(W25Q64_t * dev, uint8_t * id)
{
	spi_transaction_t SPITransaction;
	uint8_t data[4];
	data[0] = CMD_JEDEC_ID;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 4 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if(_DEBUG_)W25Q64_dump("readManufacturer", ret, data, 4);
	memcpy(id, &data[1], 3);
	return ret ;
}

//
// Check during processing such as writing
// Return value: true:processing false:idle
//
bool W25Q64_IsBusy(W25Q64_t * dev)
{
	spi_transaction_t SPITransaction;
	uint8_t data[2];
	data[0] = CMD_READ_STATUS_R1;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 2 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if (ret != ESP_OK) return false;
	if( (data[1] & SR1_BUSY_MASK) != 0) return true;
	return false;
}


//
// Power down 
//
esp_err_t W25Q64_powerDown(W25Q64_t * dev)
{
	spi_transaction_t SPITransaction;
	uint8_t data[1];
	data[0] = CMD_POWER_DOWN;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 1 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	return ret;
}


//
// Write permission setting
//
esp_err_t W25Q64_WriteEnable(W25Q64_t * dev)
{
	spi_transaction_t SPITransaction;
	uint8_t data[1];
	data[0] = CMD_WRITE_ENABLE;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 1 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	return ret;
}


//
// Write-protected setting
//
esp_err_t W25Q64_WriteDisable(W25Q64_t * dev)
{
	spi_transaction_t SPITransaction;
	uint8_t data[1];
	data[0] = CMD_WRITE_DISABLE;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 1 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	return ret;
}

//
// Read data
// addr(in):Read start address
//          3 Bytes Address Mode : 24 Bits 0x000000 - 0xFFFFFF
//          4 Bytes Address Mode : 32 Bits 0x00000000 - 0xFFFFFFFF
// n(in):Number of read data
//
uint16_t W25Q64_read(W25Q64_t * dev, uint32_t addr, uint8_t *buf, uint16_t n)
{ 
	spi_transaction_t SPITransaction;
	uint8_t *data;
	data = (uint8_t *)malloc(n+5);
	size_t offset;
	if (dev->_4bmode) {
		data[0] = CMD_READ_DATA4B;
		data[1] = (addr>>24) & 0xFF; // A31-A24
		data[2] = (addr>>16) & 0xFF; // A23-A16
		data[3] = (addr>>8) & 0xFF; // A15-A08
		data[4] = addr & 0xFF; // A07-A00
		offset = 5;
	} else {
		data[0] = CMD_READ_DATA;
		data[1] = (addr>>16) & 0xFF; // A23-A16
		data[2] = (addr>>8) & 0xFF; // A15-A08
		data[3] = addr & 0xFF; // A07-A00
		offset = 4;
	}
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = (n+offset) * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	memcpy(buf, &data[offset], n);
	free(data);
	if (ret != ESP_OK) return 0;
	return n;
}

//
// Fast read data
// addr(in):Read start address
//          3 Bytes Address Mode : 24 Bits 0x000000 - 0xFFFFFF
//          4 Bytes Address Mode : 32 Bits 0x00000000 - 0xFFFFFFFF
// n(in):Number of read data
//
uint16_t W25Q64_fastread(W25Q64_t * dev, uint32_t addr, uint8_t *buf, uint16_t n)
{
	spi_transaction_t SPITransaction;
	uint8_t *data;
	data = (uint8_t *)malloc(n+6);
	size_t offset;
	if (dev->_4bmode) {
		data[0] = CMD_FAST_READ4B;
		data[1] = (addr>>24) & 0xFF; // A31-A24
		data[2] = (addr>>16) & 0xFF; // A23-A16
		data[3] = (addr>>8) & 0xFF; // A15-A08
		data[4] = addr & 0xFF; // A07-A00
		data[5] = 0; // Dummy
		offset = 6;
	} else {
		data[0] = CMD_FAST_READ;
		data[1] = (addr>>16) & 0xFF; // A23-A16
		data[2] = (addr>>8) & 0xFF; // A15-A08
		data[3] = addr & 0xFF; // A07-A00
		data[4] = 0; // Dummy
		offset = 5;
	}
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = (n+offset) * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	esp_err_t ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	memcpy(buf, &data[offset], n);
	free(data);
	if (ret != ESP_OK) return 0;
	return n;
}


//
// Erasing data in 4kb space units
// sect_no(in):Sector number(0 - 2048)
// flgwait(in):true:Wait for complete / false:No wait for complete
// Return value: true:success false:fail
//
// Note:
// The data sheet states that erasing usually takes 30ms and up to 400ms.
// The upper 11 bits of the 23 bits of the address correspond to the sector number.
// The lower 12 bits are the intra-sectoral address.
//
// 補足:
// データシートでは消去に通常 30ms 、最大400msかかると記載されている
// アドレス23ビットのうち上位 11ビットがセクタ番号の相当する。
// 下位12ビットはセクタ内アドレスとなる。
//
bool W25Q64_eraseSector(W25Q64_t * dev, uint16_t sect_no, bool flgwait)
{
	spi_transaction_t SPITransaction;
	uint8_t data[4];
	uint32_t addr = sect_no;
	addr<<=12;

	// Write permission setting
	esp_err_t ret;
	ret = W25Q64_WriteEnable(dev);
	if (ret != ESP_OK) return false;

	data[0] = CMD_SECTOR_ERASE;
	data[1] = (addr>>16) & 0xff;
	data[2] = (addr>>8) & 0xff;
	data[3] = addr & 0xff;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 4 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if (ret != ESP_OK) return false;

	// Busy check
	while( W25Q64_IsBusy(dev) & flgwait) {
		vTaskDelay(1);
	}
	return true;
}

//
// Erasing data in 64kb space units
// blk_no(in):Block number(0 - 127)
// flgwait(in):true:Wait for complete / false:No wait for complete
// Return value: true:success false:fail
//
// Note:
// The data sheet states that erasing usually takes 150ms and up to 1000ms.
// The upper 7 bits of the 23 bits of the address correspond to the block.
// The lower 16 bits are the address in the block.
//
// 補足:
// データシートでは消去に通常 150ms 、最大1000msかかると記載されている
// アドレス23ビットのうち上位 7ビットがブロックの相当する。下位16ビットはブロック内アドレスとなる。
//
bool W25Q64_erase64Block(W25Q64_t * dev, uint16_t blk_no, bool flgwait)
{
	spi_transaction_t SPITransaction;
	uint8_t data[4];
	uint32_t addr = blk_no;
	addr<<=16;

	// Write permission setting
	esp_err_t ret;
	ret = W25Q64_WriteEnable(dev);
	if (ret != ESP_OK) return false;

	data[0] = CMD_BLOCK_ERASE64KB;
	data[1] = (addr>>16) & 0xff;
	data[2] = (addr>>8) & 0xff;
	data[3] = addr & 0xff;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 4 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if (ret != ESP_OK) return false;

	// Busy check
	while( W25Q64_IsBusy(dev) & flgwait) {
		vTaskDelay(1);
	}
	return true;
}

//
// Erasing data in 32kb space units
// blk_no(in):Block number(0 - 255)
// flgwait(in):true:Wait for complete / false:No wait for complete
// Return value: true:success false:fail
//
// Note:
// The data sheet states that erasing usually takes 120ms and up to 800ms.
// The upper 8 bits of the 23 bits of the address correspond to the block.
// The lower 15 bits are the in-block address.
//
// 補足:
// データシートでは消去に通常 120ms 、最大800msかかると記載されている
// アドレス23ビットのうち上位 8ビットがブロックの相当する。下位15ビットはブロック内アドレスとなる。
//
bool W25Q64_erase32Block(W25Q64_t * dev, uint16_t blk_no, bool flgwait)
{
	spi_transaction_t SPITransaction;
	uint8_t data[4];
	uint32_t addr = blk_no;
	addr<<=15;

	// Write permission setting
	esp_err_t ret;
	ret = W25Q64_WriteEnable(dev);
	if (ret != ESP_OK) return false;

	data[0] = CMD_BLOCK_ERASE32KB;
	data[1] = (addr>>16) & 0xff;
	data[2] = (addr>>8) & 0xff;
	data[3] = addr & 0xff;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 4 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if (ret != ESP_OK) return false;

	// Busy check
	while( W25Q64_IsBusy(dev) & flgwait) {
		vTaskDelay(1);
	}
	return true;
}


//
// Erase all data
// flgwait(in):true:Wait for complete / false:No wait for complete
// Return value: true:success false:fail
//
// Note:
// The data sheet states that erasing usually takes 15s and up to 30s.
//
// 補足:
// データシートでは消去に通常 15s 、最大30sかかると記載されている
//
bool W25Q64_eraseAll(W25Q64_t * dev, bool flgwait)
{
	spi_transaction_t SPITransaction;
	uint8_t data[1];

	// Write permission setting
	esp_err_t ret;
	ret = W25Q64_WriteEnable(dev);
	if (ret != ESP_OK) return false;

	data[0] = CMD_CHIP_ERASE;
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = 1 * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	assert(ret==ESP_OK);
	if (ret != ESP_OK) return false;

	// Busy check
	while( W25Q64_IsBusy(dev) & flgwait) {
		vTaskDelay(1);
	}
	return true;
}

//
// Page write
// sect_no(in):Sector number(0x00 - 0x7FF) 
// inaddr(in):In-sector address(0x00-0xFFF)
// data(in):Write data
// n(in):Number of bytes to write(0～256)
//
int16_t W25Q64_pageWrite(W25Q64_t * dev, uint16_t sect_no, uint16_t inaddr, uint8_t* buf, int16_t n)
{
	if (n > 256) return 0;
	spi_transaction_t SPITransaction;
	uint8_t *data;

	uint32_t addr = sect_no;
	addr<<=12;
	addr += inaddr;

	// Write permission setting
	esp_err_t ret;
	ret = W25Q64_WriteEnable(dev);
	if (ret != ESP_OK) return 0;

	// Busy check
	if (W25Q64_IsBusy(dev)) return 0;  

	data = (unsigned char*)malloc(n+4);
	data[0] = CMD_PAGE_PROGRAM;
	data[1] = (addr>>16) & 0xff;
	data[2] = (addr>>8) & 0xff;
	data[3] = addr & 0xFF;
	memcpy( &data[4], buf, n );
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = (n+4) * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	free(data);
	assert(ret==ESP_OK);
	if (ret != ESP_OK) return 0;

	// Busy check
	while( W25Q64_IsBusy(dev) ) {
		vTaskDelay(1);
	}
	return n;
}

// init ESP32 logging
// sector/inaddr number 0 is reserved specifically for the last written address
// init sect_no = 1 (2 bytes)
// init inaddr = 0 (2 bytes)
// record modemID (4 bytes)
int16_t W25Q32_initLogging(W25Q64_t * dev, uint8_t * modemID){
	uint16_t sect_no = 1;
	uint16_t inaddr = 0;
	uint16_t n = 8; //data is going to be 8 bytes long

	uint8_t data[8];
	uint8_t buf[2];

	memset(buf, 0, 2);
	memcpy(buf, &sect_no, 2);

	data[0] = buf[1];
	data[1] = buf[0];

	memset(buf, 0, 2);
	memcpy(buf, &inaddr, 2);

	data[2] = buf[1];
	data[3] = buf[0];

	data[4] = modemID[3];
	data[5] = modemID[2];
	data[6] = modemID[1];
	data[7] = modemID[0];


	int16_t write_result = W25Q64_pageWrite(dev, 0, 0, data, n);
	return write_result; //if 0 then error?
}

// "erase" is an 8-byte array that needs to erase the first 8 bytes (make all f's) in order to write to it
int16_t W25Q32_writeNextAddr(W25Q64_t * dev, uint16_t sect_no, uint16_t inaddr, uint32_t modemID, bool curr_next){
	// ESP_LOGI(TAG, "Next sect_no: %d", sect_no);
	// ESP_LOGI(TAG, "Next inaddr: %d", inaddr);
	
	uint8_t data[8];
	uint8_t buf[4];

	memset(buf, 0, 2);
	memcpy(buf, &sect_no, 2);

	data[0] = buf[1];
	data[1] = buf[0];

	memset(buf, 0, 2);
	memcpy(buf, &inaddr, 2);

	data[2] = buf[1];
	data[3] = buf[0];

	memset(buf, 0, 2);
	memcpy(buf, &modemID, 4);

	data[4] = buf[3];
	data[5] = buf[2];
	data[6] = buf[1];
	data[7] = buf[0];

	// if true, write next address
	// if false, write curr address
	int write_result;
	if(curr_next == true){
		write_result = W25Q64_pageWrite(dev, 0, 0, data, 8);
	}
	else if(curr_next == false){
		write_result = W25Q64_pageWrite(dev, 0, 16, data, 8);
	}
	
	return write_result;

}

// read last address written to
// takes in the buffer and the references to sect_no, inaddr
void W25Q32_readLast(uint8_t* buf, uint16_t *sect_no, uint16_t *inaddr, uint32_t *read_modemID){
	*sect_no = buf[0];
	*sect_no <<= 8;
	*sect_no += buf[1];

	*inaddr = buf[2];
	*inaddr <<= 8;
	*inaddr += buf[3];

	*read_modemID = buf[4];
	*read_modemID <<= 8;
	*read_modemID += buf[5];
	*read_modemID <<= 8;
	*read_modemID += buf[6];
	*read_modemID <<= 8;
	*read_modemID += buf[7];
}

void TagAlongPayload(uint8_t * data, int16_t empty_0, uint16_t count, uint32_t modem, int empty_1, uint32_t time){
	uint8_t buf[4];

	memset(buf, 0, 2);
	memcpy(buf, &empty_0, 2);

	data[0] = buf[1];
	data[1] = buf[0];

	memset(buf, 0, 2);
	memcpy(buf, &count, 2);
	data[2] = buf[1];
	data[3] = buf[0];

	memset(buf, 0, 2);
	memcpy(buf, &modem, 4);

	data[4] = buf[3];
	data[5] = buf[2];
	data[6] = buf[1];
	data[7] = buf[0];

	memset(buf, 0, 4);
	memcpy(buf, &empty_1, 4);

	data[8] = buf[3];
	data[9] = buf[2];
	data[10] = buf[1];
	data[11] = buf[0];

	memset(buf, 0, 4);
	memcpy(buf, &time, 4);

	data[12] = buf[3];
	data[13] = buf[2];
	data[14] = buf[1];
	data[15] = buf[0];
}

void W25Q32_readData(W25Q64_t * dev, uint32_t addr, uint8_t *data_buf, uint16_t n, uint16_t *count, uint32_t *modem, uint32_t *time){
	memset(data_buf, 0, n);
	W25Q64_read(dev, addr, data_buf, n);

	// empty_0
	// *data_buf[0];
	// *data_buf[1];

	// count
	*count = data_buf[2];
	*count <<= 8;
	*count += data_buf[3];

	// modem_id
	*modem = data_buf[4];
	*modem <<= 8;
	*modem += data_buf[5];
	*modem <<= 8;
	*modem += data_buf[6];
	*modem <<= 8;
	*modem += data_buf[7];


	// empty_1
	// *data_buf[8];
	// *data_buf[9];
	// *data_buf[10];
	// *data_buf[11];

	// time
	*time = data_buf[12];
	*time <<= 8;
	*time += data_buf[13];
	*time <<= 8;
	*time += data_buf[14];
	*time <<= 8;
	*time += data_buf[15];

	printf("%u,%x,%u\n",*count,*modem,*time);
}

//
// Page write --> double check address range
// sect_no(in):Sector number(0x00 - 0x3FF) 
// inaddr(in):In-sector address(0x00-0xFFF)
// data(in):Write data
// n(in):Number of bytes to write(0～256)
//
int16_t W25Q32_writePayload(W25Q64_t *dev, uint8_t *buf, int16_t n)
{
	uint16_t sect_no, inaddr, last_sect_no, last_inaddr;
	uint32_t modemID;
	uint8_t addr_buf[8];

	memset(addr_buf, 0, 8);
	W25Q64_read(dev, 0, addr_buf, 8);
	W25Q32_readLast(addr_buf, &sect_no, &inaddr, &modemID); // get the address to write at

	printf("Section num: %u\n", sect_no);
	printf("inaddr: %u\n", inaddr);
	printf("ModemID: %x\n", modemID);
	printf("\n");

	// storing the current sector number and inaddr
	last_sect_no = sect_no;
	last_inaddr = inaddr;

	if (n > 256) return 0;
	if (sect_no == 1047) return 0; // DOUBLE CHECK THIS

	// at this point, sect_no and inaddr should all be correct to write at

	spi_transaction_t SPITransaction;
	uint8_t *data;

	// inaddr is 12 bytes max, so shift 12 bytes
	uint32_t addr = sect_no;
	addr<<=12;
	addr += inaddr;

	// checking if this is going beyond the inaddr address
	inaddr += n;
	// inaddr overflow; increment sect_no
	if (inaddr >= 4095){
		sect_no++;
		inaddr = 0;
	}

	W25Q64_eraseSector(dev, 0, true);

	// write the last written address here at sect_no 0, inaddr 16
	int16_t write_result = W25Q32_writeNextAddr(dev, last_sect_no, last_inaddr, modemID, false);
	if(write_result != 8){
		printf("writeNextAddr failed!\n");
	}

	//write new addr
	write_result = W25Q32_writeNextAddr(dev, sect_no, inaddr, modemID, true);
	if(write_result != 8){
		printf("writeNextAddr failed!\n");
	}

	// Write permission setting
	esp_err_t ret;
	ret = W25Q64_WriteEnable(dev);
	if (ret != ESP_OK) return 0;

	// Busy check
	if (W25Q64_IsBusy(dev)) return 0;  

	data = (unsigned char*)malloc(n+4);
	data[0] = CMD_PAGE_PROGRAM;
	data[1] = (addr>>16) & 0xff;
	data[2] = (addr>>8) & 0xff;
	data[3] = addr & 0xFF;
	memcpy( &data[4], buf, n );
	memset( &SPITransaction, 0, sizeof( spi_transaction_t ) );
	SPITransaction.length = (n+4) * 8;
	SPITransaction.tx_buffer = data;
	SPITransaction.rx_buffer = data;
	ret = spi_device_transmit( dev->_SPIHandle, &SPITransaction );
	free(data);
	assert(ret==ESP_OK);
	if (ret != ESP_OK) return 0;

	// Busy check
	while( W25Q64_IsBusy(dev) ) {
		vTaskDelay(1);
	}
	return n;
}