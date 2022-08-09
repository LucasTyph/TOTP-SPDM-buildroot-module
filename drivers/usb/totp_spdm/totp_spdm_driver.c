#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/completion.h>

// SPDM includes
#include "spdm_auth.c"

// TOTP include
#include "TOTP.h"

// Certificates include
#include "certs.h"

#define USB_VENDOR_ID 0x0666			// Vendor ID of the SPDM/TOTP device
#define USB_PRODUCT_ID 0x0666			// Product ID of the SPDM/TOTP device
#define MAX_TRIES 2						// Max amount of tries to find SPDM device
#define TIMEOUT_MS 5000					// Wait time in ms to find SPDM device
#define VERIFICATION_PERIOD_MS 40000	// Wait time in ms to do SPDM/TOTP checks
// #define BUFFER_SIZE 64
#define TOTP_TIMESTEP 60				// Timestep for TOTP checks
#define TOTP_HEX_SIZE 6					// TOTP header size in bytes
#define LEN_HEX_SIZE 4					// SPDM length header size in byes
#define SPDM_RECEIVE_OFFSET 10			// TOTP_HEX_SIZE + LEN_HEX_SIZE
#define TOTP_CHALLENGE_ATTEMPTS 3		// Max amount of tries to match TOTP

// Work queue handling function definition
static void totp_spdm_work_handler(struct work_struct *w);

// Pointer necessary to work queues
static struct workqueue_struct *wq = 0;

// Definition of the handler attached to totp_spdm_work work queue
static DECLARE_WORK(totp_spdm_work, totp_spdm_work_handler);

static void print_usb_interface_descriptor (const struct usb_interface_descriptor i) {
	pr_info("USB_INTERFACE_DESCRIPTOR:\n");
	pr_info("-----------------------------\n");
	pr_info("bLength: 0x%x\n", i.bLength);
	pr_info("bDescriptorType: 0x%x\n", i.bDescriptorType);
	pr_info("bInterfaceNumber: 0x%x\n", i.bInterfaceNumber);
	pr_info("bAlternateSetting: 0x%x\n", i.bAlternateSetting);
	pr_info("bNumEndpoints: 0x%x\n", i.bNumEndpoints);
	pr_info("bInterfaceClass: 0x%x\n", i.bInterfaceClass);
	pr_info("bInterfaceSubClass: 0x%x\n", i.bInterfaceSubClass);
	pr_info("bInterfaceProtocol: 0x%x\n", i.bInterfaceProtocol);
	pr_info("iInterface: 0x%x\n", i.iInterface);
	pr_info("\n");
}
 
static void print_usb_endpoint_descriptor (const struct usb_endpoint_descriptor e) {
	pr_info("USB_ENDPOINT_DESCRIPTOR:\n");
	pr_info("------------------------\n");
	pr_info("bLength: 0x%x\n", e.bLength);
	pr_info("bDescriptorType: 0x%x\n", e.bDescriptorType);
	pr_info("bEndPointAddress: 0x%x\n", e.bEndpointAddress);
	pr_info("bmAttributes: 0x%x\n", e.bmAttributes);
	pr_info("wMaxPacketSize: 0x%x\n", e.wMaxPacketSize);
	pr_info("bInterval: 0x%x\n", e.bInterval);
	pr_info("\n");
}

// Main class struct
struct totp_spdm_usb {
	unsigned int endpoints_count;	// number of available endpoints
	struct urb *out_urb;			// URB for outgoing transfers
	struct urb *in_urb;				// 
	uint8_t port_number;
	struct usb_device *dev;
	uint8_t in_endpoint_addr;
	uint8_t out_endpoint_addr;

	// SPDM variables
	void* spdm_context;
	return_status spdm_status;
	void* response_data;
	size_t response_size;
	struct completion spdm_response_done;
	struct completion spdm_request_sent;
	uint32_t session_id;
} *totp_spdm_usb_struct;

/*
* Shut down the system in case something goes wrong.
*/
static void fail(void){
		char * shutdown_argv[] = { "/sbin/poweroff", NULL };

		pr_alert("Shutting down system in 5...\n");
		msleep(5000);
		// uncommment for shutting down the system
		call_usermodehelper(shutdown_argv[0], shutdown_argv, NULL, UMH_NO_WAIT);
		// kernel_power_off();
		kernel_halt();
}

/*
* In case of error with SPDM-related funcions, free SPDM context
*/
static void err_free_spdm(void){
	kfree(totp_spdm_usb_struct->spdm_context);
}

/*
* Hex to decimal conversion
* Source: https://stackoverflow.com/a/11068850
*/
static const long hextable[] = { 
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1, 0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,-1,10,11,12,13,14,15,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/** 
 * @brief convert a hexidecimal string to a signed long
 * will not produce or process negative numbers except 
 * to signal error.
 * 
 * @param hex without decoration, case insensitive. 
 * 
 * @return -1 on error, or result (max (sizeof(long)*8)-1 bits)
 */
static long hexdec(unsigned const char *hex) {
	long ret = 0; 
	while (*hex && ret >= 0) {
		ret = (ret << 4) | hextable[*hex++];
	}
	return ret; 
}

/*
* Fetches SPDM response size from specific byte from the response itself
*/
static size_t get_size_from_response(void) {
	uint8_t size_hex[LEN_HEX_SIZE];
	unsigned long size_dec;

	memcpy(size_hex, totp_spdm_usb_struct->response_data, LEN_HEX_SIZE*sizeof(uint8_t));
	size_dec = hexdec(size_hex);
	pr_info ("size_dec: %lu", size_dec);
	return size_dec;
}

/*
* Finds whether value val is contained in array arr.
*/
static int valueinarray(uint32_t val, uint32_t arr[], uint32_t arr_size) {
	uint8_t i;
	for(i = 0; i < arr_size; i++){
		if(arr[i] == val)
			return 1;
	}
	return 0;
}

/*
* Creates an array of TOTP values and saves them into an array
*/
static void get_totp(uint32_t* code_array){
	int i, diff;
	struct timespec *ts;
	uint32_t steps;

	// set key for now
	// TODO: some different method of getting the key
	uint8_t hmacKey[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};

	TOTP(hmacKey, 10, TOTP_TIMESTEP); // key, key size, timestep in s

	// Get current time
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);

	// Get number of steps
	steps = ts->tv_sec / TOTP_TIMESTEP;

	// This weird for loop creates TOTP_CHALLENGE_ATTEMPTS TOTPs
	// It should create half of TOTP_CHALLENGE_ATTEMPTS, rounded down, 
	// attempts before and after the specific amount of timesteps
	// as such, TOTP_CHALLENGE_ATTEMPTS = 3 tries from steps-1 to steps+1
	// TOTP_CHALLENGE_ATTEMPTS = 5 tries from steps-2 to steps+2 and so on
	diff = TOTP_CHALLENGE_ATTEMPTS / 2;
	for(i = 0; i < TOTP_CHALLENGE_ATTEMPTS; i++){
		code_array[i] = getCodeFromSteps(steps - diff);
		diff--;
	}
}

/*
* Checks whether the specified TOTP value is valid or not, by generating
* TOTP_CHALLENGE_ATTEMPTS TOTP values and chcking whether any of them
* match the value coming from the device, dev_totp.
* Returns 1 if true, 0 otherwise.
*/
static int totp_challenge(uint32_t dev_totp){
	uint32_t driver_totp_array[TOTP_CHALLENGE_ATTEMPTS];

	get_totp(driver_totp_array);

	if(!valueinarray(dev_totp, driver_totp_array, TOTP_CHALLENGE_ATTEMPTS)){
		return 0;
	}

	return 1;
}

/*
* Extracts TOTP data from response array (totp_spdm_usb_struct->response_data),
* and checks whether the result is consistent through totp_challenge.
*/
static void verify_totp_from_response(void) {
	uint8_t totp_hex[TOTP_HEX_SIZE];
	uint32_t totp_dec;
	int result;

	// Fetch TOTP code starting from 4th position
	memcpy(totp_hex, totp_spdm_usb_struct->response_data + LEN_HEX_SIZE, TOTP_HEX_SIZE*sizeof(char));

	// Transform TOTP hex into unsigned int
	totp_dec = hexdec(totp_hex);
	pr_info("totp_dec: %u\n", totp_dec);

	// Check TOTP consistency
	result = totp_challenge(totp_dec);
	if (!result){
		pr_alert("TOTP %u did not match the device's challenge.", totp_dec);
		fail();
	}
}

/*
* Callback funciton for receiving messages
*/
static void recv_arbitrary_data_callback(struct urb *urb){
	int i;
	
	// Work with received data
	totp_spdm_usb_struct->response_size = get_size_from_response();
	verify_totp_from_response();
	memmove (totp_spdm_usb_struct->response_data,
			totp_spdm_usb_struct->response_data + SPDM_RECEIVE_OFFSET,
			(totp_spdm_usb_struct->response_size) * sizeof(uint8_t));

	pr_info("totp_spdm_usb_struct->response_data:\n");
	for (i = 0; i < totp_spdm_usb_struct->response_size; i++){
		if ((i+1)%8 != 0){
			pr_cont("%02X ", ((uint8_t *)(totp_spdm_usb_struct->response_data))[i]);
		}
		else {
			pr_info("%02X ", ((uint8_t *)(totp_spdm_usb_struct->response_data))[i]);
		}
	}

	if (!completion_done (&totp_spdm_usb_struct->spdm_response_done)){
		complete (&totp_spdm_usb_struct->spdm_response_done);
		pr_info("spdm_response_done completed");
	}

	// Free URB
	usb_free_urb(urb);
}

/*
* Receive any message
*/
static void recv_arbitrary_data(void *data, size_t *size){
	int response;
	struct urb *in_urb;

	// Allocate URB
	in_urb = usb_alloc_urb(0, GFP_KERNEL);

	// Fill URB with necessary info
	usb_fill_bulk_urb(
		in_urb,								// URB pointer
		totp_spdm_usb_struct->dev,			// relevant usb_device
		usb_rcvbulkpipe(					// bulk pipe
			totp_spdm_usb_struct->dev,
			totp_spdm_usb_struct->in_endpoint_addr),
		data,								// buffer
		*size,								// buffer size
		recv_arbitrary_data_callback,		// callback funciton
		totp_spdm_usb_struct				// context (?)
	);

	// Submit urb
	response = usb_submit_urb(in_urb, GFP_KERNEL);
	if (response) {
		usb_free_urb(in_urb);
		printk(KERN_INFO "erro %d em usb_submit_urb\n", response);
		fail();
	}
}

/*
* Receive SPDM message
*/
static return_status spdm_usb_receive_message(
			IN void *spdm_context,
			IN OUT uintn *response_size,
			IN OUT void *response,
			IN uint64 timeout){
	int i;

	// initializing completion struct
	init_completion(&totp_spdm_usb_struct->spdm_response_done);

	// Setting the response array to the maximum possible size initially
	totp_spdm_usb_struct->response_data = kmalloc(4608, GFP_DMA);
	totp_spdm_usb_struct->response_size = *response_size;
	pr_info("original size: %llu\n", *response_size);
	recv_arbitrary_data(totp_spdm_usb_struct->response_data, &(totp_spdm_usb_struct->response_size));

	// Code must (not) continue until the response is completed.
	// Sending and receiving URBs is not a synchronous process, so
	// this is necessary to make sure we have the right data here.
	wait_for_completion(&totp_spdm_usb_struct->spdm_response_done);

	*response_size = totp_spdm_usb_struct->response_size;
	memcpy(response, totp_spdm_usb_struct->response_data, totp_spdm_usb_struct->response_size);
	pr_info("Received SPDM response with size %llu\n", *response_size);
	
	pr_info("SPDM response:\n");
	for (i = 0; i < *response_size; i++){
		if ((i+1)%8 != 0){
			pr_cont("%02X ", ((uint8_t *)response)[i]);
		}
		else {
			pr_info("%02X ", ((uint8_t *)response)[i]);
		}
	}
	return RETURN_SUCCESS;
}

/*
* Callback funciton for receiving messages
*/
static void send_arbitrary_data_callback(struct urb *urb){
	if (!completion_done (&totp_spdm_usb_struct->spdm_request_sent)){
		complete (&totp_spdm_usb_struct->spdm_request_sent);
		pr_info("spdm_request_sent completed");
	}

	// Free URB
	usb_free_urb(urb);
}

/*
* Send any message
*/
static void send_arbitrary_data(uint8_t *data, uint32_t size){
	int response;
	struct urb *out_urb;

	// Allocate URB
	out_urb = usb_alloc_urb(0, GFP_KERNEL);

	// Fill URB with necessary info
	usb_fill_bulk_urb(
		out_urb,							// URB pointer
		totp_spdm_usb_struct->dev,			// relevant usb_device
		usb_sndbulkpipe(					// bulk pipe
			totp_spdm_usb_struct->dev,
			totp_spdm_usb_struct->out_endpoint_addr),
		data,								// buffer
		size,								// buffer size
		send_arbitrary_data_callback,		// callback funciton
		totp_spdm_usb_struct				// context (?)
	);

	// Submit urb
	response = usb_submit_urb(out_urb, GFP_KERNEL);
	if (response) {
		usb_free_urb(out_urb);
		printk(KERN_INFO "erro %d em usb_submit_urb\n", response);
		fail();
	}
}

/*
* Send SPDM messages
*/
static return_status spdm_usb_send_message(
			IN void *spdm_context,
			IN uintn request_size,
			IN void *request,
			IN uint64 timeout) {
	void *request_with_length_header;
	char len_str[LEN_HEX_SIZE];
	pr_info("Sending SPDM request with size %llu\n", request_size);
	init_completion(&totp_spdm_usb_struct->spdm_request_sent);

	// Add 4 bytes of length to first positions of request buffer
	request_with_length_header = kmalloc(request_size + LEN_HEX_SIZE, GFP_KERNEL);
	sprintf(len_str, "%llx", request_size);
	memcpy(request_with_length_header, len_str, LEN_HEX_SIZE*sizeof(char));

	// Copy rest of request buffer
	memcpy(request_with_length_header + LEN_HEX_SIZE, request, request_size);
	send_arbitrary_data(request_with_length_header, request_size + LEN_HEX_SIZE);

	wait_for_completion(&totp_spdm_usb_struct->spdm_request_sent);
	return RETURN_SUCCESS;
}

/*
* Function to initialize SPDM context
*/
static void* init_spdm(void) {
	void *spdm_context;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;
	spdm_data_parameter_t parameter;
	spdm_version_number_t spdm_version;

	pr_info("spdm_context size: 0x%x\n", (uint32_t)spdm_get_context_size());
	spdm_context = (void *)kmalloc(spdm_get_context_size(), GFP_KERNEL);
	if (spdm_context == NULL) {
		pr_alert("Failed to initialize SPDM context.\n");
		return NULL;
	}

	// Initialize context variable
	spdm_init_context(spdm_context);

	// Set functions for setting and receiving SPDM messages
	spdm_register_device_io_func(
			spdm_context,
			spdm_usb_send_message,
			spdm_usb_receive_message);
	
	if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
		spdm_register_transport_layer_func(
			spdm_context, spdm_transport_mctp_encode_message,
			spdm_transport_mctp_decode_message);
	} else {
		pr_alert("SPDM transfer type not supported.\n");
		return NULL;
	}

	if (m_use_version != SPDM_MESSAGE_VERSION_11) {
		zero_mem(&parameter, sizeof(parameter));
		parameter.location = SPDM_DATA_LOCATION_LOCAL;
		spdm_version.major_version = (m_use_version >> 4) & 0xF;
		spdm_version.minor_version = m_use_version & 0xF;
		spdm_version.alpha = 0;
		spdm_version.update_version_number = 0;
		spdm_set_data(spdm_context, SPDM_DATA_SPDM_VERSION, &parameter,
			      &spdm_version, sizeof(spdm_version));
	}

	if (m_use_secured_message_version != SPDM_MESSAGE_VERSION_11) {
		zero_mem(&parameter, sizeof(parameter));
		if (m_use_secured_message_version != 0) {
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			spdm_version.major_version =
				(m_use_secured_message_version >> 4) & 0xF;
			spdm_version.minor_version =
				m_use_secured_message_version & 0xF;
			spdm_version.alpha = 0;
			spdm_version.update_version_number = 0;
			spdm_set_data(spdm_context,
				      SPDM_DATA_SECURED_MESSAGE_VERSION,
				      &parameter, &spdm_version,
				      sizeof(spdm_version));
		} else {
			spdm_set_data(spdm_context,
				      SPDM_DATA_SECURED_MESSAGE_VERSION,
				      &parameter, NULL, 0);
		}
	}

	zero_mem(&parameter, sizeof(parameter));
	parameter.location = SPDM_DATA_LOCATION_LOCAL;

	data8 = 0;
	spdm_set_data(spdm_context, SPDM_DATA_CAPABILITY_CT_EXPONENT,
		      &parameter, &data8, sizeof(data8));
	data32 = m_use_requester_capability_flags;
	if (m_use_capability_flags != 0) {
		data32 = m_use_capability_flags;
	}
	spdm_set_data(spdm_context, SPDM_DATA_CAPABILITY_FLAGS, &parameter,
		      &data32, sizeof(data32));

	data8 = m_support_measurement_spec;
	spdm_set_data(spdm_context, SPDM_DATA_MEASUREMENT_SPEC, &parameter,
		      &data8, sizeof(data8));
	data32 = m_support_asym_algo;
	spdm_set_data(spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter,
		      &data32, sizeof(data32));
	data32 = m_support_hash_algo;
	spdm_set_data(spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter,
		      &data32, sizeof(data32));
	data16 = m_support_dhe_algo;
	spdm_set_data(spdm_context, SPDM_DATA_DHE_NAME_GROUP, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_aead_algo;
	spdm_set_data(spdm_context, SPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_req_asym_algo;
	spdm_set_data(spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_key_schedule_algo;
	spdm_set_data(spdm_context, SPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
		      sizeof(data16));

	return spdm_context;
}

#define TEST_PSK_DATA_STRING "TestPskData"
#define TEST_PSK_HINT_STRING "TestPskHint"

/*
* Initiates SPDM data related to certificates, that require the connection
* to be at SPDM_CONNECTION_STATE_NEGOTIATED.
*/
void init_spdm_certificates(void* spdm_context) {
	uint8_t index;
	return_status status;
	uintn data_size;
	spdm_data_parameter_t parameter;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;

	pr_info("init_spdm_certificates\n");
	zero_mem(&parameter, sizeof(parameter));
	parameter.location = SPDM_DATA_LOCATION_CONNECTION;

	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_CONNECTION_STATE, &parameter,
		      &data32, &data_size);
	ASSERT(data32 == SPDM_CONNECTION_STATE_NEGOTIATED);

	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
		      &data32, &data_size);
	m_use_measurement_hash_algo = data32;
	
	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter,
		      &data32, &data_size);
	m_use_asym_algo = data32;
	
	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter,
		      &data32, &data_size);
	m_use_hash_algo = data32;
	
	data_size = sizeof(data16);
	spdm_get_data(spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		      &data16, &data_size);
	m_use_req_asym_algo = data16;

	if ((m_use_slot_id == 0xFF) ||
			((m_use_requester_capability_flags &
			SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0)) {
		zero_mem(&parameter, sizeof(parameter));
		parameter.location = SPDM_DATA_LOCATION_LOCAL;
		spdm_set_data(spdm_context,
				SPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
				&parameter,
				responder_public_certificate_chain_data,
				responder_public_certificate_chain_size);
	} else {
		zero_mem(&parameter, sizeof(parameter));
		parameter.location = SPDM_DATA_LOCATION_LOCAL;
		spdm_set_data(spdm_context,
				SPDM_DATA_PEER_PUBLIC_ROOT_CERT_HASH,
				&parameter,
				responder_public_certificate_chain_hash,
				responder_public_certificate_chain_hash_size);
	}
	zero_mem(&parameter, sizeof(parameter));
	parameter.location = SPDM_DATA_LOCATION_LOCAL;
	data8 = m_use_slot_count;
	spdm_set_data(spdm_context, SPDM_DATA_LOCAL_SLOT_COUNT,
				&parameter, &data8, sizeof(data8));

	for (index = 0; index < m_use_slot_count; index++) {
		parameter.additional_data[0] = index;
		spdm_set_data(spdm_context,
				SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
				&parameter,
				requester_public_certificate_chain_data,
				requester_public_certificate_chain_size);
	}

	status = spdm_set_data(
			spdm_context,
			SPDM_DATA_PSK_HINT,
			NULL,
			TEST_PSK_HINT_STRING,
			sizeof(TEST_PSK_HINT_STRING));
	
	if (RETURN_ERROR(status)) {
		printk("spdm_set_data - %x\n", (uint32)status);
		fail();
	}

}

/*
* URB callback function.
* Will be called every time an incoming URB request finishes
*/
/*
static void urb_in_callback(struct urb *urb){
	int i, result;
	uint32_t totp_dec;

	pr_info("totp_spdm_usb_struct->in_buf: %px\n", totp_spdm_usb_struct->in_buf);
	for (i = 0; i < (BUFFER_SIZE)/8; i++){
		pr_info("%02X %02X %02X %02X %02X %02X %02X %02X",
			totp_spdm_usb_struct->in_buf[8*i+0], totp_spdm_usb_struct->in_buf[8*i+1],
			totp_spdm_usb_struct->in_buf[8*i+2], totp_spdm_usb_struct->in_buf[8*i+3], 
			totp_spdm_usb_struct->in_buf[8*i+4], totp_spdm_usb_struct->in_buf[8*i+5],
			totp_spdm_usb_struct->in_buf[8*i+6], totp_spdm_usb_struct->in_buf[8*i+7]);
	}
	pr_info("-----\n");

	// Fetch TOTP code starting from 16th position
	memcpy(totp_spdm_usb_struct->totp_hex, &(totp_spdm_usb_struct->in_buf)[16], 7*sizeof(char));

	// Transform TOTP hex into unsigned int
	totp_dec = hexdec(totp_spdm_usb_struct->totp_hex);
	pr_info("totp_dec: %u\n", totp_dec);

	// Check TOTP consistency
	result = totp_challenge(totp_dec);
	if (!result){
		pr_alert("TOTP %u did not match the device's challenge.", totp_dec);
		fail();
	}

	// Set URBs as inactive
	spin_lock(&usb_spinlock);
	totp_spdm_usb_struct->out_urb_is_active = false;
	totp_spdm_usb_struct->in_urb_is_active = false;
	spin_unlock(&usb_spinlock);

	// Free URBs
	usb_free_urb(totp_spdm_usb_struct->out_urb);
	usb_free_urb(totp_spdm_usb_struct->in_urb);
	kfree(totp_spdm_usb_struct->in_buf);
	kfree(totp_spdm_usb_struct->buf);
}
*/

/*
* URB callback function.
* Will be called every time an outgoing URB request finishes.
* Also sends another URB, which gathers the device's response.
*/
/*
static void urb_out_callback(struct urb *urb){
	int response;

	// Set URB as active
	spin_lock(&usb_spinlock);
	totp_spdm_usb_struct->in_urb_is_active = true;
	spin_unlock(&usb_spinlock);

	// allocate memory in totp_spdm_usb struct's input buffer and URB
	// these will be used to get the device's response
	totp_spdm_usb_struct->in_buf = kmalloc(totp_spdm_usb_struct->buf_size, GFP_ATOMIC);
	totp_spdm_usb_struct->in_urb = usb_alloc_urb(0, GFP_ATOMIC);
	totp_spdm_usb_struct->in_buf_size = BUFFER_SIZE;

	// fill URB with necessary info
	usb_fill_bulk_urb(
		totp_spdm_usb_struct->in_urb,		// URB pointer
		totp_spdm_usb_struct->dev,			// relevant usb_device
		usb_rcvbulkpipe(					// receiving bulk pipe
			totp_spdm_usb_struct->dev,
			totp_spdm_usb_struct->in_endpoint_addr & USB_ENDPOINT_NUMBER_MASK),
		totp_spdm_usb_struct->in_buf,		// buffer
		totp_spdm_usb_struct->in_buf_size,	// buffer size
		urb_in_callback,					// callback funciton
		totp_spdm_usb_struct				// context (?)
	);
	response = usb_submit_urb(totp_spdm_usb_struct->in_urb, GFP_ATOMIC);
	if (response) {
		usb_free_urb(totp_spdm_usb_struct->in_urb);
		printk(KERN_INFO "erro %d em usb_submit_urb\n", response);
	}
}
*/

/*
* Temporary function to set buffer and buffer size
*/
/*
static void set_buffer(void){
	uint8_t data[BUFFER_SIZE] = {[0] = 0, [1] = 1, [2] = 2, [9] = 9, [10] = 10};
	//01 02 03 00 00 00 00 00 00 09 0A 00 00

	totp_spdm_usb_struct->buf_size = BUFFER_SIZE;
	totp_spdm_usb_struct->buf = kmalloc(totp_spdm_usb_struct->buf_size, GFP_KERNEL);
	memcpy(totp_spdm_usb_struct->buf, data, BUFFER_SIZE);
}
*/

/*
* Main function to send data through an URB to relevant USB device
*/
/*
static void send_data(void){
	int response;

	// Set URB as active
	spin_lock(&usb_spinlock);
	totp_spdm_usb_struct->out_urb_is_active = true;
	spin_unlock(&usb_spinlock);

	// allocate URB
	totp_spdm_usb_struct->out_urb = usb_alloc_urb(0, GFP_KERNEL);

	// fill URB with necessary info
	usb_fill_bulk_urb(
		totp_spdm_usb_struct->out_urb,		// URB pointer
		totp_spdm_usb_struct->dev,			// relevant usb_device
		usb_sndbulkpipe(					// bulk pipe
			totp_spdm_usb_struct->dev,
			totp_spdm_usb_struct->out_endpoint_addr),
		totp_spdm_usb_struct->buf,			// buffer
		totp_spdm_usb_struct->buf_size,		// buffer size
		urb_out_callback,					// callback funciton
		totp_spdm_usb_struct				// context (?)
	);

	// submit urb
	response = usb_submit_urb(totp_spdm_usb_struct->out_urb, GFP_KERNEL);
	if (response) {
		usb_free_urb(totp_spdm_usb_struct->out_urb);
		printk(KERN_INFO "erro %d em usb_submit_urb\n", response);
	}
}
*/

/*
* Work queue function.
* Will work on a separate thread from the very beginning of the
* driver's life cycle.
*/
static void totp_spdm_work_handler(struct work_struct *w) {
	int tries;
	bool use_psk;
	uint8_t heartbeat_period;
	uint8_t measurement_hash[MAX_HASH_SIZE];
	bool device_found = false;

	// Maybe in some world it takes longer for the device to be found
	// For this case, a timeout with a set number of tries
	for (tries = 0; tries < MAX_TRIES; tries++){
		if (totp_spdm_usb_struct->endpoints_count != 0){
			pr_info("SPDM device found on attempt %d\n", tries);
			device_found = true;
			break;
		}
		msleep(TIMEOUT_MS);
	}

	if (!device_found){
		pr_alert("SPDM device not found!\n");
		fail();
	}

	while(true){
		// TODO: periodic SPDM checks
		pr_info("Initializing periodic SPDM checks.");

		// Initialize SPDM
		totp_spdm_usb_struct->spdm_context = init_spdm();
		if (totp_spdm_usb_struct->spdm_context == NULL) {
			pr_alert("Failed to initialize SPDM context.\n");
		}

		// get_version, get_capabilities, and negotiate_algorithms
		totp_spdm_usb_struct->spdm_status = spdm_init_connection(
				totp_spdm_usb_struct->spdm_context, false);
		if (RETURN_ERROR(totp_spdm_usb_struct->spdm_status)) {
			pr_alert("Error on spdm_init_connection: %llX.", totp_spdm_usb_struct->spdm_status);
			err_free_spdm();
			fail();
		} else {
			pr_info("SPDM Context initialized.");
		}

		init_spdm_certificates(totp_spdm_usb_struct->spdm_context);

		// GET_DIGEST, GET_CERTIFICATE, CHALLENGE messages
		totp_spdm_usb_struct->spdm_status = do_authentication_via_spdm(totp_spdm_usb_struct->spdm_context);
		if (RETURN_ERROR(totp_spdm_usb_struct->spdm_status)) {
			pr_info("do_authentication_via_spdm - %x", (uint32)totp_spdm_usb_struct->spdm_status);
			err_free_spdm();
			fail();
		} else {
			pr_info("do_authentication_via_spdm - done");
		}

		use_psk = FALSE;
		heartbeat_period = 0;
		totp_spdm_usb_struct->spdm_status = spdm_start_session(totp_spdm_usb_struct->spdm_context,
				use_psk,
				m_use_measurement_summary_hash_type,
				m_use_slot_id,
				&totp_spdm_usb_struct->session_id,
				&heartbeat_period,
				measurement_hash);
		if (RETURN_ERROR(totp_spdm_usb_struct->spdm_status)) {
			pr_info("spdm_start_session - %x", (uint32)totp_spdm_usb_struct->spdm_status);
			err_free_spdm();
			fail();
		}

		pr_info("session_id: %d", totp_spdm_usb_struct->session_id);
		pr_info("All SPDM checks realized successfully.");
		msleep(VERIFICATION_PERIOD_MS);
		totp_spdm_usb_struct->spdm_status = spdm_stop_session(
					totp_spdm_usb_struct->spdm_context,
					totp_spdm_usb_struct->session_id,
					0);
		if (RETURN_ERROR(totp_spdm_usb_struct->spdm_status)) {
			pr_info("spdm_stop_session - %x", (uint32)totp_spdm_usb_struct->spdm_status);
			err_free_spdm();
			fail();
		}
	}
}

/*
* This function will be called when USB device is inserted.
*/
static int usb_totp_spdm_probe (struct usb_interface *interface, const struct usb_device_id *id) {
	struct usb_endpoint_descriptor *bulk_in, *bulk_out;
	struct usb_host_interface *iface_desc;
	unsigned int i;
	int retval;

	printk(KERN_INFO "usb_totp_spdm_probe\n");
	totp_spdm_usb_struct->dev = interface_to_usbdev(interface);

	// Endpoint-related kernel prints
	iface_desc = interface->cur_altsetting;
	dev_info(&interface->dev, "USB Driver Probed: Vendor ID : 0x%02x,\t"
		"Product ID : 0x%02x\n", id->idVendor, id->idProduct);

	// We set this bariable to make sure at least one device has been found 
	totp_spdm_usb_struct->endpoints_count = iface_desc->desc.bNumEndpoints;

	print_usb_interface_descriptor(iface_desc->desc);
	for (i = 0; i < totp_spdm_usb_struct->endpoints_count; i++) {
		print_usb_endpoint_descriptor(iface_desc->endpoint[i].desc);
	}

	/* set up the endpoint information */
	/* use only the first bulk-in and bulk-out endpoints */
	retval = usb_find_common_endpoints(iface_desc,
			&bulk_in, &bulk_out, NULL, NULL);
	if (retval) {
		dev_err(&interface->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
	}
	
	totp_spdm_usb_struct->in_endpoint_addr = bulk_in->bEndpointAddress;
	totp_spdm_usb_struct->out_endpoint_addr = bulk_out->bEndpointAddress;

	return 0;  //return 0 indicates we are managing this device
}

/*
* This function will be called when USB device is removed.
*/
static void usb_totp_spdm_disconnect (struct usb_interface *interface) {
	pr_info("usb_totp_spdm_disconnect\n");
	fail();
	dev_info (&interface->dev, "USB Driver Disconnected\n");
}
 
/*
* usb_device_id provides a list of different types of
* USB devices that the driver supports
*/
const struct usb_device_id usb_totp_spdm_table[] = {
	{USB_DEVICE (USB_VENDOR_ID, USB_PRODUCT_ID)},
	{} /* Terminating entry */
};

MODULE_DEVICE_TABLE(usb, usb_totp_spdm_table);

static struct usb_driver usb_totp_spdm_driver = {
	.name       = "TOTP + SPDM USB Driver",
	.probe      = usb_totp_spdm_probe,
	.disconnect = usb_totp_spdm_disconnect,
	.id_table   = usb_totp_spdm_table,
};

/*
* Initializing function for the driver.
* Must create an instance of the driver's global struct, 
* and also invoke the necessary functions to start up the
* work handler function.
*/
static int __init usb_totp_spdm_init (void) {
	printk(KERN_INFO "usb_totp_spdm_init\n");

	// create an instance of the driver's struct
	totp_spdm_usb_struct = vmalloc(sizeof(struct totp_spdm_usb));
	totp_spdm_usb_struct->endpoints_count = 0;

	// start the workqueue pointer, in case it is not set yet
	if (!wq){
		wq = create_singlethread_workqueue("totp_spdm");
		printk(KERN_INFO "not wq\n");
	}

	// create totp_spdm_work workqueue
	if (wq){
		queue_work(wq, &totp_spdm_work);
		printk(KERN_INFO "wq\n");
	}
	//register the USB device
	return usb_register(&usb_totp_spdm_driver);
}
 
static void __exit usb_totp_spdm_exit (void) {
	pr_info("usb_totp_spdm_exit\n");

	// stop totp_spdm_work work queue
	cancel_work_sync(&totp_spdm_work);
	destroy_workqueue(wq);

	//deregister the USB device
	usb_deregister(&usb_totp_spdm_driver);
}
 
module_init(usb_totp_spdm_init);
module_exit(usb_totp_spdm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TOTP + SPDM USB Driver");
MODULE_VERSION("0.2");

