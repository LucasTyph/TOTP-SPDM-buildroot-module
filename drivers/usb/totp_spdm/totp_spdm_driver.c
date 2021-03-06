#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/time.h>

// SPDM includes
#include "spdm_auth.c"

// TOTP include
#include "TOTP.h"

/*
** This macro is used to tell the driver to use old method or new method.
** If it is 0, then driver will use old method. ie: __init and __exit
** If it is non zero, then driver will use new method. ie: module_usb_driver
*/
#define IS_NEW_METHOD_USED 1
#define USB_VENDOR_ID 0x0666
#define USB_PRODUCT_ID 0x0666
#define MAX_TRIES 2
#define TIMEOUT_MS 5000
#define VERIFICATION_PERIOD_MS 10000
#define BUFFER_SIZE 64
#define URB_REQUEST_OFFSET 8
#define TOTP_TIMESTEP 60

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
	unsigned int endpoints_count;
	struct urb *out_urb;
	struct urb *in_urb;
	uint8_t port_number;
	struct usb_device *dev;
	uint8_t in_endpoint_addr;
	uint8_t out_endpoint_addr;
	uint8_t *buf;
	unsigned long buf_size;
	uint8_t *in_buf;
	unsigned long in_buf_size;
	uint32_t totp_code;
} *totp_spdm_usb_struct;

static void fail(void){
		// shutdown device
		pr_alert("Shutting down system...\n");
		// uncommment for shutting down the system
		kernel_power_off();
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

int valueinarray(uint32_t val, uint32_t arr[], uint32_t arr_size) {
	uint8_t i;
	for(i = 0; i < arr_size; i++){
		if(arr[i] == val)
			return 1;
	}
	return 0;
}

static void get_totp(uint32_t* code_array){
	int i, challenge_attempts, diff;
	struct timespec *ts;
	uint32_t steps;

	// set key for now
	// TODO: some different method of getting the key
	uint8_t hmacKey[] = {0x4d, 0x79, 0x4c, 0x65, 0x67, 0x6f, 0x44, 0x6f, 0x6f, 0x72};

	TOTP(hmacKey, 10, TOTP_TIMESTEP); // key, key size, timestep in s

	// get current time
	ts = kmalloc(sizeof(*ts), GFP_KERNEL);
	getnstimeofday(ts);

	// get number of steps
	steps = ts->tv_sec / TOTP_TIMESTEP;

	challenge_attempts = 3;
	diff = challenge_attempts / 2;
	for(i = 0; i < challenge_attempts; i++){
		code_array[i] = getCodeFromSteps(steps - diff);
		diff--;
	}
}

static int totp_challenge(uint32_t dev_totp){
	uint32_t gen_totp[3];

	get_totp(gen_totp);

	if(!valueinarray(dev_totp, gen_totp, 3)){
		return 0;
	}

	return 1;
}

/*
* URB callback function.
* Will be called every time an incoming URB request finishes
*/
static void urb_in_callback(struct urb *urb){
	int i, result;
	uint8_t totp_hex[7];
	uint32_t totp_dec;

	if (!urb){
		pr_info("!urb\n");
	}

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
	memcpy(totp_hex, &(totp_spdm_usb_struct->in_buf)[16], 7*sizeof(char));

	// Transform TOTP hex into unsigned int
	totp_dec = hexdec(totp_hex);
	pr_info("totp_dec: %u\n", totp_dec);

	// Check TOTP consistency
	result = totp_challenge(totp_dec);
	if (!result){
		fail();
	}

	// Free URBs
	usb_free_urb(totp_spdm_usb_struct->out_urb);
	usb_free_urb(totp_spdm_usb_struct->in_urb);
	kfree(totp_spdm_usb_struct->in_buf);
	kfree(totp_spdm_usb_struct->buf);
}

/*
* URB callback function.
* Will be called every time an outgoing URB request finishes.
* Also sends another URB, which gathers the device's response.
*/
static void urb_out_callback(struct urb *urb){
	int response;

	// allocate memory in totp_spdm_usb struct's input buffer and URB
	// these will be used to get the device's response
	totp_spdm_usb_struct->in_buf = kmalloc(totp_spdm_usb_struct->buf_size, GFP_ATOMIC);
	totp_spdm_usb_struct->in_urb = usb_alloc_urb(0, GFP_ATOMIC);
	totp_spdm_usb_struct->in_buf_size = BUFFER_SIZE;

	// fill URB with necessary info
	usb_fill_bulk_urb(
		totp_spdm_usb_struct->in_urb,		// URB pointer
		totp_spdm_usb_struct->dev,			// relevant usb_device
		usb_rcvbulkpipe(					// receiving control pipe
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

/*
* Temporary function to set buffer and buffer size
*/
static void set_buffer(void){
	uint8_t data[BUFFER_SIZE] = {[0] = 5, [1] = 0x11, [2] = 0xe1, [9] = 0xc6, [10] = 0xf7};
	//05 11 e1 00 00 00 00 00 00 c6 f7 00 00

	totp_spdm_usb_struct->buf_size = BUFFER_SIZE;
	totp_spdm_usb_struct->buf = kmalloc(totp_spdm_usb_struct->buf_size, GFP_KERNEL);
	memcpy(totp_spdm_usb_struct->buf, data, BUFFER_SIZE);
}

/*
* Main function to send data through an URB to relevant USB device
*/
static void send_data(void){
	int response;

	// allocate URB
	totp_spdm_usb_struct->out_urb = usb_alloc_urb(0, GFP_KERNEL);

	// fill URB with necessary info
	usb_fill_bulk_urb(
		totp_spdm_usb_struct->out_urb,		// URB pointer
		totp_spdm_usb_struct->dev,			// relevant usb_device
		usb_sndbulkpipe(					// control pipe
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

/*
* Work queue function called continuously
*/
static void totp_spdm_work_handler(struct work_struct *w) {
	int tries;
	bool device_found = false;
	void *spdm_context;
	return_status status;

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
		msleep(VERIFICATION_PERIOD_MS);

		// transfer buffer
		set_buffer();

		spdm_context = (void *)kmalloc (spdm_get_context_size(), GFP_KERNEL);
		status = do_authentication_via_spdm(spdm_context);
		pr_info("status: %d\n", status);

		send_data();
	}
}

/*
** This function will be called when USB device is inserted.
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
** This function will be called when USB device is removed.
*/
static void usb_totp_spdm_disconnect (struct usb_interface *interface) {
	printk (KERN_INFO "usb_totp_spdm_disconnect\n");
	dev_info (&interface->dev, "USB Driver Disconnected\n");
}
 
//usb_device_id provides a list of different types of USB devices that the driver supports
const struct usb_device_id usb_totp_spdm_table[] = {
	{USB_DEVICE (USB_VENDOR_ID, USB_PRODUCT_ID)},
	{} /* Terminating entry */
};
 
//This enable the linux hotplug system to load the driver automatically when the device is plugged in
MODULE_DEVICE_TABLE(usb, usb_totp_spdm_table);

//The structure needs to do is register with the linux subsystem
static struct usb_driver usb_totp_spdm_driver = {
	.name       = "TOTP + SPDM USB Driver",
	.probe      = usb_totp_spdm_probe,
	.disconnect = usb_totp_spdm_disconnect,
	.id_table   = usb_totp_spdm_table,
};

#if (IS_NEW_METHOD_USED == 0)
//This will replace module_init and module_exit.
module_usb_driver(usb_totp_spdm_driver);
 
#else
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
	printk(KERN_INFO "usb_totp_spdm_exit\n");

	// stop totp_spdm_work work queue
	cancel_work_sync(&totp_spdm_work);
	destroy_workqueue(wq);

	//deregister the USB device
	usb_deregister(&usb_totp_spdm_driver);
}
 
module_init(usb_totp_spdm_init);
module_exit(usb_totp_spdm_exit);
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TOTP + SPDM USB Driver");
MODULE_VERSION("0.2");

