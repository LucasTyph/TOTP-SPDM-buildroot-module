#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/slab.h>

/*
** This macro is used to tell the driver to use old method or new method.
** If it is 0, then driver will use old method. ie: __init and __exit
** If it is non zero, then driver will use new method. ie: module_usb_driver
*/
#define IS_NEW_METHOD_USED (1)
#define USB_VENDOR_ID (0x0666)
#define USB_PRODUCT_ID (0x0666)
#define MAX_TRIES (2)
#define TIMEOUT_MS (5000)
#define MS_VERIFICATION_PERIOD (10000)

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
	u8 id;
	unsigned int endpoints_count;
	struct urb *out_urb;
	struct urb *in_urb;
	uint8_t port_number;
	struct usb_device *dev;
	uint8_t *buf;
	unsigned long buf_size;
	void *private;
} *totp_spdm_usb_struct;

/* get and set the serial private data pointer helper functions */
static inline void *usb_get_usb_data(struct totp_spdm_usb *usb)
{
	return usb->private;
}

static inline void usb_set_serial_data(struct totp_spdm_usb *usb, void *data)
{
	usb->private = data;
}

/*
* Temporary function to set buffer and buffer size
*/
static void set_buffer(struct totp_spdm_usb *s){
	s->buf_size = 512;
	uint8_t data[512] = {[0] = 5, [1] = 0x11, [2] = 0xe1, [9] = 0xc6, [10] = 0xf7};
	//05 11 e1 00 00 00 00 00 00 c6 f7 00 00
	s->buf = data;
}

/*
* URB callback function.
* Will be called every time an RUB request finishes
*/
static void urb_out_callback(struct urb *urb){
	printk(KERN_INFO "urb_out_callback\n");
}

/*
* Main function to send data through and URB to relevant USB device
*/
static void send_data(void){
	int response;

	// transfer buffer
	set_buffer(totp_spdm_usb_struct);

	char *buffer = kmalloc(totp_spdm_usb_struct->buf_size, GFP_DMA); /* required by kernel >= 4.9 */
	buffer = memcpy(buffer, totp_spdm_usb_struct->buf, totp_spdm_usb_struct->buf_size);
	
	// allocate URB
	totp_spdm_usb_struct->out_urb = usb_alloc_urb(0, GFP_KERNEL);

	// fill URB with necessary info
	usb_fill_bulk_urb(
		totp_spdm_usb_struct->out_urb,		// URB pointer
		totp_spdm_usb_struct->dev,			// relevant usb_device
		usb_sndbulkpipe(
			totp_spdm_usb_struct->dev,
			2),								// control pipe
		buffer,								// buffer
		totp_spdm_usb_struct->buf_size,		// buffer size
		urb_out_callback,					// callback funciton
		totp_spdm_usb_struct				// context (?)
	);
	
	// submit urb
	response = usb_submit_urb(totp_spdm_usb_struct->out_urb, GFP_KERNEL);
	if (response) {
		printk(KERN_INFO "erro %d em usb_submit_urb\n", response);
	}
	
	// free urb
	usb_free_urb(totp_spdm_usb_struct->out_urb);
	kfree(buffer);
}

/*
* Work queue function called continuously
*/
static void totp_spdm_work_handler(struct work_struct *w) {
	int tries;
	bool device_found = false;

	// Maybe in some world it takes longer for the device to be found
	// For this case, a timeout with a set number of tries
	for (tries = 0; tries < MAX_TRIES; tries++){
		if (totp_spdm_usb_struct->endpoints_count != 0){
			pr_info("SPDM device found on attempt %d\n", tries);
			device_found = true;
			break;
			msleep(TIMEOUT_MS);
		}
	}

	if (!device_found){
		// shutdown device
		pr_alert("SPDM device not found!\n");
		pr_alert("Shutting down system...\n");
		// uncommment for shutting down the system
		// kernel_power_off();
	}

	while(true){
		pr_info("work handler\nid: %d\n", totp_spdm_usb_struct->id);
		send_data();
		msleep(MS_VERIFICATION_PERIOD);
	}
}

/*
** This function will be called when USB device is inserted.
*/
static int usb_totp_spdm_probe (struct usb_interface *interface, const struct usb_device_id *id) {
	printk(KERN_INFO "usb_totp_spdm_probe\n");
	totp_spdm_usb_struct->dev = interface_to_usbdev(interface);

	// Endpoint-related kernel prints
	unsigned int i;
	struct usb_host_interface *iface_desc = interface->cur_altsetting;
	dev_info(&interface->dev, "USB Driver Probed: Vendor ID : 0x%02x,\t"
		"Product ID : 0x%02x\n", id->idVendor, id->idProduct);

	// We set this bariable to make sure at least one device has been found 
	totp_spdm_usb_struct->endpoints_count = iface_desc->desc.bNumEndpoints;

	print_usb_interface_descriptor(iface_desc->desc);
	for (i = 0; i < totp_spdm_usb_struct->endpoints_count; i++) {
		print_usb_endpoint_descriptor(iface_desc->endpoint[i].desc);
	}
	
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
	totp_spdm_usb_struct->id = 1;

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

