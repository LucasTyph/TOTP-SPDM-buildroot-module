#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/hrtimer.h>
#include <linux/sched.h>
#include <linux/mutex.h>

/*
** This macro is used to tell the driver to use old method or new method.
** If it is 0, then driver will use old method. ie: __init and __exit
** If it is non zero, then driver will use new method. ie: module_usb_driver
*/
#define IS_NEW_METHOD_USED (1)
#define USB_VENDOR_ID (0x0666)
#define USB_PRODUCT_ID (0x0666)
#define IRQ_NO 11

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

struct totp_spdm_usb {
	struct urb *out_urb;
	struct urb *in_urb;
	uint8_t port_number;
	struct usb_device *dev;
	uint8_t *buf;
	unsigned long buf_size;
	void *private;
} *totp_spdm_usb;

/* get and set the serial private data pointer helper functions */
static inline void *usb_get_usb_data(struct totp_spdm_usb *usb)
{
	return usb->private;
}

static inline void usb_set_serial_data(struct totp_spdm_usb *usb, void *data)
{
	usb->private = data;
}

static void set_buffer(struct totp_spdm_usb *s){
	s->buf_size = 512;
	uint8_t data[512] = {[0] = 5, [1] = 0x11, [2] = 0xe1, [9] = 0xc6, [10] = 0xf7};
	//05 11 e1 00 00 00 00 00 00 c6 f7 00 00
	s->buf = data;
}

static void urb_out_callback(struct urb *urb){
	printk(KERN_INFO "urb_out_callback\n");
}

static void send_data(void){
	int response;

	// transfer buffer
	set_buffer(totp_spdm_usb);
	
	// allocate URB
	totp_spdm_usb->out_urb = usb_alloc_urb(0, GFP_KERNEL);
	usb_fill_bulk_urb(
		totp_spdm_usb->out_urb,
		totp_spdm_usb->dev,
		usb_sndctrlpipe(
			totp_spdm_usb->dev,
			0),
		totp_spdm_usb->buf,
		totp_spdm_usb->buf_size,
		urb_out_callback,
		totp_spdm_usb
	);
	
	// submit urb
	response = usb_submit_urb(totp_spdm_usb->out_urb, GFP_KERNEL);
	if (response) {
		printk(KERN_INFO "erro em usb_submit_urb\n");
	}
	
	// free urb
	usb_free_urb(totp_spdm_usb->out_urb);
}

static struct hrtimer htimer;
static ktime_t kt_period;

static enum hrtimer_restart timer_function(struct hrtimer *timer)
{
	send_data();
	
	printk(KERN_INFO "timer_function\n");

	hrtimer_forward_now(timer, kt_period);
	return HRTIMER_RESTART;
}

static void timer_init(void) {
	kt_period = ktime_set(10, 0); // seconds, nanoseconds
	hrtimer_init(&htimer, CLOCK_REALTIME, HRTIMER_MODE_REL);
	htimer.function = timer_function;
	hrtimer_start(&htimer, kt_period, HRTIMER_MODE_REL);
}

static void timer_cleanup(void) {
	hrtimer_cancel(&htimer);
}

static irqreturn_t sample_irq(int irq, void *dev_id){
	printk("irq %d\n", irq);
	return IRQ_RETVAL(1);
}

/*
** This function will be called when USB device is inserted.
*/
static int etx_usb_probe (struct usb_interface *interface, const struct usb_device_id *id) {
	printk(KERN_INFO "etx_usb_probe\n");
	unsigned int i;
	unsigned int endpoints_count;
	struct usb_host_interface *iface_desc = interface->cur_altsetting;
 
	dev_info(&interface->dev, "USB Driver Probed: Vendor ID : 0x%02x,\t"
		"Product ID : 0x%02x\n", id->idVendor, id->idProduct);
             
	endpoints_count = iface_desc->desc.bNumEndpoints;

	print_usb_interface_descriptor(iface_desc->desc);

	for (i = 0; i < endpoints_count; i++) {
		print_usb_endpoint_descriptor(iface_desc->endpoint[i].desc);
	}
	
	totp_spdm_usb->dev = usb_get_dev(interface_to_usbdev(interface));
	timer_init();
	
	printk(KERN_INFO "Initializing timer-based function\n");
	
	return 0;  //return 0 indicates we are managing this device
}

/*
** This function will be called when USB device is removed.
*/
static void etx_usb_disconnect (struct usb_interface *interface) {
	printk (KERN_INFO "etx_usb_disconnect\n");
	free_irq (IRQ_NO,(void *)(sample_irq));
	timer_cleanup();
	dev_info (&interface->dev, "USB Driver Disconnected\n");
}
 
//usb_device_id provides a list of different types of USB devices that the driver supports
const struct usb_device_id etx_usb_table[] = {
	{USB_DEVICE (USB_VENDOR_ID, USB_PRODUCT_ID)},
	{} /* Terminating entry */
};
 
//This enable the linux hotplug system to load the driver automatically when the device is plugged in
MODULE_DEVICE_TABLE(usb, etx_usb_table);

//The structure needs to do is register with the linux subsystem
static struct usb_driver etx_usb_driver = {
	.name       = "TOTP + SPDM USB Driver",
	.probe      = etx_usb_probe,
	.disconnect = etx_usb_disconnect,
	.id_table   = etx_usb_table,
};

#if (IS_NEW_METHOD_USED == 0)
//This will replace module_init and module_exit.
module_usb_driver(etx_usb_driver);
 
#else
static int __init etx_usb_init (void) {
	printk(KERN_INFO "etx_usb_init\n");
	//register the USB device
	return usb_register(&etx_usb_driver);
}
 
static void __exit etx_usb_exit (void) {
	printk(KERN_INFO "etx_usb_exit\n");
	//deregister the USB device
	usb_deregister(&etx_usb_driver);
}
 
module_init(etx_usb_init);
module_exit(etx_usb_exit);
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TOTP + SPDM USB Driver");
MODULE_VERSION("0.2");

