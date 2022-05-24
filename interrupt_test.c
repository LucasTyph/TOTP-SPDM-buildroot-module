#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/usb.h>

/*
* This macro is used to tell the driver to use old method or new method.
*  If it is 0, then driver will use old method. ie: __init and __exit
*  If it is non zero, then driver will use new method. ie: module_usb_driver
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

	for ( i = 0; i < endpoints_count; i++ ) {
		print_usb_endpoint_descriptor(iface_desc->endpoint[i].desc);
	}
	return 0;  //return 0 indicates we are managing this device
}

/*
** This function will be called when USB device is removed.
*/
static void etx_usb_disconnect (struct usb_interface *interface) {
	printk(KERN_INFO "etx_usb_disconnect\n");
	dev_info(&interface->dev, "USB Driver Disconnected\n");
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

// código de interrupções
/*
static irqreturn_t sample_irq(int irq, void *dev_id){
	printk("irq %d\n", irq);
	return IRQ_RETVAL(1);
}

static int myinit(void) {
	printk(KERN_INFO "hello init\n");
	int ret;
	
	ret = request_irq(IRQ_NO, &sample_irq, IRQF_SHARED, "uhci_hcd:usb1", 0);
	if (ret < 0) {
		printk(KERN_ALERT "%s: request_irg failed with %d\n", __func__, ret);
	}
	
	return 0;
}

static void myexit(void) {
    printk(KERN_INFO "hello exit\n");
}

MODULE_LICENSE("GPL");
module_init(myinit)
module_exit(myexit)
*/
