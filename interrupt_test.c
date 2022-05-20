#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#define IRQ_NO 11

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
