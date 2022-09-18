#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "hw/usb.h"
#include "desc.h"

#define RECV_BUF 384
#define MAX_PACKET_SIZE 512

/* struct que não é de fato usado pra muita coisa,
mas é definido em todos os dispositivos usb
precisa ser modificado para o dispositivo usb em questão */

typedef struct {
    USBDevice dev;
    uint8_t data[MAX_PACKET_SIZE];
} USBTotpSpdmState;

/* esses defines são feitos em todos os dispositivos usb
o TYPE_USB_TOTP_SPDM define o nome do dispositivo,
e o outro define eu não entendi muito bem, mas ele usa o struct de cima */

#define TYPE_USB_TOTP_SPDM "usb-totp-spdm-dev"
#define USB_TOTP_SPDM_DEV(obj) OBJECT_CHECK(USBTotpSpdmState, (obj), TYPE_USB_TOTP_SPDM)

/* daqui para frente, tem várias funções de descrição do USB
Essa seção é baseada no dev-serial.c, com as principais mudanças sendo
os números seriais (idVendor e idProduct), que aparecem quando se roda lsusb,
e os definidores de classe/protocolo  (bInterfaceClass, bDeviceClass, etc.),
que eu mudei para 0x00, que deveria ser o dispositivo mais geral
https://www.usb.org/defined-class-codes */

enum {
    STR_MANUFACTURER = 1,
    STR_SERIALNUMBER,
};

static const USBDescStrings desc_strings = {
    [STR_MANUFACTURER]    = "666",
    [STR_SERIALNUMBER]    = "666",
};

static const USBDescIface desc_iface0 = {
    .bInterfaceNumber              = 0,
    .bNumEndpoints                 = 2,
    .bInterfaceClass               = 0x00,
    .bInterfaceSubClass            = 0x00,
    .bInterfaceProtocol            = 0x00,
    .eps = (USBDescEndpoint[]) {
        {
            .bEndpointAddress      = USB_DIR_IN | 0x01,
            .bmAttributes          = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize        = MAX_PACKET_SIZE,
        },{
            .bEndpointAddress      = USB_DIR_OUT | 0x02,
            .bmAttributes          = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize        = MAX_PACKET_SIZE,
        },
    }
};

static const USBDescDevice desc_device = {
    .bcdUSB                        = 0x0200,
    .bDeviceClass                  = 0x00,
    .bDeviceSubClass               = 0x00,
    .bDeviceProtocol               = 0x00,
    .bMaxPacketSize0               = 8,
    .bNumConfigurations            = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces        = 1,
            .bConfigurationValue   = 1,
            .bmAttributes          = USB_CFG_ATT_ONE,
            .bMaxPower             = 50,
            .nif = 1,
            .ifs = &desc_iface0,
        },
    },
};

static const USBDesc desc_totp_spdm = {
    .id = {
        .idVendor          = 0x0666,
        .idProduct         = 0x0666,
        .bcdDevice         = 0x0400,
        .iManufacturer     = STR_MANUFACTURER,
        .iSerialNumber     = STR_SERIALNUMBER,
    },
    .full = &desc_device,
    .str  = desc_strings,
};

/* aparentemente essa função precisa existir, e chamar usb_desc_handle_control */

static void usb_totp_spdm_handle_control(USBDevice *dev, USBPacket *p,
               int request, int value, int index, int length, uint8_t *data)
{
    // USBTotpSpdmState *s = (USB_TOTP_SPDM_DEV *)dev;
    int ret;
    ret = usb_desc_handle_control(dev, p, request, value, index, length, data);
    if (ret >= 0) {
        return;
    }
}

static void usb_totp_spdm_handle_data(USBDevice *dev, USBPacket *p)
{
    USBTotpSpdmState *s = (USBTotpSpdmState *) dev;
    printf("usb_totp_spdm_handle_data\n");
    printf("p->ep->nr: %d\n", p->ep->nr);
    printf("p->iov.size: %ld\n", p->iov.size);

    switch (p->pid) {

    // dados saindo do driver
    case USB_TOKEN_OUT:     // PID 225
        printf("USB_TOKEN_OUT\n");
        printf("p->pid: %d\n", p->pid);

        usb_packet_copy(p, s->data, p->iov.size);
    
        for (int i = 0; i < (p->iov.size); i++){
            printf("%02X ", s->data[i]);
            if ((i+1)%8 == 0){
                printf("\n");
            }
        }
        break;

    // dados chegando no driver
    case USB_TOKEN_IN:      // PID 105
        printf("USB_TOKEN_IN\n");
        printf("p->pid: %d\n", p->pid);

        if (s->data != NULL){
            printf("s->data + 1\n");
            for (int i = 0; i < MAX_PACKET_SIZE; i++){
                s->data[i] = s->data[i] + 1;
            }
        }

        int len = MIN(MAX_PACKET_SIZE, p->iov.size);

        // uint8_t data[64] = {[0] = 6, [1] = 0x12, [2] = 0xe2, [9] = 0xc7, [10] = 0xf8};
	    // 06 12 e2 00 00 00 00 00 00 c7 f8 00 00
        usb_packet_copy(p, s->data, len);

        for (int i = 0; i < (p->iov.size); i++){
            printf("%02X ", ((uint8_t *)((p->iov.iov)->iov_base))[i]);
            if ((i+1)%8 == 0){
                printf("\n");
            }
        }
        break;
    
    default:
        printf("default\n");
        printf("p->pid: %d\n", p->pid);
        break;
    }

    printf("---\n");
}

/* aparentemente essa função também precisa existir
dentro dela o usb é incializado com usb_desc_create_serial e usb_desc_init, 
e "conectado" à vm com dev->auto_attach = 0; e usb_device_attach(dev, &error_abort); */

static void usb_totp_spdm_realize(USBDevice *dev, Error **errp)
{
    // USBTotpSpdmState *s = USB_SERIAL_DEV(dev);
    Error *local_err = NULL;

    usb_desc_create_serial(dev);
    usb_desc_init(dev);
    dev->auto_attach = 0;

    usb_check_attach(dev, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    usb_device_attach(dev, &error_abort);
}

/* essa função também está em todos os devices
mudar o nome na variável .name não parece ter nenhum efeito imediato
eu não sei bem o que isso faz */

static const VMStateDescription vmstate_usb_totp_spdm = {
    .name = "usb-totp-spdm",
    .unmigratable = 1,
};

/* vetor (?) de propriedades que era usado no serial
não tem muito uso no momento */

static Property totp_spdm_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

/* funções de inicalização
a variável .name em totp_spdm_info define o nome que precisda ser usado na chamada do qemu */

static void usb_totp_spdm_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);

    uc->realize        = usb_totp_spdm_realize;
    uc->handle_control = usb_totp_spdm_handle_control;
    uc->handle_data    = usb_totp_spdm_handle_data;
    uc->product_desc   = "Dispositivo USB para comunicação TOTP + SPDM";
    uc->usb_desc       = &desc_totp_spdm;
    dc->props = totp_spdm_properties;
    dc->vmsd = &vmstate_usb_totp_spdm;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo totp_spdm_info = {
    .name          = "usb-totp-spdm",
    .parent        = TYPE_USB_DEVICE,
    .instance_size = sizeof(USBTotpSpdmState),
    .class_init    = usb_totp_spdm_class_initfn,
};

/* por algum motivo, o print dessa função nunca acontece */

static USBDevice *usb_totp_spdm_init(USBBus *bus, const char *cmdline)
{
    USBDevice *dev;
    const char *name = TYPE_USB_TOTP_SPDM;
    
    dev = usb_create(bus, name);
    
    return dev;
}

static void usb_totp_spdm_register_types(void)
{
    type_register_static(&totp_spdm_info);
    usb_legacy_register(TYPE_USB_TOTP_SPDM, "totp-spdm", usb_totp_spdm_init);
}

type_init(usb_totp_spdm_register_types)
