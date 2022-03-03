#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "net.h"
#include "platform.h"
#include "util.h"

#define DUMMY_MTU UINT16_MAX

#define DUMMY_IRQ INTR_IRQ_BASE

static int dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst) {
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    // drop data
    return 0;
}

static int dummy_isr(unsigned int irq, void *id) {}

static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit,
};

struct net_device *dummy_init(void) {
    struct net_device *dev;

    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failed");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_DUMMY;
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->ops = &dummy_ops;
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failed");
        return NULL;
    }
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
