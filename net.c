#include "net.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ip.h"
#include "platform.h"
#include "util.h"

struct net_protocol {
    struct net_protocol *next;
    uint16_t type;
    struct queue_head queue;
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
    uint8_t data[];
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to
 * protect these lists with a mutex. */
static struct net_device *devices;
static struct net_protocol *protocols;

struct net_device *net_device_alloc(void) {
    struct net_device *dev = memory_alloc(sizeof(struct net_device));
    if (!dev) {
        errorf("memory_alloc() failed");
        return NULL;
    }
    return dev;
}

/* NOTE: must not be called after net_run() */
int net_device_register(struct net_device *dev) {
    static unsigned int index = 0;  // device index

    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    dev->next = devices;  // append
    devices = dev;
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int net_device_open(struct net_device *dev) {
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failed, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;  // up flag
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int net_device_close(struct net_device *dev) {
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("already closed, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failed, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;  // up flag
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst) {
    if (!NET_DEVICE_IS_UP(dev)) {
        // if device is not up, cannot transmit
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("device transmit failed, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev)) {
    struct net_protocol *proto;

    // check duplication
    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }
    // alloc
    proto = memory_alloc(sizeof(*proto));
    if (!proto) {
        errorf("memory_alloc() failed");
        return -1;
    }
    proto->type = type;
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    infof("registered, type=0x%04x", type);
    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev) {
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {  // type matched
            // protect queue begin
            // allocate
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry) {
                errorf("memory_alloc() failed");
                return -1;
            }
            // setting metadata and copy data
            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);
            // push
            queue_push(&proto->queue, entry);

            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu", proto->queue.num, dev->name, type, len);
            debugdump(data, len);
            // software interruption
            intr_raise_irq(INTR_IRQ_SOFTIRQ);
            return 0;
        }
    }
    // unsupported protocol
    return 0;
}

int net_softirq_handler(void) {
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next) {
        while (1) {
            // pop entry from protocol's queue
            entry = queue_pop(&proto->queue);
            if (!entry) {
                break;
            }
            debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zu", proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);
            // call handler
            proto->handler(entry->data, entry->len, entry->dev);
            memory_free(entry);
        }
    }
    return 0;
}

int net_run(void) {
    struct net_device *dev;

    if (intr_run() == -1) {
        errorf("intr_run() failed");
        return -1;
    }

    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("running...");
    return 0;
}

void net_shutdown(void) {
    struct net_device *dev;

    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }
    intr_shutdown();  // terminate interrupt
    debugf("shutting down");
}

int net_init(void) {
    if (intr_init() == -1) {
        errorf("intr_init() failed");
        return -1;
    }
    if (ip_init() == -1) {
        errorf("ip_init() failed");
        return -1;
    }
    infof("initialized");
    return 0;
}