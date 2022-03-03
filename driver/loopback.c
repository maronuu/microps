#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "net.h"
#include "platform.h"
#include "util.h"

#define LOOPBACK_MTU UINT16_MAX
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE + 1)

#define PRIV(x) ((struct loopback *)x->priv)

// private data
struct loopback {
    int irq;
    mutex_t mutex;
    struct queue_head queue;
};

struct loopback_queue_entry {
    uint16_t type;
    size_t len;
    uint8_t data[];  // flexible array member
};

static int loopback_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst) {
    struct loopback_queue_entry *entry;
    unsigned int num;

    // protect queue begin
    mutex_lock(&PRIV(dev)->mutex);
    if (PRIV(dev)->queue.num >= LOOPBACK_QUEUE_LIMIT) {
        // overflow
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("queue is full");
        return -1;
    }
    // prepare entry
    entry = memory_alloc(sizeof(*entry) + len);  // len is for array
    if (!entry) {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("memory_alloc() failed");
        return -1;
    }
    entry->type = type;
    entry->len = len;
    memcpy(entry->data, data, len);
    queue_push(&PRIV(dev)->queue, entry);  // push queue
    num = PRIV(dev)->queue.num;
    mutex_unlock(&PRIV(dev)->mutex);
    // protect queue end
    debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zd", num, dev->name, type, len);
    debugdump(data, len);
    intr_raise_irq(PRIV(dev)->irq);  // raise interruption
    return 0;
}

static int loopback_isr(unsigned int irq, void *id) {
    struct net_device *dev;
    struct loopback_queue_entry *entry;

    dev = (struct net_device *)id;
    // protect queue begin
    mutex_lock(&PRIV(dev)->mutex);
    while (1) {
        entry = queue_pop(&PRIV(dev)->queue);
        if (!entry) {
            // end loop
            break;
        }
        debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd", PRIV(dev)->queue.num, dev->name, entry->type,
               entry->len);
        debugdump(entry->data, entry->len);
        net_input_handler(entry->type, entry->data, entry->len, dev);
        memory_free(entry);  // free memory for the entry
    }
    mutex_unlock(&PRIV(dev)->mutex);
    // protect queue end
    return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

struct net_device *loopback_init(void) {
    struct net_device *dev;
    struct loopback *lo;  // private data

    // device
    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failed");
        return NULL;
    }
    dev->type = NET_DEVICE_FLAG_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;
    dev->ops = &loopback_ops;
    // private data
    lo = memory_alloc(sizeof(*lo));
    if (!lo) {
        errorf("memory_alloc() failed");
        return NULL;
    }
    lo->irq = LOOPBACK_IRQ;
    mutex_init(&lo->mutex);
    queue_init(&lo->queue);
    dev->priv = lo;  // register private data to device

    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failed");
        return NULL;
    }
    intr_request_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name, dev);

    debugf("initialized, dev=%s", dev->name);
    return dev;
}