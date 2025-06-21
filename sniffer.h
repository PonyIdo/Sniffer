#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>
#include <linux/netfilter.h>

// The major device number.
// We don't rely on dynamic registration
// any more. We want ioctls to know this
// number at compile time.
//#define MAJOR_NUM 244
#define MAJOR_NUM 235

// Set the message of the device driver
//#define MSG_SLOT_CHANNEL _IOW(MAJOR_NUM, 0, unsigned long)
//#define MSG_SLOT_SET_CEN _IOW(MAJOR_NUM, 1, unsigned long)

#define DEVICE_RANGE_NAME "slot_dev"
#define SUCCESS 0





#endif
