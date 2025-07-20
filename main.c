#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "sniffer.h"

#define DEVICE_PATH "/dev/slot_dev"


void set_mode(int fd, unsigned int mode) {
    if (ioctl(fd, SNIFFER_SET_MODE, &mode) < 0) {
        perror("ioctl failed");
        exit(EXIT_FAILURE);
    }
    printf("[+] Set mode to %u\n", mode);
}

int main() {
    int fd = open(DEVICE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return 1;
    }

    unsigned int len = 0;
    uint16_t offset = 0;

    // Mode 0: Get length
    set_mode(fd, READ_MODE_LEN);
    if (read(fd, &len, sizeof(len)) != sizeof(len)) {
        perror("read len failed");
        close(fd);
        return 1;
    }
    printf("[+] Packet length: %u bytes\n", len);

    // Mode 1: Get data
    unsigned char data[len];

    set_mode(fd, READ_MODE_DATA);
    ssize_t read_bytes = read(fd, data, len);
    if (read_bytes != len) {
        perror("read data failed");
        close(fd);
        return 1;
    }

    printf("[+] Packet data");
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Mode 2: Get network offset
    set_mode(fd, READ_MODE_NETWORK_OFFSET);
    ssize_t bytes_read = read(fd, &offset, sizeof(offset));
    if (bytes_read < 0) {
        perror("read network offset failed");
        close(fd);
        return 1;
    }
    if (bytes_read != sizeof(offset)) {
        fprintf(stderr, "read network offset failed: expected %zu, got %zd\n",
                sizeof(offset), bytes_read);
        close(fd);
        return 1;
    }
    printf("[+] Network header offset: %u bytes\n", offset);

    // Mode 3: Get transport offset
    set_mode(fd, READ_MODE_TRANSPORT_OFFSET);
    bytes_read = read(fd, &offset, sizeof(offset));
    if (bytes_read < 0) {
        perror("read transport offset failed");
        close(fd);
        return 1;
    }
    if (bytes_read != sizeof(offset)) {
        fprintf(stderr, "read transport offset failed: expected %zu, got %zd\n",
                sizeof(offset), bytes_read);
        close(fd);
        return 1;
    }
    printf("[+] Transport header offset: %u bytes\n", offset);

    close(fd);
    return 0;
}
