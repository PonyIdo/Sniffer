#include <stdint.h>

#ifndef PACKETDATA_H
#define PACKETDATA_H 

typedef struct {
    unsigned char *head;
    uint16_t transport_header;
    unsigned int len;
} PacketData;

#endif