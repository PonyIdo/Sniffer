#include <stdint.h>

#ifndef SKBUFF_H
#define SKBUFF_H 

typedef struct {
    unsigned char *head;
    uint16_t transport_header;
    uint16_t network_header;
    unsigned int len;
} SK_Buff;

#endif