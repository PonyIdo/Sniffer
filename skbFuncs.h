#include "packetdata.h"
#include <netinet/ip.h>

#ifndef SKBFUNCS_H
#define SKBFUNCS_H 


unsigned char getPacket_protocol(PacketData *packetData){
    unsigned char *headptr = packetData->head;
    uint16_t transport_offset = packetData->transport_header;
    unsigned int len = packetData->len;
    

    unsigned char *transport_headerptr = headptr + transport_offset;
    struct iphdr *ip_header = (struct iphdr *)transport_headerptr;
    unsigned char protocol = ip_header->protocol;
    return protocol;
}

#endif