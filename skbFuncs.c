#include "skbFuncs.h"
#include <netinet/ip.h>


unsigned char getPacket_protocol(SK_Buff *skbuff){
    unsigned char *headptr = skbuff->head;
    uint16_t network_offset = skbuff->network_header;
    unsigned char *network_headerptr = headptr + network_offset;
    unsigned int protocol_offset = 9;
    unsigned char *transport_protocolptr = network_headerptr + protocol_offset;
    unsigned char protocol = *transport_protocolptr;
    return protocol;
}

uint16_t getPacket_destination_port(SK_Buff *skbuff){
    unsigned char *headptr = skbuff->head;
    uint16_t transport_offset = skbuff->transport_header;

    unsigned char *transport_headerptr = headptr + transport_offset;
    unsigned int destination_port_offset = 2;
    unsigned char *destination_portptr = transport_headerptr + destination_port_offset;
    uint16_t destination_port = *destination_portptr;
    return destination_port;
}

uint16_t getPacket_source_port(SK_Buff *skbuff){
    unsigned char *headptr = skbuff->head;
    uint16_t transport_offset = skbuff->transport_header;

    unsigned char *transport_headerptr = headptr + transport_offset;
    unsigned int source_port_offset = 0;
    unsigned char *source_portptr = transport_headerptr + source_port_offset;
    uint16_t source_port = *source_portptr;
    return source_port;
}