#include "skbFuncs.h"
#include "skbuff.h"
#include <netinet/ip.h>

unsigned char getPacket_protocol(SK_Buff *skbuff){
    unsigned char *headptr = skbuff->head;
    uint16_t network_offset = skbuff->network_header;
    unsigned int len = skbuff->len;
    

    unsigned char *network_headerptr = headptr + network_offset;
    unsigned int protocol_offset = 72;
    unsigned char *transport_protocolptr = network_headerptr + protocol_offset;
    unsigned char protocol = *transport_protocolptr;
    return protocol;
}