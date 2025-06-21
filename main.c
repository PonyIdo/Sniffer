#include <stdio.h>
#include "skbFuncs.h"

int main(){
    unsigned char ch = 'h';
    unsigned char *head = &ch;
    uint16_t transport_header = 1;
    uint16_t network_header = 1;
    unsigned int len = 1;
    SK_Buff skbuff = {head, transport_header, network_header, len};//pony give me
    SK_Buff *skbuffptr = &skbuff;
    getPacket_protocol(skbuffptr);
    return 0;
}