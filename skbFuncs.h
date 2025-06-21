#ifndef SKBFUNCS_H
#define SKBFUNCS_H 

#include <stdint.h>
#include "skbuff.h"

unsigned char getPacket_protocol(SK_Buff *skbuff);

uint16_t getPacket_destination_port(SK_Buff *skbuff);
uint16_t getPacket_source_port(SK_Buff *skbuff);
#endif
