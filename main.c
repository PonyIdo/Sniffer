#include <stdio.h>
#include "packetdata.h"
#include "skbFuncs.h"

int main(){
    PacketData *packetDataPtr;
    getPacket_protocol(packetDataPtr);
    return 0;
}