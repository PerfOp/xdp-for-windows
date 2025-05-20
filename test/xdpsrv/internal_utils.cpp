#include "netport.h"
#include "internal_utils.h"
#include <stdio.h>

BOOLEAN verbose = FALSE;
BOOLEAN largePages = FALSE;
UINT16 udpDestPort = DEFAULT_UDP_DEST_PORT;

/*
INT64
QpcToUs64(
    INT64 Qpc,
    INT64 QpcFrequency
)
{
    //
    // Multiply by a big number (1000000, to convert seconds to microseconds)
    // and divide by a big number (QpcFrequency, to convert counts to secs).
    //
    // Avoid overflow with separate multiplication/division of the high and low
    // bits.
    //
    // Taken from QuicTimePlatToUs64 (https://github.com/microsoft/msquic).
    //
    UINT64 High = (Qpc >> 32) * 1000000;
    UINT64 Low = (Qpc & MAXUINT32) * 1000000;
    return
        ((High / QpcFrequency) << 32) +
        ((Low + ((High % QpcFrequency) << 32)) / QpcFrequency);
}
*/

void PrintPacketMeta(_In_ void* buffer) {
    ETHERNET_HEADER* EthernetHeader = (ETHERNET_HEADER*)buffer;
    UINT16 ethType = ntohs(EthernetHeader->Type);
    printf("Parsing packet mac address: %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n",
        EthernetHeader->Source.Byte[0],
        EthernetHeader->Source.Byte[1],
        EthernetHeader->Source.Byte[2],
        EthernetHeader->Source.Byte[3],
        EthernetHeader->Source.Byte[4],
        EthernetHeader->Source.Byte[5],
        EthernetHeader->Destination.Byte[0],
        EthernetHeader->Destination.Byte[1],
        EthernetHeader->Destination.Byte[2],
        EthernetHeader->Destination.Byte[3],
        EthernetHeader->Destination.Byte[4],
        EthernetHeader->Destination.Byte[5]
    );
    IPV4_HEADER* ip = NULL;
    switch (ethType) {
    case 0x8100:
        printf("VLAN packet\n");
        break;
    case 0x0806:
        printf("ARP packet\n");
        break;
    case 0x86DD:
        printf("IPv6 packet\n");
        break;
    case 0x0800:
        printf("IPv4 packet\n");
        ip = (IPV4_HEADER*)(EthernetHeader + 1);
        break;
    }

    if (ip != NULL) {
        printf("IP Address : %s -> %s\n", inet_ntoa(ip->SourceAddress), inet_ntoa(ip->DestinationAddress));
        switch (ip->Protocol) {
        case IPPROTO_UDP:
        {
            UINT16* port = (UINT16*)(ip + 1);
            printf("Port %d -> %d\n", ntohs(port[0]), ntohs(port[1]));
            break;
        }
        default:
            //printf("Protocol %d\n", ip->protocol);
            printf("Protocol %d\n", ip->Protocol);
            break;
        }
    }
    else {
        printf("Invalid ip header\n");
    }
    return;
}
