#include "netport.h"
#include "internal_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


BOOLEAN logVerbose = FALSE;
BOOLEAN largePages = FALSE;
UINT16 udpDestPort = DEFAULT_UDP_DEST_PORT;
const uint16_t MAX_IP_LEN = 16;

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
        //printf("VLAN packet\n");
        break;
    case 0x0806:
        //printf("ARP packet\n");
        break;
    case 0x86DD:
        //printf("IPv6 packet\n");
        break;
    case 0x0800:
        //printf("IPv4 packet\n");
        ip = (IPV4_HEADER*)(EthernetHeader + 1);
        break;
    }

    if (ip != NULL) {
        //printf("IP Address : %s -> %s\n", inet_ntoa(ip->SourceAddress), inet_ntoa(ip->DestinationAddress));
        switch (ip->Protocol) {
        case IPPROTO_UDP:
        {
            UINT16* port = (UINT16*)(ip + 1);
            printf("Port %d -> %d\n", ntohs(port[0]), ntohs(port[1]));
            break;
        }
        default:
            //printf("Protocol %d\n", ip->Protocol);
            break;
        }
    }
    else {
        //printf("Invalid ip header\n");
    }
    return;
}


int is_valid_ip(const char* ip) {
    int num, dots = 0;
    char ip_copy[MAX_IP_LEN];
    char* context = NULL;


    if (strncpy_s(ip_copy, sizeof(ip_copy), ip, _TRUNCATE) != 0) {
        return 0;
    }

    char* ptr = strtok_s(ip_copy, ".", &context);
    while (ptr) {
        if (!isdigit(*ptr)) return 0;
        num = atoi(ptr);
        if (num < 0 || num > 255) return 0;
        ptr = strtok_s(NULL, ".", &context);
        dots++;
    }
    return dots == 4;
}

bool parseAddress(const char* input, char* ip_out, int& port_out) {
    char buffer[64];
    if (strncpy_s(buffer, sizeof(buffer), input, _TRUNCATE) != 0) {
        printf("Failed to copy\n");
        return false;
    }

    char* colon = strchr(buffer, ':');
    if (!colon) {
        printf("Missing : as separator\n");
        return false;
    }

    *colon = '\0';
    const char* ip = buffer;
    const char* port_str = colon + 1;

    if (!is_valid_ip(ip)) {
        printf("Invalid ip\n");
        return false;
    }

    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        printf("Invalid port\n");
        return false;
    }

    if (strncpy_s(ip_out, MAX_IP_LEN, ip, _TRUNCATE) != 0) {
        printf("Failed to copy IP\n");
        return false;
    }

    port_out = port;
    return true;
}
