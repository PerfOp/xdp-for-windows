#include "network_utils.h"
#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>

#include <winternl.h>

#pragma warning(push)
#pragma warning(disable: 6001)

#ifndef _KERNEL_MODE
inline
BOOLEAN
PktStringToInetAddressA(
    _Out_ INET_ADDR* InetAddr,
    _Out_ ADDRESS_FAMILY* AddressFamily,
    _In_ CONST CHAR* String
)
{
    NTSTATUS Status;
    CONST CHAR* Terminator;

    //
    // Attempt to parse the target as an IPv4 literal.
    //
    *AddressFamily = AF_INET;
    Status = RtlIpv4StringToAddressA(String, TRUE, &Terminator, &InetAddr->Ipv4);

    if (Status != STATUS_SUCCESS) {
        //
        // Attempt to parse the target as an IPv6 literal.
        //
        *AddressFamily = AF_INET6;
        Status = RtlIpv6StringToAddressA(String, &Terminator, &InetAddr->Ipv6);

        if (Status != STATUS_SUCCESS) {
            //
            // No luck, bail.
            //
            return FALSE;
        }
    }

    return TRUE;
}
#endif

VOID* InitUdpPacket(/*BOOL IsUdp*/CHAR* srcETH, CHAR* srcIP, UINT16 srcPort, CHAR* dstETH, CHAR* dstIP, UINT16 dstPort) {
    ETHERNET_ADDRESS EthSrc, EthDst;
    INET_ADDR IpSrc, IpDst;
    UINT16 PortSrc, PortDst;
    ADDRESS_FAMILY Af, AfSrc, AfDst;
    UCHAR* PayloadBuffer=NULL;
    UCHAR* PacketBuffer=NULL;
    UINT32 PacketLength;
    UINT16 PayloadLength=64;
    const CHAR* Terminator;

    if (RtlEthernetStringToAddressA(srcETH, &Terminator, (DL_EUI48*)&EthSrc)) {
        return NULL;
    }

    if (RtlEthernetStringToAddressA(dstETH, &Terminator, (DL_EUI48*)&EthDst)) {
        return NULL;
    }

    if (!PktStringToInetAddressA(&IpSrc, &AfSrc, srcIP)) {
        return NULL;
    }

    if (!PktStringToInetAddressA(&IpDst, &AfDst, dstIP)) {
        return NULL;
    }

    if (AfSrc != AfDst) {
        return NULL;
    }

    Af = AfSrc;

    PortSrc = htons(srcPort);
    PortDst = htons(dstPort);

    //if (IsUdp) {
    PacketLength = UDP_HEADER_BACKFILL(Af) + PayloadLength;
    __analysis_assume(PacketLength > UDP_HEADER_BACKFILL(Af));
    /*
    }
    else {
        PacketLength = TCP_HEADER_BACKFILL(Af) + PayloadLength;
        __analysis_assume(PacketLength > TCP_HEADER_BACKFILL(Af));
    }
    */
    PayloadBuffer = (UCHAR*) calloc(1, PayloadLength > 0 ? PayloadLength : 1);
    if (PayloadBuffer == NULL) {
        return NULL;
    }

    PacketBuffer = (UCHAR*) malloc(PacketLength);

    if (PacketBuffer == NULL) {
        return NULL;
    }
    else {
        memset(PacketBuffer, 0, PacketLength);
    }

    //if (IsUdp) {
    if (!PktBuildUdpFrame(
        PacketBuffer, &PacketLength, PayloadBuffer, PayloadLength, &EthDst, &EthSrc, Af, &IpDst, &IpSrc,
        PortDst, PortSrc)) {
        free(PayloadBuffer);
        free(PacketBuffer);
    }
/*
    }

    else {
        if (!PktBuildTcpFrame(
            PacketBuffer, &PacketLength, PayloadBuffer, PayloadLength,
            NULL, 0, 1, 2, TH_SYN | TH_ACK, 4, &EthDst, &EthSrc, Af, &IpDst, &IpSrc,
            PortDst, PortSrc)) {
            Usage("Failed to build the TCP packet");
            Err = 1;
            goto Exit;
        }
    }
*/


    return PacketBuffer;
}

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
        switch (ip->Protocol){
        case IPPROTO_UDP:
        {
            UINT16* port = (UINT16*)(ip + 1);
            printf("Port %d -> %d\n", ntohs(port[0]),ntohs(port[1]));
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
void InitLocalAdapter(DWORD ifindex) {
    char macaddr[18] = { 0 };
    char ipaddr[15] = { 0 };
    GetMACAddress(ifindex, macaddr, 18);
    printf("Mac:%s\n", macaddr);
    GetIPAddress(5, ipaddr, 15);
    printf("IP:%s\n", ipaddr);
    return;
}
