//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#pragma once

#include <Windows.h>
#include <inaddr.h>
#include <in6addr.h>
#include <winsock2.h>
#include <netiodef.h>
#include <iphlpapi.h>

#if defined(_KERNEL_MODE) && !defined(htons)
#define __pkthlp_htons
#define htons RtlUshortByteSwap
#define ntohs RtlUshortByteSwap
#define htonl RtlUlongByteSwap
#define ntohl RtlUlongByteSwap
#endif

#ifndef STATUS_SUCCESS
#define __pkthlp_NTSTATUS
#define STATUS_SUCCESS 0
#endif

typedef DL_EUI48 ETHERNET_ADDRESS;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _UDP_HDR {
    UINT16 uh_sport;
    UINT16 uh_dport;
    UINT16 uh_ulen;
    UINT16 uh_sum;
} UDP_HDR;

typedef union {
    IN_ADDR Ipv4;
    IN6_ADDR Ipv6;
} INET_ADDR;

#define UDP_HEADER_BACKFILL(AddressFamily) \
    (sizeof(ETHERNET_HEADER) + sizeof(UDP_HDR) + \
        ((AddressFamily == AF_INET) ? sizeof(IPV4_HEADER) : sizeof(IPV6_HEADER)))

#define TCP_HEADER_BACKFILL(AddressFamily) \
    (sizeof(ETHERNET_HEADER) + sizeof(TCP_HDR) + \
        ((AddressFamily == AF_INET) ? sizeof(IPV4_HEADER) : sizeof(IPV6_HEADER)))

#define TCP_MAX_OPTION_LEN 40
#define UDP_HEADER_STORAGE UDP_HEADER_BACKFILL(AF_INET6)
#define TCP_HEADER_STORAGE (TCP_HEADER_BACKFILL(AF_INET6) + TCP_MAX_OPTION_LEN)

inline
UINT16
PktChecksumFold(
    _In_ UINT32 Checksum
)
{
    Checksum = (UINT16)Checksum + (Checksum >> 16);
    Checksum = (UINT16)Checksum + (Checksum >> 16);

    return (UINT16)Checksum;
}

inline
UINT16
PktPartialChecksum(
    _In_ CONST VOID* Buffer,
    _In_ UINT16 BufferLength
)
{
    UINT32 Checksum = 0;
    CONST UINT16* Buffer16 = (CONST UINT16*)Buffer;

    while (BufferLength >= sizeof(*Buffer16)) {
        Checksum += *Buffer16++;
        BufferLength -= sizeof(*Buffer16);
    }

    if (BufferLength > 0) {
        Checksum += *(UCHAR*)Buffer16;
    }

    return PktChecksumFold(Checksum);
}

inline
UINT16
PktPseudoHeaderChecksum(
    _In_ CONST VOID* SourceAddress,
    _In_ CONST VOID* DestinationAddress,
    _In_ UINT8 AddressLength,
    _In_ UINT16 DataLength,
    _In_ UINT8 NextHeader
)
{
    UINT32 Checksum = 0;

    Checksum += PktPartialChecksum(SourceAddress, AddressLength);
    Checksum += PktPartialChecksum(DestinationAddress, AddressLength);
    DataLength = htons(DataLength);
    Checksum += PktPartialChecksum(&DataLength, sizeof(DataLength));
    Checksum += (NextHeader << 8);

    return PktChecksumFold(Checksum);
}

inline
UINT16
PktChecksum(
    _In_ UINT16 InitialChecksum,
    _In_ CONST VOID* Buffer,
    _In_ UINT16 BufferLength
)
{
    UINT32 Checksum = InitialChecksum;

    Checksum += PktPartialChecksum(Buffer, BufferLength);

    return ~PktChecksumFold(Checksum);
}

inline
_Success_(return != FALSE)
BOOLEAN
PktBuildUdpFrame(
    _Out_ VOID * Buffer,
    _Inout_ UINT32 * BufferSize,
    _In_ CONST UCHAR * Payload,
    _In_ UINT16 PayloadLength,
    _In_ CONST ETHERNET_ADDRESS * EthernetDestination,
    _In_ CONST ETHERNET_ADDRESS * EthernetSource,
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ CONST VOID * IpDestination,
    _In_ CONST VOID * IpSource,
    _In_ UINT16 PortDestination,
    _In_ UINT16 PortSource
)
{
    CONST UINT32 TotalLength = UDP_HEADER_BACKFILL(AddressFamily) + PayloadLength;
    if (*BufferSize < TotalLength) {
        return FALSE;
    }

    UINT16 UdpLength = sizeof(UDP_HDR) + PayloadLength;
    UINT8 AddressLength;

    ETHERNET_HEADER* EthernetHeader = (ETHERNET_HEADER*)Buffer;
    EthernetHeader->Destination = *EthernetDestination;
    EthernetHeader->Source = *EthernetSource;
    EthernetHeader->Type =
        htons(AddressFamily == AF_INET ? ETHERNET_TYPE_IPV4 : ETHERNET_TYPE_IPV6);
    Buffer = EthernetHeader + 1;

    if (AddressFamily == AF_INET) {
        IPV4_HEADER* IpHeader = (IPV4_HEADER*)Buffer;

        if (UdpLength + (UINT16)sizeof(*IpHeader) < UdpLength) {
            return FALSE;
        }

        RtlZeroMemory(IpHeader, sizeof(*IpHeader));
        IpHeader->Version = IPV4_VERSION;
        IpHeader->HeaderLength = sizeof(*IpHeader) >> 2;
        IpHeader->TotalLength = htons(sizeof(*IpHeader) + UdpLength);
        IpHeader->TimeToLive = 1;
        IpHeader->Protocol = IPPROTO_UDP;
        AddressLength = sizeof(IN_ADDR);
        RtlCopyMemory(&IpHeader->SourceAddress, IpSource, AddressLength);
        RtlCopyMemory(&IpHeader->DestinationAddress, IpDestination, AddressLength);
        IpHeader->HeaderChecksum = PktChecksum(0, IpHeader, sizeof(*IpHeader));

        Buffer = IpHeader + 1;
    }
    else {
        IPV6_HEADER* IpHeader = (IPV6_HEADER*)Buffer;
        RtlZeroMemory(IpHeader, sizeof(*IpHeader));
        IpHeader->VersionClassFlow = IPV6_VERSION;
        IpHeader->PayloadLength = htons(UdpLength);
        IpHeader->NextHeader = IPPROTO_UDP;
        IpHeader->HopLimit = 1;
        AddressLength = sizeof(IN6_ADDR);
        RtlCopyMemory(&IpHeader->SourceAddress, IpSource, AddressLength);
        RtlCopyMemory(&IpHeader->DestinationAddress, IpDestination, AddressLength);

        Buffer = IpHeader + 1;
    }

    UDP_HDR* UdpHeader = (UDP_HDR*)Buffer;
    UdpHeader->uh_sport = PortSource;
    UdpHeader->uh_dport = PortDestination;
    UdpHeader->uh_ulen = htons(UdpLength);
    UdpHeader->uh_sum =
        PktPseudoHeaderChecksum(IpSource, IpDestination, AddressLength, UdpLength, IPPROTO_UDP);

    Buffer = UdpHeader + 1;

    RtlCopyMemory(Buffer, Payload, PayloadLength);
    UdpHeader->uh_sum = PktChecksum(0, UdpHeader, UdpLength);

    if (UdpHeader->uh_sum == 0 && AddressFamily == AF_INET6) {
        //
        // UDPv6 requires a non-zero checksum field.
        //
        UdpHeader->uh_sum = (UINT16)~0;
    }

    *BufferSize = TotalLength;

    return TRUE;
}
/*
struct iphdr {
    unsigned char ihl : 4, version : 4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
    unsigned char res1 : 4, doff : 4;
    unsigned char fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    unsigned short window; //   window size
    unsigned short check; //   tcp checksum
    unsigned short urg_ptr; //   urgent pointer
};
*/

typedef struct SAdapterMeta {
	UINT32 ifindex;
	UINT32 mtu;
	UINT32 group;
	UINT32 node;
	UINT64 cpuAffinity;
    INET_ADDR netAddr;
    ETHERNET_ADDRESS ethAddr;
    ADDRESS_FAMILY Af;
    UINT16 port;
#ifdef WIN32
    IP_ADAPTER_INFO adapterInfo;
#endif
    BOOL setValue(const char* targetIp, const char* targetMac, UINT16 dstPort);
    BOOL getLocalByIP(const char* ipStr);
    BOOL debug_output();
} AdapterMeta;

VOID* InitUdpPacket(/*BOOL IsUdp*/CHAR* srcETH, CHAR* srcIP, UINT16 srcPort, CHAR* dstETH, CHAR* dstIP, UINT16 dstPort);
//void InitLocalAdapter(DWORD ifindex);
BOOL FindAdapterByIP(const char* targetIP, VOID* pInfo) ;
void PrintPacketMeta(_In_ void* buffer);

#ifdef __cplusplus
} // extern "C"
#endif
