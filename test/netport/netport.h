#pragma once


#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <Windows.h>
#include <inaddr.h>
#include <in6addr.h>
#include <netiodef.h>
#include <iphlpapi.h>
#include <string>

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
        
const int kMacAddrLength = 18;
const UINT16 kDefaultUDPTTL = 128;
const UINT16 kDefaultDstPort = 1234;
const UINT16 kDefaultSrcPort = 4321;

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

    typedef struct _MTU_HDR_V4 {
        ETHERNET_HEADER EthHeader;
        IPV4_HEADER     IpHeader;
        UDP_HDR         UdpHeader;
    }MTU_HDR_V4;

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
            _Out_ VOID* Buffer,
            _Inout_ UINT32* BufferSize,
            _In_ CONST UCHAR* Payload,
            _In_ UINT16 PayloadLength,
            _In_ CONST ETHERNET_ADDRESS* EthernetDestination,
            _In_ CONST ETHERNET_ADDRESS* EthernetSource,
            _In_ ADDRESS_FAMILY AddressFamily,
            _In_ CONST VOID* IpDestination,
            _In_ CONST VOID* IpSource,
            _In_ UINT16 PortDestination,
            _In_ UINT16 PortSource,
            _In_ const UINT8 ttl
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
            IpHeader->TimeToLive = ttl;
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
            IpHeader->HopLimit = ttl;
            AddressLength = sizeof(IN6_ADDR);
            RtlCopyMemory(&IpHeader->SourceAddress, IpSource, AddressLength);
            RtlCopyMemory(&IpHeader->DestinationAddress, IpDestination, AddressLength);

            Buffer = IpHeader + 1;
        }

        UDP_HDR* UdpHeader = (UDP_HDR*)Buffer;
        UdpHeader->uh_sport = htons(PortSource);
        UdpHeader->uh_dport = htons(PortDestination);
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

    UCHAR
        HexToBin(
            _In_ CHAR Char
        );

    VOID
        HexStringToByte(
            _Inout_ UCHAR* Buffer,
            _In_ UINT32 BufferSize,
            _In_opt_z_ const CHAR* Hex
        );
	VOID ByteToHexString(
        _In_ const UCHAR* bytes, 
        _In_ const size_t length, 
        _Out_ CHAR* out_buffer, 
        _In_ const size_t buffer_size) ;

class NicAdapter {
    private:
        INT ifindex;
        UINT32 mtu;
        UINT32 group;
        UINT32 node;
        UINT64 cpuAffinity;
        ADDRESS_FAMILY addressFamily;
        // Remote value
        INET_ADDR dstIpAddr;
        ETHERNET_ADDRESS dstEthAddr;
        INET_ADDR srcIpAddr;
        ETHERNET_ADDRESS srcEthAddr;
        UINT32 packetSize;

        //BYTE verbDstEthAddr[MAX_ADAPTER_ADDRESS_LENGTH];
        char verbDstEthAddr[kMacAddrLength];
        char verbDstIpAddr[4 * 4];

        //BYTE verbSrcEthAddr[MAX_ADAPTER_ADDRESS_LENGTH];
        char verbSrcEthAddr[kMacAddrLength*2];
        char verbSrcIpAddr[4 * 4];

        UINT16 dstPort;
        UINT16 srcPort;

#ifdef WIN32
        IP_ADAPTER_INFO adapterInfo;
    public:
        BOOL fillAdapterInfo(PIP_ADAPTER_INFO adapterinfo);
#endif
    public:
		// Apis for set src and dst ip and mac
        NicAdapter() : ifindex(-1), mtu(0), group(0), node(0), cpuAffinity(0), addressFamily(AF_INET),
            packetSize(0), dstPort(kDefaultDstPort), srcPort(kDefaultSrcPort) {
            RtlZeroMemory(&dstIpAddr, sizeof(dstIpAddr));
            RtlZeroMemory(&dstEthAddr, sizeof(dstEthAddr));
            RtlZeroMemory(&srcIpAddr, sizeof(srcIpAddr));
            RtlZeroMemory(&srcEthAddr, sizeof(srcEthAddr));
			RtlZeroMemory(&adapterInfo, sizeof(adapterInfo));
            RtlZeroMemory(verbDstEthAddr, sizeof(verbDstEthAddr));
            RtlZeroMemory(verbDstIpAddr, sizeof(verbDstIpAddr));
            RtlZeroMemory(verbSrcEthAddr, sizeof(verbSrcEthAddr));
			RtlZeroMemory(verbSrcIpAddr, sizeof(verbSrcIpAddr));
        }
        INT GetIfindex() {
            return ifindex;
        }
        BOOL InitLocalByIP(const char* ip, const UINT16 port = kDefaultSrcPort);
        BOOL InitLocalByIdx(const UINT32 idx, const UINT16 port = kDefaultSrcPort);
        BOOL AssignLocal(const char* ipaddr, const char* ethaddr, UINT16 port=kDefaultSrcPort);
        
        BOOL SetTarget(const char* ipaddr, const char* ethaddr=NULL, UINT16 port=kDefaultDstPort);

        BOOL MTUFromPayload(const UCHAR* payload, UINT32 payloadlength,
            BYTE* mtuBuffer, UINT32& mtulength,
            const UINT8 ttl= kDefaultUDPTTL);
        BOOL debug_output();

    private:
		// Apis for transfering the string ip/mac to inet_addr and ETHERNET_ADDRESS for generating the udp packet
        BOOL identifyLocal(void);
        BOOL identifyTarget(void);
		// Support APIs for call the windows platform APIs on adapters
        BOOL findAdapterByIP(const char* ipaddr, const UINT16 port);
        BOOL selLocalPort(const UINT16 port);
		// Support APIs for output information
};

VOID* InitUdpPacket(CHAR* srcETH, CHAR* srcIP, UINT16 srcPort, CHAR* dstETH, CHAR* dstIP, UINT16 dstPort, UINT32 PayloadLength, UINT32& bufferLength, const UINT8 ttl=1) ;

#ifdef __cplusplus
} // extern "C"
#endif
