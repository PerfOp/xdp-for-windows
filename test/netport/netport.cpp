// netport.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include "netport.h"

#include <stdio.h>
#include <stdlib.h>

#include <winternl.h>
#include <WS2tcpip.h>

#pragma warning(push)
#pragma warning(disable: 6001)

// TODO: This is an example of a library function
void fnnetport()
{
}

UCHAR
        HexToBin(
            _In_ CHAR Char
        )
    {
        Char = (CHAR)tolower(Char);

        if (Char >= '0' && Char <= '9') {
            return (UCHAR)(Char - '0');
        }

        if (Char >= 'a' && Char <= 'f') {
            return (UCHAR)(10 + Char - 'a');
        }

        //ASSERT_FRE(!"Invalid hex");
        return 0;
    }

    VOID
        GetDescriptorPattern(
            _Inout_ UCHAR* Buffer,
            _In_ UINT32 BufferSize,
            _In_opt_z_ const CHAR* Hex
        )
    {
        while (Hex != NULL && *Hex != '\0') {
            //ASSERT_FRE(BufferSize > 0);

            *Buffer = HexToBin(*Hex++);
            *Buffer <<= 4;

            //ASSERT_FRE(*Hex != '\0');
            *Buffer |= HexToBin(*Hex++);

            Buffer++;
            BufferSize--;
        }
    }


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

VOID* InitUdpPacket(/*BOOL IsUdp*/CHAR* srcETH, CHAR* srcIP, UINT16 srcPort, CHAR* dstETH, CHAR* dstIP, UINT16 dstPort, UINT32 PayloadLength, UINT32& PacketLength) {
    ETHERNET_ADDRESS EthSrc, EthDst;
    INET_ADDR IpSrc, IpDst;
    UINT16 PortSrc, PortDst;
    ADDRESS_FAMILY Af, AfSrc, AfDst;
    UCHAR* PayloadBuffer = NULL;
    UCHAR* PacketBuffer = NULL;
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
    PayloadBuffer = (UCHAR*)calloc(1, PayloadLength > 0 ? PayloadLength : 1);
    if (PayloadBuffer == NULL) {
        return NULL;
    }

    PacketBuffer = (UCHAR*)malloc(PacketLength);

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

VOID* CreateUdpPacket(
    ADDRESS_FAMILY Af,
    ETHERNET_ADDRESS EthSrc,
    INET_ADDR IpSrc, 
    UINT16 srcPort, 
    ETHERNET_ADDRESS EthDst,
    INET_ADDR IpDst, 
    UINT16 dstPort, 
    UINT32 PayloadLength, 
    UINT32& PacketLength
) {
    UINT16 PortSrc, PortDst;
    UCHAR* PayloadBuffer = NULL;
    UCHAR* PacketBuffer = NULL;
    
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
    PayloadBuffer = (UCHAR*)calloc(1, PayloadLength > 0 ? PayloadLength : 1);
    if (PayloadBuffer == NULL) {
        return NULL;
    }

    PacketBuffer = (UCHAR*)malloc(PacketLength);

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

    return PacketBuffer;
}
       
VOID* AdapterMeta::GenMTUBuffer(const char* payload, UINT32 size) {
    payloadSize = size;
    VOID* buffer=CreateUdpPacket(
		Af,
        srcEthAddr, 
        srcIpAddr, 
        srcPort, 
        dstEthAddr, 
        dstIpAddr, 
        dstPort, 
        payloadSize, 
        packetSize);
    return buffer;
}
        
BOOL AdapterMeta::fillAdapterInfo(PIP_ADAPTER_INFO padapterinfo) {
	ifindex = padapterinfo->Index;
	memcpy(&adapterInfo, padapterinfo, sizeof(IP_ADAPTER_INFO));
	memcpy(verbSrcIpAddr, padapterinfo->IpAddressList.IpAddress.String, sizeof(verbSrcIpAddr));

    sprintf_s(verbSrcEthAddr, 20, "%02X-%02X-%02X-%02X-%02X-%02X",
        padapterinfo->Address[0], padapterinfo->Address[1],
        padapterinfo->Address[2], padapterinfo->Address[3],
        padapterinfo->Address[4], padapterinfo->Address[5]);

    return TRUE;
}

//helpers: query the ip and mac via ifindex
BOOL AdapterMeta::findAdapterByIP(const char* targetIP, const UINT16 srcport) {
    const int ADAPTERNUM = 16;
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)&(adapterInfo);
    IP_ADAPTER_INFO pIpAdapterInfo[ADAPTERNUM];
    unsigned long stSize = sizeof(IP_ADAPTER_INFO) * ADAPTERNUM;

    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        return FALSE;
    }
    PIP_ADAPTER_INFO cur = pIpAdapterInfo;
    while (cur) {
        switch (cur->Type) {
        case MIB_IF_TYPE_OTHER:
            break;
        case MIB_IF_TYPE_ETHERNET:
        {
            IP_ADDR_STRING* pIpAddrString = &(cur->IpAddressList);
            if (strcmp(targetIP, pIpAddrString->IpAddress.String) == 0) {
                fillAdapterInfo(cur);
				srcPort = srcport;
                //memcpy(pAdapterInfo, cur, sizeof(IP_ADAPTER_INFO));

                //printf("ip: %s\n", pIpAddrString->IpAddress.String);
                //printf("mask: %s\n", pIpAddrString->IpMask.String);
                printf("ip: %s\n", verbSrcIpAddr);
                printf("mask: %s\n", pIpAddrString->IpMask.String);
                printf("mac:%s\n", verbSrcEthAddr);
                break;
            }
        }
        break;
        case MIB_IF_TYPE_TOKENRING:
        case MIB_IF_TYPE_FDDI:
        case MIB_IF_TYPE_PPP:
        case MIB_IF_TYPE_LOOPBACK:
        case MIB_IF_TYPE_SLIP:
            break;
        default:
        {
            IP_ADDR_STRING* pIpAddrString = &(cur->IpAddressList);
            printf("ip: %s\n", pIpAddrString->IpAddress.String);
            printf("mask: %s\n", pIpAddrString->IpMask.String);
        }
        break;
        }
        cur = cur->Next;
    }
    printf("Target:%s\n", targetIP);
    return TRUE;
}

BOOL AdapterMeta::InitLocalByIP(const char* ipaddr, const UINT16 port) {
    if (!findAdapterByIP(ipaddr, port)) {
        printf("inet_pton failed\n");
        return FALSE;
    }
    if (inet_pton(AF_INET, adapterInfo.IpAddressList.IpAddress.String, &dstIpAddr.Ipv4) != 1) {
        printf("inet_pton failed\n");
        return FALSE;
    }
    //memcpy(&verbSrcEthAddr, adapterInfo.Address, 6);
    return TRUE;
}

BOOL AdapterMeta::debug_output() {
    printf("ifindex: %d\n", ifindex);
    printf("mtu: %d\n", mtu);
    printf("src IP : %s\n", verbSrcIpAddr);
    printf("dst IP : %s\n", verbDstIpAddr);
    printf("src mac: %s\n", verbSrcEthAddr);
    printf("dst mac: %s\n", verbDstEthAddr);
    return TRUE;
}

BOOL AdapterMeta::AssingLocal(const char* ipaddr, const char* ethaddr, UINT16 port) {
    //const CHAR* Terminator;
	memcpy(verbSrcIpAddr, ipaddr, sizeof(verbSrcIpAddr));

	memset(verbSrcEthAddr, 0, sizeof(verbSrcEthAddr));
	memcpy(verbSrcEthAddr, ethaddr, sizeof(verbSrcEthAddr));
	
    srcPort = port;
    
	if (identifyLocal() == FALSE) {
		return FALSE;
	}
    return TRUE;
}

BOOL AdapterMeta::SetTarget(const char* ipaddr, const char* ethaddr, UINT16 port) {
	memcpy(verbDstIpAddr, ipaddr, sizeof(verbDstIpAddr));
	memcpy(verbDstEthAddr, ethaddr, sizeof(verbDstEthAddr));
    dstPort = port;

    if (!identifyTarget()) {
        return FALSE;
    }

    return TRUE;
}
        
BOOL AdapterMeta::identifyLocal(void) {
    const CHAR* Terminator;
    if (!PktStringToInetAddressA(&srcIpAddr, &Af, verbSrcIpAddr)) {
        return FALSE;
    }

    if (RtlEthernetStringToAddressA(verbSrcEthAddr, &Terminator, (DL_EUI48*)&srcEthAddr)) {
        return FALSE;
    }
    return TRUE;
}

BOOL AdapterMeta::identifyTarget(void) {
    const CHAR* Terminator;
    if (!PktStringToInetAddressA(&dstIpAddr, &Af, verbDstIpAddr)) {
        return FALSE;
    }

    if (RtlEthernetStringToAddressA(verbDstEthAddr, &Terminator, (DL_EUI48*)&dstEthAddr)) {
        return FALSE;
    }
    return TRUE;
}
        
BOOL AdapterMeta::selLocalPort(const UINT16 port) {
	srcPort = port;
    return TRUE;
}

