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
    UCHAR* PayloadBuffer = NULL;
    UCHAR* PacketBuffer = NULL;
    UINT32 PacketLength;
    UINT16 PayloadLength = 64;
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

BOOL AdapterMeta::getLocalByIP(const char* ipStr) {
    if (!FindAdapterByIP(ipStr, &adapterInfo)) {
        printf("inet_pton failed\n");
        return FALSE;
    }
    if (inet_pton(AF_INET, adapterInfo.IpAddressList.IpAddress.String, &netAddr.Ipv4) != 1) {
        printf("inet_pton failed\n");
        return FALSE;
    }
    memcpy(&ethAddr, adapterInfo.Address, 6);
    return TRUE;
}

BOOL AdapterMeta::debug_output() {
    printf("ifindex: %d\n", ifindex);
    printf("mtu: %d\n", mtu);
    printf("group: %d\n", group);
    printf("node: %d\n", node);
    printf("cpuAffinity: %I64x\n", cpuAffinity);
    return TRUE;
}

BOOL AdapterMeta::setValue(const char* targetIp, const char* targetMac, UINT16 dstPort) {
    const CHAR* Terminator;
    //PktStringToInetAddressA

    if (!PktStringToInetAddressA(&netAddr, &Af, targetIp)) {
        return FALSE;
    }

    if (RtlEthernetStringToAddressA(targetMac, &Terminator, (DL_EUI48*)&ethAddr)) {
        return FALSE;
    }

    port = ntohs(dstPort);
    return TRUE;
}

//helpers: query the ip and mac via ifindex
BOOL FindAdapterByIP(const char* targetIP, VOID* pInfo) {
    const int ADAPTERNUM = 16;
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)pInfo;
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
                memcpy(pAdapterInfo, cur, sizeof(IP_ADAPTER_INFO));
                printf("ip: %s\n", pIpAddrString->IpAddress.String);
                printf("mask: %s\n", pIpAddrString->IpMask.String);
                char macAddr[20] = { 0 };
                sprintf_s(macAddr, 20, "%02X:%02X:%02X:%02X:%02X:%02X",
                    cur->Address[0], cur->Address[1],
                    cur->Address[2], cur->Address[3],
                    cur->Address[4], cur->Address[5]);
                printf("mac:%s\n", macAddr);
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
