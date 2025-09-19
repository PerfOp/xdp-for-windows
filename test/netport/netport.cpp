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

VOID ByteToHexString(const UCHAR* bytes, const size_t length, CHAR* out_buffer, const size_t buffer_size) {
    size_t offset = 0;
    for (size_t i = 0; i < length && offset < buffer_size - 3; ++i) {
        int written = snprintf(out_buffer + offset, buffer_size - offset, "%02X", bytes[i]);
        if (written < 0 || written >= buffer_size - offset) {
            break;
        }
        offset += written;
    }
    out_buffer[offset] = '\0';
}

// TODO: This is an example of a library function
UCHAR HexToBin(
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

VOID HexStringToByte(
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

HANDLE g_hMapFile = NULL;
void* g_hBuffer = NULL;
LPVOID CreateOrBindMemory(const char* handleName, const size_t size){
    wchar_t wname[256];
    MultiByteToWideChar(CP_ACP, 0, handleName, -1, wname, 256);

    HANDLE g_hMapFile = CreateFileMapping(
        INVALID_HANDLE_VALUE,     
        NULL,                    
        PAGE_READWRITE,         
        0,                     
        size,                 
        wname//L"MySharedMemory"    
    );


    if (g_hMapFile == NULL) {
        printf_error("Create file faiure\n");
    }
    else {
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            printf_error("Attached an exist file handle\n");
        }
        else {
            printf_error("Created a file handle\n");
        }
    }


    g_hBuffer = MapViewOfFile(
        g_hMapFile,           
        FILE_MAP_ALL_ACCESS,
        0, 0, size         
    );

    return g_hBuffer;
}
BOOL ReleaseBondMemory(const char* handleName) {
    if (g_hBuffer != NULL) {
        UnmapViewOfFile(g_hBuffer);
    }
    if (g_hMapFile != NULL) {
        CloseHandle(g_hMapFile);
    }
    return TRUE;
}

#ifndef _KERNEL_MODE
inline BOOLEAN PktStringToInetAddressA(
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

VOID* InitUdpPacket(
        CHAR* srcETH,
        CHAR* srcIP,
        UINT16 srcPort,
        CHAR* dstETH,
        CHAR* dstIP,
        UINT16 dstPort,
        UINT32 PayloadLength,
        UINT32& PacketLength,
        const UINT8 ttl)
{
    ETHERNET_ADDRESS EthSrc, EthDst;
    INET_ADDR IpSrc, IpDst;
    //UINT16 PortSrc, PortDst;
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

    /*
       PortSrc = htons(srcPort);
       PortDst = htons(dstPort);
       */
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
                PacketBuffer, &PacketLength,
                PayloadBuffer, PayloadLength,
                &EthDst, &EthSrc,
                Af,
                &IpDst, &IpSrc,
                dstPort, srcPort,
                ttl)) {
        free(PayloadBuffer);
        free(PacketBuffer);
    }
    /*
       }

       else {
       if (!PktBuildTcpFrame(
       PacketBuffer, &packetLength, PayloadBuffer, PayloadLength,
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

BOOL BuildUdpPacket(
        ADDRESS_FAMILY Af,
        ETHERNET_ADDRESS EthSrc,
        INET_ADDR IpSrc,
        UINT16 srcPort,
        ETHERNET_ADDRESS EthDst,
        INET_ADDR IpDst,
        UINT16 dstPort,
        const UCHAR* payloadBuffer,
        UINT32 payloadLength,
        UCHAR* mtuBuffer,
        UINT32& packetLength,
        const UINT8 ttl
        ) {
    /*
       UINT16 PortSrc, PortDst;

       PortSrc = htons(srcPort);
       PortDst = htons(dstPort);
       */
    //if (IsUdp) {
    packetLength = UDP_HEADER_BACKFILL(Af) + payloadLength;
    __analysis_assume(packetLength > UDP_HEADER_BACKFILL(Af));

    //for (int i = 0; i < 6; i++) {
    //    printf("%X", payloadBuffer[i]);
    //}
    //printf("\n");
    /*
       }
       else {
       PacketLength = TCP_HEADER_BACKFILL(Af) + PayloadLength;
       __analysis_assume(PacketLength > TCP_HEADER_BACKFILL(Af));
       }
       */

    //if (IsUdp)
    if (!PktBuildUdpFrame(
                //PacketBuffer, &PacketLength, PayloadBuffer, PayloadLength, &EthDst, &EthSrc, Af, &IpDst, &IpSrc,
                mtuBuffer, &packetLength, payloadBuffer, payloadLength, &EthDst, &EthSrc, Af, &IpDst, &IpSrc,
                dstPort, srcPort, ttl)) {
        return FALSE;
    }

    return TRUE;
}

BOOL NicAdapter::MTUFromPayload(const UCHAR* payload, UINT32 payloadlength, BYTE* mtuBuffer, UINT32& mtulength, const UINT8 ttl) {
    return BuildUdpPacket(
        addressFamily,
        srcEthAddr,
        srcIpAddr,
        srcPort,
        dstEthAddr,
        dstIpAddr,
        dstPort,
        payload,
        payloadlength,
        mtuBuffer,
        mtulength,
        ttl);
}

BOOL NicAdapter::fillAdapterInfo(PIP_ADAPTER_INFO padapterinfo) {
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
BOOL NicAdapter::findAdapterByIP(const char* targetIP, const UINT16 srcport) {
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

BOOL NicAdapter::InitLocalByIdx(const UINT32 idx, const UINT16 port) {
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufferSize);

    IP_ADAPTER_ADDRESSES* adapterAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapterAddresses, &bufferSize) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* adapter = adapterAddresses; adapter != nullptr; adapter = adapter->Next) {
            if (adapter->IfIndex == idx) {
                //printf("Interface: %s\n", adapter->FriendlyName);
                for (IP_ADAPTER_UNICAST_ADDRESS* addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next) {
                    SOCKADDR_IN* sa_in = (SOCKADDR_IN*)addr->Address.lpSockaddr;
                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, sizeof(ipStr));
                    printf("IPv4 Address: %s\n", ipStr);
                    this->InitLocalByIP(ipStr, port);
                }
                this->ifindex = idx;
                free(adapterAddresses);
                return TRUE;
            }
        }
    }
    printf("No adapter found with index %u, please use an emuratable ifindex\n", idx);
    free(adapterAddresses);

    return FALSE;
}
BOOL NicAdapter::InitLocalByIP(const char* ipaddr, const UINT16 port) {
    if (!findAdapterByIP(ipaddr, port)) {
        printf("Cannot locate the adapter by ip\n");
        return FALSE;
    }
    return identifyLocal();
}

BOOL NicAdapter::debug_output() {
    printf("Debug Output the meta of the Adapter\n");
    printf("ifindex: %d\n", ifindex);
    printf("mtu: %d\n", mtu);
    printf("src IP : %s:%d\n", verbSrcIpAddr, srcPort);
    printf("dst IP : %s:%d\n", verbDstIpAddr, dstPort);
    printf("src mac: %s\n", verbSrcEthAddr);
    printf("dst mac: %s\n", verbDstEthAddr);
    return TRUE;
}

BOOL NicAdapter::AssignLocal(const char* ipaddr, const char* ethaddr, UINT16 port) {
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

BOOL NicAdapter::SetTarget(const char* ipaddr, const char* ethaddr, UINT16 port) {
    memcpy(verbDstIpAddr, ipaddr, sizeof(verbDstIpAddr));
    if (ethaddr != NULL) {
        memcpy(verbDstEthAddr, ethaddr, sizeof(verbDstEthAddr));
    }
    else {
        memcpy(verbDstEthAddr, "12-34-56-78-9A-BC", sizeof(verbDstEthAddr));
    }
    dstPort = port;

    if (!identifyTarget()) {
        return FALSE;
    }

    return TRUE;
}

BOOL NicAdapter::identifyLocal(void) {
    const CHAR* Terminator;
    if (!PktStringToInetAddressA(&srcIpAddr, &addressFamily, verbSrcIpAddr)) {
        return FALSE;
    }

    if (RtlEthernetStringToAddressA(verbSrcEthAddr, &Terminator, (DL_EUI48*)&srcEthAddr)) {
        return FALSE;
    }
    return TRUE;
}

BOOL NicAdapter::identifyTarget(void) {
    const CHAR* Terminator;
    if (!PktStringToInetAddressA(&dstIpAddr, &addressFamily, verbDstIpAddr)) {
        return FALSE;
    }
    if (RtlEthernetStringToAddressA(verbDstEthAddr, &Terminator, (DL_EUI48*)&dstEthAddr)) {
        return FALSE;
    }

    return TRUE;
}

BOOL NicAdapter::selLocalPort(const UINT16 port) {
    srcPort = port;
    return TRUE;
}

