//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#include <assert.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <pathcch.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <vector>
#include <netiodef.h>
#include "helpers.h"

EXTERN_C
bool InitAdapter(DWORD ifIndex) {
    std::vector<char> macaddr(20);
	GetMACAddress(ifIndex, macaddr.data(), macaddr.size());
    return true;
}
//helpers: query the ip and mac via ifindex
EXTERN_C
void GetMACAddress(DWORD ifIndex, char* macAddr, size_t macAddrSize) {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    DWORD dwStatus = GetAdaptersInfo(adapterInfo, &dwBufLen);

	assert(macAddr);
	assert(macAddrSize >= 18);

    if (dwStatus != ERROR_SUCCESS) {
        strcpy_s(macAddr, macAddrSize, "Error getting adapter info");
        return;
    }

    PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
    while (pAdapterInfo) {
        if (pAdapterInfo->Index == ifIndex) {
            snprintf(macAddr, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                pAdapterInfo->Address[0], pAdapterInfo->Address[1],
                pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
            return;
        }
        pAdapterInfo = pAdapterInfo->Next;
    }
    strcpy_s(macAddr, macAddrSize, "MAC not found");
}

EXTERN_C
void GetIPAddress(DWORD ifIndex, char* ipAddr, size_t ipAddrSize) {
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG family = AF_UNSPEC;
	
	assert(ipAddr);
    assert(ipAddrSize >= 15);

    GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

    if (GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->IfIndex == ifIndex) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                while (pUnicast) {
                    getnameinfo(pUnicast->Address.lpSockaddr, pUnicast->Address.iSockaddrLength, ipAddr, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);
                    free(pAddresses);
                    return;
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    free(pAddresses);
    strcpy_s(ipAddr, ipAddrSize, "IP not found");
}

/*
EXTERN_C
void GetAdapterMeta(_In_ DWORD ifIndex,
	_Out_ AdapterMeta* adapterMeta) {

}*/
//-helpers: query the ip and mac via ifindex
