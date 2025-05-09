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
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);

    IP_ADAPTER_ADDRESSES* adapterAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapterAddresses, &bufferSize) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* adapter = adapterAddresses; adapter != NULL; adapter = adapter->Next) {
            if (adapter->IfIndex == ifIndex || adapter->Ipv6IfIndex == ifIndex) {
                for (IP_ADAPTER_UNICAST_ADDRESS* addr = adapter->FirstUnicastAddress; addr != NULL; addr = addr->Next) {
                    SOCKADDR* sa = addr->Address.lpSockaddr;
                    char ipStr[INET6_ADDRSTRLEN] = { 0 };
                    getnameinfo(sa, (socklen_t)addr->Address.iSockaddrLength, ipStr, sizeof(ipStr), NULL, 0, NI_NUMERICHOST);
                    printf("Interface Index %lu -> IP Address: %s\n", ifIndex, ipStr);
                }
            }
        }
    }
    free(adapterAddresses);

    /*
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
    */
    strcpy_s(ipAddr, ipAddrSize, "IP not found");
}

void FindAdapterByIP(const char* targetIP, VOID* pInfo) {
	const int ADAPTERNUM = 16;
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)pInfo;
	IP_ADAPTER_INFO pIpAdapterInfo[ADAPTERNUM];
    unsigned long stSize = sizeof(IP_ADAPTER_INFO) * ADAPTERNUM;

    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        if (pIpAdapterInfo != NULL) {
            delete[]pIpAdapterInfo;
            return;
        }
    }
    PIP_ADAPTER_INFO cur = pIpAdapterInfo;
    while (cur) {
        switch (cur->Type) {
        case MIB_IF_TYPE_OTHER:
            break;
        case MIB_IF_TYPE_ETHERNET:
        {
            IP_ADDR_STRING* pIpAddrString = &(cur->IpAddressList);
            printf("ip: %s\n", pIpAddrString->IpAddress.String);
            printf("mask: %s\n", pIpAddrString->IpMask.String);
            if (strcmp(targetIP, pIpAddrString->IpAddress.String) == 0) {
				memcpy(pAdapterInfo, cur, sizeof(IP_ADAPTER_INFO));
                char hex[16] = {'0', '1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
                char macStr[18] = {};
                int k = 0;
                for (int j = 0; j < cur->AddressLength; j++) {
                    macStr[k++] = hex[(cur->Address[j] & 0xf0) >> 4];
                    macStr[k++] = hex[cur->Address[j] & 0x0f];
                    macStr[k++] = '-';
                }
                macStr[k - 1] = 0;
                printf("Mac:%s\n", macStr);
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
}


/*
EXTERN_C
void GetAdapterMeta(_In_ DWORD ifIndex,
	_Out_ AdapterMeta* adapterMeta) {

}*/
//-helpers: query the ip and mac via ifindex
