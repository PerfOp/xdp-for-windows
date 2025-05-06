//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

//#include <Windows.h>
#include <assert.h>
#include <stdlib.h>
//helpers: query the ip and mac via ifindex
#include <winsock2.h>
//-helpers: query the ip and mac via ifindex
#include <iphlpapi.h>
#include <pathcch.h>
#include <stdio.h>
//helpers: query the ip and mac via ifindex
#include <ws2tcpip.h>
//-helpers: query the ip and mac via ifindex
#include <vector>
#include <netiodef.h>
#include "helpers.h"

typedef struct _ETH_HEADER {
	UCHAR Destination[6];
	UCHAR Source[6];
	USHORT EthType;
} ETH_HEADER, * PETH_HEADER;


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

EXTERN_C
void PrintPacketMeta(void* buffer) {
	ETH_HEADER* pEthHdr =
		(ETH_HEADER*)buffer;
	UINT16 ethType = ntohs(pEthHdr->EthType);
	printf("Consuming RX entry:{mac address: %02X:%02X:%02X:%02X:%02X:%02X}\n",
		pEthHdr->Source[0],
		pEthHdr->Source[1],
		pEthHdr->Source[2],
		pEthHdr->Source[3],
		pEthHdr->Source[4],
		pEthHdr->Source[5]
	);
	struct iphdr* ip = NULL;
	switch (ethType) {
	case 0x8100:
		printf("Consuming RX as VLAN packet\n");
		break;
	case 0x0806:
		printf("Consuming RX as ARP packet\n");
		break;
	case 0x86DD:
		printf("Consuming RX as IPv6 packet\n");
		break;
	case 0x0800:
		printf("Consuming RX as IPv4 packet\n");
		ip = (struct iphdr*)(pEthHdr + 1);
		break;
	}

	if (ip != NULL) {
		UINT32 srcip = ntohl(ip->saddr);
		printf("Consuming RX as IP packet {ip src: %d.%d.%d.%d}\n",
			(srcip >> 24) & 0xFF,
			(srcip >> 16) & 0xFF,
			(srcip >> 8) & 0xFF,
			srcip & 0xFF);
		switch (ip->protocol) {
		case IPPROTO_UDP:
		{
			UINT16* port = (UINT16*)(ip + 1);
			printf("UDP src port %d\n", ntohs(port[0]));
			//printf("UDP dst port %d\n", ntohs(port[1]));
			break;
		}
		default:
			printf("Protocol %d\n", ip->protocol);
			break;
		}
	}
	else {
		printf("Invalid ip header\n");
	}
	return;
}
//-helpers: query the ip and mac via ifindex
