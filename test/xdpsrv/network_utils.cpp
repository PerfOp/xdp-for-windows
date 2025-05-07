#include "network_utils.h"
#include <stdio.h>

void PrintPacketMeta(_In_ void* buffer) {
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
