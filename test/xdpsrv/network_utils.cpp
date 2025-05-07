#include "network_utils.h"
#include <stdio.h>

void PrintPacketMeta(_In_ void* buffer) {

	ETHERNET_HEADER* EthernetHeader = (ETHERNET_HEADER*)buffer;
	UINT16 ethType = ntohs(EthernetHeader->Type);
	printf("Consuming RX entry:{mac address: %02X:%02X:%02X:%02X:%02X:%02X}\n",
		EthernetHeader->Source.Byte[0],
		EthernetHeader->Source.Byte[1],
		EthernetHeader->Source.Byte[2],
		EthernetHeader->Source.Byte[3],
		EthernetHeader->Source.Byte[4],
		EthernetHeader->Source.Byte[5]
	);
	IPV4_HEADER* ip = NULL;
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
		ip = (IPV4_HEADER*)(EthernetHeader + 1);
		break;
	}

	if (ip != NULL) {
		printf("IP Address : % s\n", inet_ntoa(ip->SourceAddress));
		switch (ip->Protocol){
		case IPPROTO_UDP:
		{
			UINT16* port = (UINT16*)(ip + 1);
			printf("UDP src port %d\n", ntohs(port[0]));
			//printf("UDP dst port %d\n", ntohs(port[1]));
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
