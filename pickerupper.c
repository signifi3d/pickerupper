/*
pickerupper
By: signified

Usage: pickerupper MAC [ifname]


Specifically outputs dropped Ethernet frames. Requires rx-fcs and rx-all to be turned on
on your device, and also must be run as root. In order for this to work you need to use
the MAC address of the machine you're receiving frames on as the first argument to 
pickerupper. It's the only time you really get an FCS. The program calculates the FCS
and checks it against what came with the packet. Please only supply a MAC in the 
XX:XX:XX:XX:XX:XX format. I mean, it's up to you if you don't want the program to work,
but I've literally only coded for that situation. If you don't notice anything happening
then it's probably because your card hasn't actually had any packets to drop or your card
doesn't support rx-all. If you're seeing a lot then it's probably because you don't have rx-fcs
on, or your card doesn't support it.

Copyright 2020 signified

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

bool dest_eq(const u_char* pckt, const u_char* addr) {
	for (int i = 0; i < 6; ++i) {
		if ( pckt[i] == addr[i] ) 
			continue;
		else
			return false;
	}
	return true;
}

unsigned int crc32b(const u_char* pckt, int length) {
	int i, j;
	unsigned int byte, crc, mask;

	i = 0;
	crc = 0xFFFFFFFF;
	for (int k = 0; k < length; ++k) {
		byte = pckt[i];
		crc = crc ^ byte;
		for ( j = 7; j >= 0; --j ) {
			mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xEDB88320 & mask);
		}
		i++;
	} 
	return ~crc;
}

bool crc_eq(const u_char* pckt, int length) {
	unsigned int pckt_fcs = 0;
	unsigned int fcs = crc32b(pckt, length-4);
	for (int i = 0; i < 4; ++i) {
		pckt_fcs = pckt_fcs | pckt[length-(1+i)];
		if ( i != 3 )
			pckt_fcs = pckt_fcs << 8;
	}

	return fcs == pckt_fcs;
}

void hexstring_to_address(const char* hexstring, u_char* address) {
	for (int i = 0; i < 17; i += 3) {
		u_char total = 0;
		for (int j = 0; j <= 1; ++j) {
			u_char holder = 0;
			if ( hexstring[i+j] >= 0x30 && hexstring[i+j] <= 0x39 ) {
				holder = hexstring[i+j] - 0x30;
			} else if ( hexstring[i+j] >= 0x41 && hexstring[i+j] <= 0x46 ) {
				holder = (hexstring[i+j] - 0x40) + 9;
			} else if ( hexstring[i+j] >= 0x61 && hexstring[i+j] <= 0x66 ) {
				holder = (hexstring[i+j] - 0x60) + 9;
			}
			if ( j == 0 )
				total += holder * 16;
			else
				total += holder; 
		}
		address[i/3]=total;
	}
}

int main (int argc, char **argv) {

	pcap_t* handle;
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr* hdr;
	const u_char* packet;
	u_char dest[6];
	int e;
	
	if (argc == 1) {
		printf("Usage: pickerupper MAC [ifname]\n");
		exit(1);
	}

	hexstring_to_address(argv[1], dest);
	printf("Scanning all frames received by: ");
	for (int i = 0; i < 6; ++i) {
		printf("%x", dest[i]);
	}
	printf("\n");
	if (argc <= 2)
		dev = pcap_lookupdev(errbuf);
	else 
		dev = argv[2];

	if (dev == NULL) {
		printf("%s\n",errbuf);
		exit(1);
	}
	printf("Device: %s\n", dev);

	handle = pcap_create(dev, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Error occured, couldn't create handle. Is your device valid?\n");
		exit(1);
	}

	if (pcap_activate(handle)) {
		fprintf(stderr, "Couldn't activate handle. Are you running as root?\n");
		pcap_close(handle);
		exit(1);
	} 

	do {
		e = pcap_next_ex(handle, &hdr, &packet);
	
		if ( e != 1 ) {
			if ( e == 0 ) {
				fprintf(stderr, "Buffer timeout expired.\n");
			} else if (e == PCAP_ERROR) {
				fprintf(stderr, "Error occured while reading the packet.\n");
			} else if (e == PCAP_ERROR_BREAK) {
				fprintf(stderr, "No more packets to read.\n");
			} else {
				fprintf(stderr, "Unknown error occured.\n");
			}
			pcap_close(handle);
			exit(1);
		} 
		if (dest_eq(packet, dest) && !crc_eq(packet,hdr->len)) {
			for (int i = 1; i <= hdr->len; ++i) {
				printf("%02x ", packet[i-1]);
				if ( (i % 6 == 0) || i == hdr->len ) {
					printf("\n");
				}
			}
		}
	} while(1);
	pcap_close(handle);

	return 0;
}



