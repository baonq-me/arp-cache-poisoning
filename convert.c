/*
 *  $Id: convert.c, v1.0 19/11/2016 12:29:09 quocbao Exp $
 *
 *  convert.c - function prototypes
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
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "structures.h"
#include "const.h"
#include "convert.h"


uint16_t calcChecksum(uint8_t* addr, uint16_t count)
{
    /* Compute Internet Checksum for "count" bytes
    *         beginning at location "addr".
    */
    register unsigned long sum = 0;

    while (count > 1)
    {
        /*  This is the inner loop */
        sum += (unsigned short)*addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}


int exec(char* command, char* output, int buffsize)
{
    FILE* fp = popen(command, "r");

    if (fp == NULL)
		return EXIT_FAILURE;
	else if (output == NULL)
	{
        pclose(fp);
        return EXIT_SUCCESS;
	}

    char* line = (char*)malloc(buffsize);
    output[0] = '\0';

    while (fgets(line, buffsize, fp) != NULL)
		if (buffsize - strlen(output) + 1 > strlen(line))
			strcat(output, line);
		else break;
	free(line);
	pclose(fp);


    uint32_t len = strlen(output);
    if (len > 0)
	{
		while (output[len-1] == '\n' || output[len-1] == ' ')
		{
			output[len-1] = '\0';
			len--;
		}
		return EXIT_SUCCESS;
	} else
		return EXIT_FAILURE;
}


void ether_ntoa_z(const uint8_t *addr, char* mac)
{
    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0], addr[1],
            addr[2], addr[3],
            addr[4], addr[5]);
}

int readMyIP(char* device, uint32_t *ip, char* ip_char)
{
	*ip = 0;
	ip_char[0] = '\0';

	if (checkDevice(device) != EXIT_SUCCESS)
        return EXIT_FAILURE;

	char str[BUFFSIZE];

    sprintf(str, "/sbin/ifconfig %s | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'", device);
    int exitcode = exec(str, str, BUFFSIZE);

    if (exitcode != EXIT_SUCCESS)
        return exitcode;

    if (ip_char != NULL)
        strcpy(ip_char, str);

    *ip = libnet_name2addr4(NULL, ip_char, LIBNET_DONT_RESOLVE);

    return EXIT_SUCCESS;
}

int readMyMAC(char* device, uint8_t* mac, char* mac_char)
{
	memset(mac, 0, LENGTH_MAC_ADDRESS);
    mac_char[0] = '\0';

	if (checkDevice(device) != EXIT_SUCCESS)
        return EXIT_FAILURE;

	char str[BUFFSIZE];
    sprintf(str, "cat /sys/class/net/%s/address", device);
    int exitcode = exec(str, str, BUFFSIZE);

    if (exitcode != EXIT_SUCCESS)
        return exitcode;

    if (mac_char != NULL)
        memcpy(mac_char, str, 18);

    if (mac != NULL)
	{
		int length;
		uint8_t* mac_tmp = libnet_hex_aton(str, &length);
		memcpy(mac, mac_tmp, LENGTH_MAC_ADDRESS);
		free(mac_tmp);
	}

    return EXIT_SUCCESS;
}

uint32_t count(char* str, char c)
{
    uint32_t n = 0;
    int i = 0;

    while (str[i] != '\0')
        if (str[i++] == c) n++;

	return n;
}

int checkDevice(char* device)
{
    char command[BUFFSIZE];
    sprintf(command, "ls /sys/class/net | grep -w '%s' >> /dev/null", device);

    return system(command);
}

int readTargetMAC(char* device, char* ip_char, uint8_t* mac, char* mac_char)
{
    memset(mac, 0, LENGTH_MAC_ADDRESS);
    mac_char[0] = '\0';

	if (checkDevice(device) != EXIT_SUCCESS)
        return EXIT_FAILURE;

	char buf[BUFFSIZE] = "";

	// Delete current mac address of given ip in arp table
    sprintf(buf, "arp -d %s -i %s 2> /dev/null", ip_char, device);
    system(buf);

    // Perform 5 ping in 1 sec to update new mac address of ip into arp table
    sprintf(buf, "ping %s -i 0.2 -I %s -c 5 >> /dev/null", ip_char, device);
    system(buf);

    // Wait for mac address to be inserted into arp table
    sleep(TIMEOUT);

    // Read mac address from arp table
    sprintf(buf, "sudo arp -D %s -i %s | grep '%s' | awk '{print $3}' 2> /dev/null", ip_char, device, ip_char);
    int exitcode = exec(buf, buf, BUFFSIZE);

    if (exitcode != EXIT_SUCCESS)
        return exitcode;
	else if (count(buf, ':') != LENGTH_MAC_ADDRESS-1)
		return EXIT_FAILURE;

    if (mac_char != NULL)
        strcpy(mac_char, buf);

    if (mac != NULL)
	{
		int length;
		uint8_t* mac_tmp = libnet_hex_aton(buf, &length);
		memcpy(mac, mac_tmp, LENGTH_MAC_ADDRESS);
		free(mac_tmp);
	}

    return EXIT_SUCCESS;
}

int checkPermission(int info)
{
	uint32_t uid = (uint32_t)getuid();		// returns the real user ID of the calling process.
	uint32_t euid = (uint32_t)geteuid();	// returns the effective user ID of the calling process.

	if (info)
	{
		char str[100];
		snprintf(str, sizeof(str), "getent passwd \"%d\" | cut -d: -f1", uid);			// build command
		exec(str, str, sizeof(str));			// exec command and get output, we reuse str

		printf("Runing under user [%s] with UID = %d and EUID = %d\n", str, uid, euid);
	}

	if ((uid > 0) && (uid == euid))
	{
		if (info)
			printf("You need to run this program under root account !\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
