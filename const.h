/*
 *  $Id: const.h, v1.0 19/11/2016 12:32:26 quocbao Exp $
 *
 *  const.h - constant definition
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

#ifndef _CONST_H_
#define _CONST_H_

/**
 * @file const.h
 * @brief DA2 constant definition
 */

#define LENGTH_MAC_ADDRESS		6
#define BUFFSIZE				100

#define DEVICE_MAX_LEN			30		/* Max length in name of an interface (name of wireless/ethernet adapter) */
#define TIMEOUT 				1       /* Timeout between the outgoing of a ARP packet (x3) */
										/* Wait time after sending a ping and wait for arp table to be updated */
#define PCAP_INTERVAL			10      /* Read timeout in milisecond of pcap */
#define PCAP_PROMISCUOUS_MODE	1		/* Set 1 to open pcap in promiscuous mode, 0 to open in normal mode*/

#define PORT_TELNET			23			/* Port of TELNET protocol */
#define PORT_FTP_COMMAND	21			/* Port of FTP protocol in charge of send/recevice FTP command */
#define PORT_FTP_DATA		20			/* Port of FTP protocol in charge of send/recevice data */
#define LOG_TELNET		"telnet.log"	/* Filename that store all TELNET traffic */
#define LOG_FTP			"ftp.log"		/* Filename that store all FTP traffic go through FTP command port 21 */


#define ETH_HEADER_SIZE 		14		/* Size of a ethernet header without 801.1Q tag */
										/* 801.1Q tag is located between ethernet type field and source ethernet address field */
										/* If ethernet type is 0x8100 -> 801.1Q tag (4 octet)
										/* If ethernet type is 0x9100 -> double 801.1Q tag (8 octet) */
										/* STRICTLY USE THIS WITH CAREFULNESS */

// Process for 802.11 network
#define AVS_HEADER_SIZE 		64            /* AVS capture header size */
#define DATA_80211_FRAME_SIZE 	24           /* header for 802.11 data packet */
#define LLC_HEADER_SIZE 		8            /* LLC frame for encapsulation */

/* Direction for using this program */
static const char USAGE[] = "\
Usage: libnet [-d device] [-a target] [-b target]\n\
Example: ./libnet -d eth0 -a 192.168.0.11 -b 192.168.0.22\n\
";

#endif	/* _CONST_H_ */

/* EOF */
