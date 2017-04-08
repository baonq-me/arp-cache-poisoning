/*
 *  $Id: structures.h, v1.0 19/11/2016 12:35:12 quocbao Exp $
 *
 *  structures.h - constant definition
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

#ifndef _STRUCTURES_H_
#define _STRUCTURES_H_

/**
 * @file strucures.h
 * @brief DA2 strucures declaration
 */

/* In x86/x86_64 architecture, compiler will add a padding in struct
 * to fit */
#pragma pack(1)

#include "const.h"


/*
  +--------------------+-----------------+
  |       802.2        |    Data link    |
  +--------------------+                 +
  |     802.11 MAC     |      layer      |
  +------+------+------+-----------------+
  |  FH  |  DS  |  IR  |  Physical layer |
  +------+------+------+-----------------+
*/
/* SNAP LLC header format of 802.2 standard */
struct snap_header
{
	uint8_t dsap;
	uint8_t ssap;
	uint8_t ctl;
	uint16_t org;
	uint8_t org2;
	uint16_t ether_type;          /* ethernet type */
};

/* RadioTap is the standard for 802.11 reception/transmission/injection */
struct radiotap_header
{
	uint8_t it_rev;			/* Revision: Version of RadioTap */
	uint8_t it_pad;			/* Padding: 0 - Aligns the fields onto natural word boundaries */
	uint16_t it_len;		/* Length: 26 - entire length of RadioTap header */
};

/* RadioTap is the standard for 802.11 reception/transmission/injection */
struct ieee80211_radiotap_header
{
	uint8_t it_version;      /* set to 0 */
	uint8_t it_pad;
	uint16_t it_len;         /* entire length */
	uint32_t it_present;     /* fields present */
};



/* IP header (network layer) */
struct ip_header
{
    uint8_t ip_vhl;			/* version << 4 | header length >> 2 */
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;		/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_foff;		/* fragment offset field and flag*/
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* fragment flag */
#define IP_MF 0x2000	  	/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;		/* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; 	/* source and dest address */
};


/* TCP header (transport layer) */
struct tcp_header
{
    uint16_t sport;			/* source port */
    uint16_t dport;			/* destination port */
    uint32_t seq;			/* sequence number */
    uint32_t ack;			/* acknowledgement number */
    uint16_t offflag;		/* data offset & flag */
    uint16_t win;			/* window */
    uint16_t checksum;		/* checksum */
    uint16_t urg;			/* urgent pointer */
};

/* Libnet handler   */
struct LibnetHandler
{
    libnet_t *link;						/* Libnet handler work in datalink layer (layer 2) */
    libnet_t *raw4;						/* Libnet handler work in transport layer (layer 4) with IPv4 */
    libnet_t *raw6;						/* Libnet handler work in transport layer (layer 4) with IPv6 */
    char errbuf[LIBNET_ERRBUF_SIZE];	/* Error buffer */
};

/* Pcap handler */
struct PcapHandler
{
    pcap_t* p;						/* Pcap handler */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error buffer */
};

/* Struct that define an computer with internet address and ethernet address */
struct Computer
{
    struct in_addr ip;          /* internet address in octet-format */
    struct ether_addr mac;		/* ethernet address in octet-format */

    // Just for debugging purpose
    char ip_char[IP_BIND_ADDRESS_NO_PORT];	/* internet address in string-format */
    char mac_char[18];						/* ethernet address in string-format */
};

/* Struct that define a network with three computers: attacker's and victims' */
struct Network
{
    struct Computer c1;				/* Infomation about victim1 */
    struct Computer c2;				/* Infomation about victim2 */
    struct Computer c;				/* Infomation about attacker */
    char device[BUFFSIZE];			/* Name of the ethernet/wireless adapter that hacker used to connect to the network */
};

/* Struct that manage a ethernet header (in data link layer) */
struct EthernetHeader
{
    struct ether_header* header;    /* Pointer to ethernet header context  */
    uint32_t size;					/* Size of ethernet header */
};

/* Struct that manage a IP header (in network layer) */
struct IPHeader
{
    struct ip_header* header;		/* Pointer to ip header context  */
    uint32_t size;					/* Size of ethernet header */
};

/* Struct that manage a tcp header (in transport layer) */
struct TCPHeader
{
    struct tcp_header* header;	/* Pointer to tcp header context  */
    uint32_t size;				/* Size of ethernet header */
};

/* Struct that manage a payload in general */
struct Payload
{
    uint8_t* data;				/* Pointer to payload context */
    uint32_t size;				/* Size of the payload */
};

/* Struct that include some headers in some layer of a packet */
struct Packet
{
	struct EthernetHeader ethernet;		/* Ethernet header in datalink layer */
    struct IPHeader ip;					/* IP header in network layer */
    struct TCPHeader tcp;				/* TCP header in transport layer */
    struct Payload payload;				/* Payload data */
};

/* Struct that define a singly linked linear list to do memory management job */
struct AllocAddr
{
    void* addr;
    struct AllocAddr* next;
};

#endif     /* _STRUCTURES_H_ */

/* EOF */
