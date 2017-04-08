/*
 *  $Id: convert.h, v1.0 19/11/2016 12:29:09 quocbao Exp $
 *
 *  convert.h - function prototypes
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

#ifndef _CONVERT_H_
#define _CONVERT_H_

/**
 * @file convert.h
 * @brief DA2 function prototypes
 */


#include <net/ethernet.h>
#include "structures.h"

/**
 * Execute a command and take output into a string
 * @param command pointer to the command that will be executed
 * @param output pointer to buffer that store output
 * @param buffsize size of the buffer
 * @return return code of the executed command
 */
int exec(char* command, char* output, int buffsize);

/**
 * Perform a CRC checksum calculation defined by RFC1071, section 4.1
 * Reference: https://tools.ietf.org/html/rfc1071
 * @param addr pointer to data that need to be calculated
 * @param count size of data
 * @return 16bit CRC checksum
 */
uint16_t calcChecksum(uint8_t* addr, uint16_t count);


/**
 * Convert ethernet address from octet-format to string-format
 * @param addr pointer to ethernet address in octet-format
 * @param mac pointer to ethernet address in string-format
 */
void ether_ntoa_z(const uint8_t* addr, char* mac);

/**
 * Get ethernet address from given internet address
 * This function will perform a ping command and read
 * ethernet address in arp table. Dedicated use for Linux Debian
 * because of its folder structure.
 * @param ip pointer to internet address in string-format
 * @param device pointer to device name
 * @param mac pointer to ethernet address that will store the output.
 *        mac need to be allocated first by malloc() or calloc()
 * @return 0 if success, 1 if error
 */
int getMACfromIP(char* ip, char* device, uint8_t* mac);


/**
 * Read host's internet address by using ifconfig
 * @param device name of ethernet/wireless adapter to be used
 * @param ip pointer to 4-byte array that will store internet address
 * @param ip_char pointer to array that will store internet address in string-format
 * @return 0 if success, 0 if error
 */
int readMyIP(char* device, uint32_t *ip, char* ip_char);


/**
 * Read host's ethernet address by reading /sys/class/net/<device>/address
 * @param device name of ethernet/wireless adapter to be used
 * @param ip pointer to 4-byte array that will store ethernet address
 * @param ip_char pointer to array that will store ethernet address in string-format
 * @return 0 if success, 0 if error
 */
int readMyMAC(char* device, uint8_t* mac, char* mac_char);


/**
 * Read target's ethernet address by reading arptable
 * @param device name of ethernet/wireless adapter to be used
 * @param ip pointer to 4-byte array that will store ethernet address
 * @param ip_char pointer to array that will store ethernet address in string-format
 * @return 0 if success, 0 if error
 */
int readTargetMAC(char* device, char* ip_char, uint8_t* mac, char* mac_char);

/**
 * Count the number of occurrence of c in null-terminated string str
 * @param str pointer a null-terminated string
 * @param c character that need to be counted
 * @return number of occurrence
 */
uint32_t count(char* str, char c);

/**
 * Check if given ethernet/wireless adapter is exist
 * @param device name of ethernet/wireless adapter
 * @return 0 if exist, 1 if not
 */
int checkDevice(char* device);


/**
 * Check if program is running under root permission.
 * @param info 1 to print some infomation to stdout, 0 if needn't
 * @return 0 if success, 1 if not
 */
int checkPermission(int info);


#endif /* _CONVERT_H_ */

/* EOF */
