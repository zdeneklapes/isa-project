//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#ifndef SENDER_SENDER_IMPLEMENTATION_H_
#define SENDER_SENDER_IMPLEMENTATION_H_

/******************************************************************************/
/**                                 TODO                                     **/
/******************************************************************************/

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include <netinet/in.h>
#include <sys/stat.h>

#include "../common/base32.h"
#include "../common/dns_helper.h"
#include "dns_sender_events.h"
#include "errno.h"
#include "getopt.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                FUNCTION DECLARATION                      **/
/******************************************************************************/
/**
 * Print help message
 */
void usage();

/**
 * Retrieve dns server from system /etc.resolv.conf
 * @param args
 * @return true if was successful else false
 */
bool get_dns_servers_from_system(args_t *args);

/**
 * Get encoded qname right dns name format
 * @param args
 * @param qname
 * @param dgram
 * @return Length of qname
 */
size_t get_qname_dns_name_format(program_t *program);

/**
 * Get next chunk data from file
 * @param args
 * @param qname_data
 * @param dgram
 */
void get_file_data(const args_t *args, u_char *qname_data, dns_datagram_t *dgram);

/**
 * Prepare qname
 * @param args
 * @param qname_data
 * @param dgram
 */
void prepare_qname(program_t *program, unsigned char qname[]);

/**
 * Prepare datagram question
 * @param args
 * @param dgram
 */
void prepare_question(program_t *program);

/**
 * Send datagram packet
 * @param args
 * @param dgram
 */
void send_packet(program_t *program);

/**
 * Prepare packet and send it
 * @param args
 * @param dgram
 */
void prepare_and_send_packet(program_t *program);

/**
 * Start sending packets based on packet_type
 * @param program
 */
void start_sending(program_t *program);

#endif  // SENDER_SENDER_IMPLEMENTATION_H_
