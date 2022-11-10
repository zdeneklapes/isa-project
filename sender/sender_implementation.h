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
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/dns_helper.h"
#include "../common/initializations.h"
#include "dns_sender_events.h"

/******************************************************************************/
/**                                FUNCTION DECLARATION                      **/
/******************************************************************************/
/**
 * Set part of file data into qname
 *
 * @param program program_t
 */
void set_file_data(program_t *program);

/**
 * Encode data into qname
 *
 * @param program program_t
 */
void encode_data_in_qname_into_qname(program_t *program);

/**
 * Set qname into dns_datagram_t for file info
 *
 * @param program program_t
 */
void set_qname_filename_packet(program_t *program);

/**
 * Set qname into dns_datagram_t for data
 *
 * @param program program_t
 */
void set_qname_sending_packet(program_t *program);

/**
 * Set qname into dns_datagram_t for end of file
 *
 * @param program program_t
 * @param info char*
 */
void set_info_packet(program_t *program, char *info);

/**
 * Set qname into dns_datagram_t based on type of packet call other function
 * qname creation
 *
 * @param program program_t
 */
void set_qname_based_on_packet_type(program_t *program);

/**
 * Send dns_datagram to server
 * @param program
 */
void send_packet(program_t *program);

/**
 * Create dns_datagram_t packet for sending
 * @param program
 */
void prepare_question(program_t *program);

/**
 * Function that prepare and send Info packets
 * @param program
 * @param type
 */
void send_info_packet(program_t *program, enum PACKET_TYPE type);

/**
 * Function that prepare and send Data packets
 * @param program
 */
void send_filename_packet(program_t *program, enum PACKET_TYPE type);

/**
 * Function that prepare and send filename packets
 * @param program
 */
void send_sending_packet(program_t *program, enum PACKET_TYPE type);

/**
 * Function that send all packets
 * @param program
 */
void start_sending(program_t *program);

#endif  // SENDER_SENDER_IMPLEMENTATION_H_
