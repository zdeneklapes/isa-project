//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#ifndef RECEIVER_RECEIVER_IMPLEMENTATION_H_
#define RECEIVER_RECEIVER_IMPLEMENTATION_H_

/******************************************************************************/
/**                             INCLUDES                                     **/
/******************************************************************************/
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../common/argument_parser.h"
#include "../common/base32.h"
#include "../common/dns_helper.h"
#include "../common/initializations.h"
#include "arpa/inet.h"
#include "dns_receiver_events.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                FUNCTIONS DECLARATION                     **/
/******************************************************************************/
/**
 * Check if packet was already once processed
 * @param program program_t
 * @return true if packet was already processed
 */
bool is_resending_packet(program_t *program);

/**
 * @param program program_t
 * @return Return true if packet is resend or bad base host, false otherwise
 */
bool is_resend_or_badbasehost_packet_type(program_t *program);

/**
 * Check if base_host is same as we get from cli arguments
 * @param args
 * @param qname_chunks
 * @return
 */
bool is_base_host_correct(program_t *program, char *base_host);

/**
 * Write data to file
 * @param program
 * @param data
 */
void write_content(program_t *program, char *data);

/**
 * Create all directories needed for file
 * @param filepath
 */
void create_filepath(program_t *program);

/**
 * Process filename packet
 * @param program
 */
void process_filename_packet(program_t *program);

/**
 * Process last (END) datagram and reinit dns_datagram_t
 * @param program
 */
void process_info_end_packet(program_t *program);

/**
 * Process DATA datagram and append data into file
 * @param program
 */
void process_sending_packet(program_t *program);

/**
 * Process info packet
 * @param program
 */
void process_info_data_packet(program_t *program);

/**
 * Bad base host packet or resend packet
 * @param program
 * @return
 */
bool is_badbasehost_or_resending(program_t *program);

/**
 * Set packet type into struct dns_datagram_t
 * @param program
 */
void set_packet_type(program_t *program);

/**
 * Process whole datagram
 * @param program
 */
void process_question(program_t *program);

/**
 * Prepare datagram answer to answer the question, not used if datagram was resend
 * @param dgram
 */
void prepare_answer(dns_datagram_t *dgram);

/**
 * Receiving packet + Procesing + Sending answers (Router)
 * @param program
 */
void receive_packets(program_t *program);

#endif  // RECEIVER_RECEIVER_IMPLEMENTATION_H_
