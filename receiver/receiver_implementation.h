//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#ifndef RECEIVER_RECEIVER_IMPLEMENTATION_H_
#define RECEIVER_RECEIVER_IMPLEMENTATION_H_

/******************************************************************************/
/**                              TODO                                        **/
/******************************************************************************/
// TODO: Check if file exists
// TODO: Allocate args_t on heap
// TODO: receiver check path of filepath and create it
// TODO: Allocate args_t on heap
// TODO: dir ../../create
// TODO: dir_path zanoreni
// TODO: recursive dir creation

/******************************************************************************/
/**                             INCLUDES                                     **/
/******************************************************************************/
#include <netinet/in.h>
#include <openssl/aes.h>
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
 * Print help message
 */
void usage();

/**
 * Parse qname from received datagram and set packet type
 * @param args
 * @param qname_by_subdomains
 * @param dgram
 */
void parse_qname_to_data_and_basehost(program_t *program, char *_data_decoded, char *_data_encoded, char *_basehost);

/**
 * Check if base_host is same as we get from cli arguments
 * @param args
 * @param qname_chunks
 * @return
 */
bool is_base_host_correct(program_t *program, char *base_host);

/**
 * Process first (START) datagram and create/clean args->dst_filepath
 * @param args
 * @param qname_chunks
 * @param dgram
 */
void process_question_filename_packet(program_t *program);

/**
 * Process last (END) datagram and reinit dns_datagram_t
 * @param args
 * @param dgram
 */
void process_question_end_packet(program_t *program);

/**
 * Process DATA datagram and append data into file
 * @param args
 * @param qname_chunks
 * @param dgram
 */
void process_question_sending_packet(program_t *program);

/**
 * Process whole datagram
 * @param args
 * @param dgram
 */
void process_question(program_t *program);

/**
 * Prepare datagram answer to answer the question, not used if datagram was resend
 * @param dgram
 */
void prepare_answer(dns_datagram_t *dgram);

/**
 * Custom sento and handle UDP reliability
 * @param args
 * @param dgram
 */
void custom_sendto(program_t *program);

/**
 * Custom receive to and handle UDP reliability
 * @param dgram
 */
void custom_recvfrom(program_t *program);

/**
 * Receiving packet + Procesing + Sending answers (Router)
 * @param args
 */
void receive_packets(program_t *program);

#endif  // RECEIVER_RECEIVER_IMPLEMENTATION_H_
