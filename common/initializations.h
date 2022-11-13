#ifndef COMMON_INITIALIZATIONS_H_
#define COMMON_INITIALIZATIONS_H_

/******************************************************************************/
/**                                 INCLUDES                            **/
/******************************************************************************/
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dns_helper.h"

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/

/**
 * Deallocate memory for args_t
 * @param args
 */
void deinit_args_struct(args_t *args);

/**
 * Reinitialize args_t
 * @param program
 */
void reinit_args_struct(program_t *program);
/**
 * Initialize args_t
 * @return args_t
 */
void init_args_struct(program_t *program);

/**
 * Deallocate memory for dns_datagram_t
 * @return
 */
void deinit_dns_datagram(dns_datagram_t *dgram);

/**
 * Reinitialize dns_datagram_t
 * @return dns_datagram_t
 */
void init_dns_datagram(program_t *program);

/**
 * Sender initialization dns_datagram_t
 * @param program
 */
void init_dns_datagram_sender(program_t *program);

/**
 * Reinitialize dns_datagram_t
 * @param program
 */
void init_dns_datagram_after_info_end_packet(program_t *program);

/**
 * Reinitialize dns_datagram_t for start of new packet
 * @param program
 */
void init_dns_datagram_before_info_start_packet(program_t *program);

/**
 * Network initialization
 * @param program
 * @param is_sender
 */
void init_dns_datagram_network_info(program_t *program, bool is_sender);

/**
 * Initialize dns_datagram_t
 * @param args
 * @return dns_datagram_t
 */
void set_dns_datagram(program_t *program, bool is_sender);

/**
 * Deallocate all memory on allocated on heap
 * @param dgram
 */
void dealocate_all_exit(program_t *program, int exit_code, char *msg);

#endif  // COMMON_INITIALIZATIONS_H_
