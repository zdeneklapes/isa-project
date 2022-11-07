#ifndef COMMON_INITIALIZATIONS_H_
#define COMMON_INITIALIZATIONS_H_

/******************************************************************************/
/**                                 INCLUDES                            **/
/******************************************************************************/
#include <arpa/inet.h>
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
 * Deallocate memory for dns_datagram_t
 * @return
 */
void deinit_dns_datagram(dns_datagram_t *dgram);

/**
 * Initialize args_t
 * @return args_t
 */
args_t *init_args_struct();

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
