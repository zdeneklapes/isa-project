//
// Created by Zdeněk Lapeš on 07/11/2022.
//

#ifndef COMMON_ARGUMENT_PARSER_H_
#define COMMON_ARGUMENT_PARSER_H_

/******************************************************************************/
/**                                 INCLUDES                            **/
/******************************************************************************/
#include "dns_helper.h"
#include "initializations.h"

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
/**
 * Helper for parsing cli arguments for each switcher
 * @param argc
 * @param argv
 * @param i
 * @param args
 * @return -1 if all cli arguments was parsed else i of next parsed argument
 */
int check_switchers_and_argc(int argc, char *argv[], int i, args_t *args);

/**
 * Retrieve dns server ip from system /etc/resolv.conf file
 * @param args
 * @return
 */
bool get_dns_servers_from_system(program_t *program);

/**
 * Validate base_host, exit on validation failed
 * @param str
 */
void validate_base_host_exit(program_t *program);

/**
 * Validate dst_filepath, exit on validation failed
 * @param program
 */
void validate_dst_filepath(program_t *program);

/**
 * Validate filename, exit on validation failed
 * @param program
 */
void validate_filename(program_t *program);

/**
 * Validate upstream_dns, exit on validation failed
 * @param program
 */
void validate_upstream_dns_ip(program_t *program);

/**
 * Validate ip, exit on validation failed
 * @param program
 */
void validate_ip_type(program_t *program);

/**
 * Validate all arguments, exit on validation failed
 * @param i
 * @param program
 */
void validate_args(int i, program_t *program);

/**
 * Initialize args_t structure for sender
 * @param argc
 * @param argv
 * @return Initialized args_t struct
 */
void set_args_sender(program_t *program);

/**
 * Initialize args_t struct for receiver
 * @param argc
 * @param argv
 * @return Initialized args_t struct
 */
void set_args_receiver(program_t *program);

#endif  // COMMON_ARGUMENT_PARSER_H_
