//
// Created by Zdeněk Lapeš on 07/11/2022.
//

#ifndef COMMON_ARGUMENT_PARSER_H_
#define COMMON_ARGUMENT_PARSER_H_

/******************************************************************************/
/**                                 INCLUDES                            **/
/******************************************************************************/
#include "dns_helper.h"

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
/**
 * Helper for parsing cli arguments for each switcher
 * @param argc
 * @param argv
 * @param idx
 * @param args
 * @return -1 if all cli arguments was parsed else idx of next parsed argument
 */
int check_switchers_and_argc(int argc, char *argv[], int idx, args_t *args);

bool get_dns_servers_from_system(args_t *args);
/**
 * Validate base_host, exit on validation failed
 * @param str
 */
void validate_base_host_exit(char *str);
void validate_dst_filepath(args_t *args, args_t *args_test);
void validate_filename(args_t *args, args_t *args_test);
void validate_upstream_dns_ip(args_t *args);
void validate_ip_type(args_t *args);
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
args_t *parse_args_receiver(int argc, char *argv[]);

#endif  // COMMON_ARGUMENT_PARSER_H_
