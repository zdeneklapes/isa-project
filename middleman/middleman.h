/**
 * Project: ISA - DNS Tunneling
 *
 * @file middleman.h
 *
 * @brief Implementation of ISA project
 *
 * @author Zdenek Lapes (xlapes02)
 */

#ifndef MIDDLEMAN_MIDDLEMAN_H_
#define MIDDLEMAN_MIDDLEMAN_H_ 1

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../common/argument_parser.h"
#include "../common/dns_helper.h"
#include "../common/initializations.h"

/******************************************************************************/
/**                                MACROS                                    **/
/******************************************************************************/
#define randnum(min, max) ((rand() % (int)(((max) + 1) - (min))) + (min))

/**
 * Drop packet by change the base host url (*.com -> *.caa)
 * @param program program_t
 * @return
 */
bool middleman_drop_sender_packets(program_t *program);

/**
 * Fix the packet by change the base host url (*.caa -> *.com)
 * @param program program_t
 * @return
 */
bool middleman_fix_sender_packets(program_t *program);

/**
 * Drop packet by change the base host url (*.com -> *.caa)
 * @param program program_t
 * @return
 */
bool middleman_drop_receiver_packets(program_t *program);

/**
 * Fix the packet by change the base host url (*.caa -> *.com)
 * @param program program_t
 * @return
 */
bool middleman_fix_receiver_packets(program_t *program);

#endif  // MIDDLEMAN_MIDDLEMAN_H_
