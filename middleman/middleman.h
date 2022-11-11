//
// Created by Zdeněk Lapeš on 10/11/2022.
//

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

bool middleman_drop_sender_packets(program_t *program);
bool middleman_fix_sender_packets(program_t *program);
bool middleman_drop_receiver_packets(program_t *program);

#endif  // MIDDLEMAN_MIDDLEMAN_H_
