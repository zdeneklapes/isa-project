//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include "middleman.h"

/******************************************************************************/
/**                                MACROS                                    **/
/******************************************************************************/
#define randnum(min, max) ((rand() % (int)(((max) + 1) - (min))) + (min))

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
bool middleman_drop_sender_packets(program_t *program) {
    sleep(1);

    ////////////////////////////////
    // Send packet
    ////////////////////////////////
    if (randnum(0, 1) == 0) {
        DEBUG_PRINT("DROPPED: NO; id: %d\n", ((dns_header_t *)program->dgram->sender)->id);
        return false;
    }

    ////////////////////////////////
    // Drop packet
    ////////////////////////////////
    DEBUG_PRINT("DROPPED: YES; id: %d\n", ((dns_header_t *)program->dgram->sender)->id);

    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    int length = strlen((char *)qname);
    qname[length - 2] = 'a';
    qname[length - 1] = 'a';
    return true;
}

bool middleman_fix_sender_packets(program_t *program) {
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    int length = strlen((char *)qname);
    qname[length - 2] = 'o';
    qname[length - 1] = 'm';
    return false;
}
