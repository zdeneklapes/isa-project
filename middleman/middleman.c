/**
 * Project: ISA - DNS Tunneling
 *
 * @file middleman.c
 *
 * @brief Implementation of ISA project
 *
 * @author Zdenek Lapes (xlapes02)
 */

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
        DEBUG_PRINT("DROPPED: FALSE; id: %d\n", ((dns_header_t *)program->dgram->sender)->id);
        return false;
    }

    ////////////////////////////////
    // Drop packet
    ////////////////////////////////
    DEBUG_PRINT("DROPPED: TRUE; id: %d\n", ((dns_header_t *)program->dgram->sender)->id);

    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    int length = strlen((char *)qname);
    qname[length - 2] = 'a';
    qname[length - 1] = 'a';
    return true;
}

bool middleman_fix_sender_packets(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    DEBUG_PRINT("DROPPED: FALSE - sendto(); Packet_id/Stored_id: %d/%d\n", ((dns_header_t *)dgram->sender)->id,
                dgram->id);
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    int length = strlen((char *)qname);
    qname[length - 2] = 'o';
    qname[length - 1] = 'm';
    return false;
}

bool middleman_drop_receiver_packets(program_t *program) {
    sleep(1);

    ////////////////////////////////
    // Send packet
    ////////////////////////////////
    if (randnum(0, 1) == 0) {
        DEBUG_PRINT("DROPPED: FALSE; id: %d\n", ((dns_header_t *)program->dgram->sender)->id);
        return false;
    }

    ////////////////////////////////
    // Drop packet
    ////////////////////////////////
    DEBUG_PRINT("DROPPED: TRUE; id: %d\n", ((dns_header_t *)program->dgram->sender)->id);

    unsigned char *qname = (unsigned char *)((program->dgram->receiver + sizeof(dns_header_t)));
    qname += strlen((char *)qname) - 1;
    *(qname--) = 'a';
    *(qname--) = 'a';
    return true;
}

bool middleman_fix_receiver_packets(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    DEBUG_PRINT("DROPPED: TRUE - sendto(); Packet_id/Stored_id: %d/%d\n", ((dns_header_t *)dgram->sender)->id,
                dgram->id);
    unsigned char *qname = (unsigned char *)((program->dgram->receiver + sizeof(dns_header_t)));
    qname += strlen((char *)qname) - 1;
    *(qname--) = 'm';
    *(qname--) = 'o';
    return false;
}
