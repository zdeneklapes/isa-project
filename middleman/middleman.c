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
void middleman_drop_packets(program_t *program) {
    srand(time(NULL));

    ////////////////////////////////
    // Send packet
    ////////////////////////////////
    if (randnum(0, 1) == 0) {
        DEBUG_PRINT("Packet forward: %d\n", ((dns_header_t *)program->dgram->sender)->id);
        return;
    }

    ////////////////////////////////
    // Drop packet
    ////////////////////////////////
    DEBUG_PRINT("Packet dropped: %d\n", ((dns_header_t *)program->dgram->sender)->id);

    char base_host[QNAME_MAX_LENGTH] = {0};
    char data_encoded[QNAME_MAX_LENGTH] = {0};
    char data_decoded[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(program, data_decoded, data_encoded, base_host);

    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    memset(qname, 0, QNAME_MAX_LENGTH);
    strcat((char *)qname, data_encoded);
    strcat((char *)qname, ".");
    strcat((char *)qname, base_host);

    dns_question_fields_t *dns_question_fields =
        (dns_question_fields_t *)(program->dgram->sender + program->dgram->sender_packet_len);
    dns_question_fields->qtype = (u_short)htons(DNS_TYPE_A);
    dns_question_fields->qclass = (u_short)htons(DNS_CLASS_IN);

    // Length
    program->dgram->sender_packet_len =
        sizeof(dns_header_t) + strlen((char *)qname) + sizeof(dns_question_fields_t) + 1;
}

//
// void middleman(program_t *program) {
//    dns_datagram_t *dgram = program->dgram;
//
//    socklen_t socket_len = sizeof(struct sockaddr_in);
//    (void)socket_len;
//
//    do {
//        // Get Question
//        if ((dgram->receiver_packet_len =
//                 recvfrom(dgram->network_info.socket_fd, dgram->receiver, sizeof(dgram->receiver), MSG_WAITALL,
//                          (struct sockaddr *)&dgram->network_info.socket_address, &socket_len)) < 0) {
//            PERROR_EXIT("Error: recvfrom() failed\n");
//        }
//
//        // Drop packet
//        if (randnum(0, 1) == 1) {
//            DEBUG_PRINT("Packet dropped: %d\n", ((dns_header_t *)dgram->sender)->id);
//            continue;
//        } else {
//            set_receiver_base_host(program);
//            DEBUG_PRINT("Packet forward: %d\n", ((dns_header_t *)dgram->sender)->id);
//        }
//
//        // Forward
//        if (sendto(dgram->network_info.socket_fd, dgram->sender, dgram->sender_packet_len, CUSTOM_MSG_CONFIRM,
//                   (struct sockaddr *)&dgram->network_info.socket_address,
//                   sizeof(dgram->network_info.socket_address)) == FUNC_FAILURE) {
//            PERROR_EXIT("Error: sendto()");
//        }
//        break;
//    } while (1);
//}
//
// int main(int argc, char *argv[]) {
//    srand(time(NULL));
//    //    printf("%d\n", randnum(0, 1));
//
//    program_t *program = malloc(sizeof(program_t));
//    if (program == NULL) {
//        ERROR_EXIT("Failed to allocate memory for program", EXIT_FAILURE);
//    }
//    program->argc = argc;
//    program->argv = argv;
//    set_args_sender(program);         // Validate and parse args, if failed exit
//    set_dns_datagram(program, true);  // Validate and init dns_datagram_t, if failed exit
//
//    // Send
//    middleman(program);
//
//    //
//    dealocate_all_exit(program, EXIT_SUCCESS, NULL);
//}
