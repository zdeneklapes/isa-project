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

bool middleman_drop_receiver_packets(program_t *program) {
    // TODO: implement
    (void)program;
    return false;
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
