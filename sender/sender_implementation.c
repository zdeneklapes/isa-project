//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//
// Inspiration: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

/******************************************************************************/
/**                                 TODO                                     **/
/******************************************************************************/
// TODO: RECV before PARSE : dolejska vypis

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include "sender_implementation.h"

#include "../common/dns_helper.h"

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
/******************************************************************************/
/**                             PREPARE QNAME                                **/
/******************************************************************************/
void get_file_data(const args_t *args, u_char *qname_data, dns_datagram_t *dgram) {
    int dns_name_len = QNAME_MAX_LENGTH - strlen(args->base_host);
    size_t len = BASE32_LENGTH_DECODE(dns_name_len);
    len = len - (size_t)(ceil((double)len / SUBDOMAIN_DATA_LENGTH) + 10);  // max qname len is 255
    fread(qname_data, (int)len, 1, args->file);
    dgram->data_accumulated_len += strlen((char *)qname_data);
}

void set_qname_start_packet(program_t *program) {
    //
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);

    char *qname_data = "START.";

    // qname before encoding
    strcat((char *)qname, qname_data);
    memcpy(qname + strlen((char *)qname_data), program->args->base_host, strlen(program->args->base_host));

    // qname after encoding
    get_dns_name_format_base_host(qname);

    program->dgram->sender_packet_len = sizeof(dns_header_t) + strlen((char *)qname) + 1;
}

void set_qname_filename_packet(program_t *program) {
    program->args->tmp_ptr_filename = program->args->filename;
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);

    // qname before encoding
    strcat((char *)qname, qname_data);
    memcpy(qname + strlen((char *)qname_data), program->args->base_host, strlen(program->args->base_host));

    // qname after encoding
    get_dns_name_format_base_host(qname);

    program->dgram->sender_packet_len = sizeof(dns_header_t) + strlen((char *)qname) + 1;
}

void get_qname_data_packet() {
    // TODO: implement
}

void get_qname_sending_packet() {
    // TODO: implement
}

void get_qname_end_packet() {
    // TODO: implement
}

void set_qname_based_on_packet_type(program_t *program) {
    if (program->dgram->packet_type == START) {
        set_qname_start_packet(program);
    } else if (program->dgram->packet_type == FILENAME) {
        set_qname_filename_packet(program);
    } else if (program->dgram->packet_type == DATA) {
        get_qname_data_packet();
    } else if (program->dgram->packet_type == SENDING) {
        get_qname_sending_packet();
    } else if (program->dgram->packet_type == END) {
        get_qname_end_packet();
    }
}

// size_t get_qname_dns_name_format(program_t *program) {
//     unsigned char qname[QNAME_MAX_LENGTH];
//     prepare_qname(program, qname);
//     size_t data_len = strlen((char *)qname);
//
//     u_char base_host[QNAME_MAX_LENGTH] = {0};
//     u_char subdomain[QNAME_MAX_LENGTH] = {0};
//
//     if (packet_type == START || packet_type == END) {
//         strcat((char *)base_host, (char *)qname);  // include filename info and START/END label
//         strcat((char *)base_host, ".");            // include filename info and START/END label
//     }
//
//     // Base Host
//     strcat((char *)base_host, args->base_host);
//     DEBUG_PRINT("BASENAME encoded: %s\n", base_host);
//     get_dns_name_format_base_host(base_host);
//
//     // Data (Subdomain)
//     if (packet_type == DATA) {  // no data in START or END packet - included in base_host (because parsing function)
//         base32_encode(qname, strlen((const char *)qname), subdomain, QNAME_MAX_LENGTH);
//         DEBUG_PRINT("DATA encoded: %s\n", subdomain);
//         get_dns_name_format_subdomains(subdomain, args, dns_sender__on_chunk_encoded, dgram);
//     }
//
//     // Done
//     memset((char *)qname, 0, strlen((char *)qname));  // clean before set
//     strcat((char *)qname, (char *)subdomain);
//     strcat((char *)qname, (char *)base_host);
//
//     // Validate qname
//     if (strlen((char *)qname) >= QNAME_MAX_LENGTH)  // qname max length
//         ERROR_EXIT("Error: implementation error - qname too long, max size 255", EXIT_FAILURE);
//
//     DEBUG_PRINT("QNAME encoded: %s\n", qname);
//
//     return packet_type == DATA ? data_len : 0;
// }

/******************************************************************************/
/**                             PREPARE DATAGRAMS                            **/
/******************************************************************************/

void prepare_qname(program_t *program, unsigned char *qname) {
    args_t *args = program->args;
    char delim[] = "./";

    if (program->dgram->packet_type == START) {
        char data[QNAME_MAX_LENGTH] = {0};
        strcat(data, "START.fstart.");
        if (strncmp(args->dst_filepath, delim, 2) == 0) {
            strcat(data, args->dst_filepath + 2);
        } else {
            strcat(data, args->dst_filepath);
        }
        strcat(data, ".fend");
        memcpy(qname, data, strlen(data));
    } else if (program->dgram->packet_type == DATA) {
        get_file_data(args, qname, program->dgram);
    } else if (program->dgram->packet_type == END) {
        char data[QNAME_MAX_LENGTH] = {0};
        strcat(data, "END.fstart.");
        if (strncmp(args->dst_filepath, delim, 2) == 0) {
            strcat(data, args->dst_filepath + 2);
        } else {
            strcat(data, args->dst_filepath);
        }
        strcat(data, ".fend");
        memcpy(qname, data, strlen(data));
    } else {
        ERROR_EXIT("Error: Implementation\n", EXIT_FAILURE);
    }
}

void prepare_question(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    memset(dgram->sender, 0, DGRAM_MAX_BUFFER_LENGTH);  // clean

    // Header
    dns_header_t *header = (dns_header_t *)dgram;
    header->id = dgram->id;

    header->qr = 0;      // This is a query
    header->opcode = 0;  // This is a standard query
    header->aa = 0;      // Not Authoritative
    header->tc = 0;      // This message is
    header->rd = 1;      // Recursion Desired

    header->ra = 0;  // Recursion not available!
    header->z = 0;
    header->rcode = 0;

    header->qdcount = htons(1);  // One sender
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    DEBUG_PRINT("Header id: %d\n", header->id);

    // Question
    set_qname_based_on_packet_type(program);
    dns_question_fields_t *dns_question_fields =
        (dns_question_fields_t *)(program->dgram->sender + program->dgram->sender_packet_len);
    dns_question_fields->qtype = (u_short)htons(DNS_TYPE_A);
    dns_question_fields->qclass = (u_short)htons(DNS_CLASS_IN);

    // Length
    dgram->sender_packet_len += sizeof(dns_question_fields_t);
}

/******************************************************************************/
/**                                 SEND DGRAMS                              **/
/******************************************************************************/
void send_packet(program_t *program) {
    dns_datagram_t *dgram = program->dgram;

    socklen_t socket_len = sizeof(struct sockaddr_in);

    do {
        // Q
        if (sendto(dgram->network_info.socket_fd, dgram, dgram->sender_packet_len, CUSTOM_MSG_CONFIRM,
                   (struct sockaddr *)&dgram->network_info.socket_address,
                   sizeof(dgram->network_info.socket_address)) == FUNC_FAILURE) {
            PERROR_EXIT("Error: sendto()");
        } else {
            DEBUG_PRINT("Ok: sendto(), sender len: %lu\n", (size_t)dgram->sender_packet_len);
        }

        if (program->dgram->packet_type == DATA) {
            CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_chunk_sent,
                          (struct in_addr *)&dgram->network_info.socket_address.sin_addr,
                          (char *)program->args->dst_filepath, dgram->id, dgram->data_len);
        }

        // A
        if ((dgram->receiver_packet_len =
                 recvfrom(dgram->network_info.socket_fd, dgram->receiver, sizeof(dgram->receiver), MSG_WAITALL,
                          (struct sockaddr *)&dgram->network_info.socket_address, &socket_len)) < 0) {
            PERROR_EXIT("Error: recvfrom() failed\n");
        } else {
            if (errno == EAGAIN) {  // Handle timeout
                DEBUG_PRINT("Error: EAGAIN recvfrom(), receiver len: %lu\n", (size_t)dgram->receiver_packet_len);
                continue;
            } else {
                DEBUG_PRINT("Ok: recvfrom(), receiver len: %lu\n", (size_t)dgram->receiver_packet_len);
            }
        }
        break;
    } while (1);
}

/******************************************************************************/
/**                             SEND DATAGRAMS                               **/
/******************************************************************************/
void send_start_packet(program_t *program) {
    program->dgram->packet_type = START;
    prepare_question(program);
    send_packet(program);
}

void send_filename_packet(program_t *program) {
    program->dgram->packet_type = FILENAME;
    prepare_question(program);
    send_packet(program);
}

// void send_data_packet(program_t *program) {
//     program->dgram->packet_type = DATA;
//     prepare_and_send_packet(program);
//     send_packet(program);
// }
//
// void send_sending_packet(program_t *program) {
//     program->dgram->packet_type = SENDING;
//     prepare_and_send_packet(program);
//     send_packet(program);
// }
//
// void send_end_packet(program_t *program) {
//     program->dgram->packet_type = END;
//     prepare_and_send_packet(program);
//     send_packet(program);
// }

void start_sending(program_t *program) {
    struct stat st = {0};
    stat(program->args->filename, &st);

    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_init,
                  (struct in_addr *)&program->dgram->network_info.socket_address.sin_addr);

    send_start_packet(program);
//    send_filename_packet(program);
//    send_data_packet(program);
//    send_sending_packet(program);
//    send_end_packet(program);
#if 0
    //
    program->dgram->packet_type = DATA;
    while (!feof(program->args->file)) {
        program->dgram->id++;
        prepare_and_send_packet(program);
    }

    //
    program->dgram->packet_type = END;
    program->dgram->id++;
    prepare_and_send_packet(program);
    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_completed, (char *)program->args->dst_filepath,
                  program->dgram->data_accumulated_len);
#endif
}
