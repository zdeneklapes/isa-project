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
void set_file_data(program_t *program) {
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    unsigned int len = get_length_to_send(program);
    fread(qname, (int)len, 1, program->args->file);
    program->dgram->data_accumulated_len += strlen((char *)qname);
}

void encode_data_in_qname_into_qname(program_t *program) {
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    char qname_copy[QNAME_MAX_LENGTH] = {0};
    memcpy(qname_copy, qname, strlen((char *)qname));
    memset(qname, 0, QNAME_MAX_LENGTH);
    base32_encode((uint8_t *)qname_copy, (int)strlen((char *)qname_copy), qname, QNAME_MAX_LENGTH);
    strcat((char *)qname, ".\0");
    memcpy(qname + strlen((char *)qname), program->args->base_host,
           strlen(program->args->base_host));  // copy base host
    get_dns_name_format(qname);                // get dns qname format
}

void set_qname_filename_packet(program_t *program) {
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);

    // Set first tmp_ptr_filename
    if (!program->args->tmp_ptr_filename) {
        program->args->tmp_ptr_filename = program->args->filename;
    }

    // len
    unsigned int len = get_length_to_send(program);
    if (len > strlen((char *)program->args->tmp_ptr_filename)) {
        len = strlen((char *)program->args->tmp_ptr_filename);
    }

    // qname
    strcat((char *)qname, (char *)program->args->tmp_ptr_filename);
    prepare_data_dns_qname_format(program, dns_sender__on_chunk_encoded);  // filename encode
    encode_data_in_qname_into_qname(program);                              // base32 encode

    // update
    program->args->tmp_ptr_filename += len;
    program->dgram->sender_packet_len = sizeof(dns_header_t) + strlen((char *)qname) + 1;
}

#if 0
void test_debug_func() {
    char *aaa = "aaa\0";
    unsigned long len = strlen(aaa);
}
#endif

void set_qname_sending_packet(program_t *program) {
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    set_file_data(program);  // file data will be in qname ptr
    program->dgram->data_len = strlen((char *)qname);

    prepare_data_dns_qname_format(program, dns_sender__on_chunk_encoded);  // filename encode
    encode_data_in_qname_into_qname(program);                              // base32 encode

    // update
    program->dgram->sender_packet_len = sizeof(dns_header_t) + strlen((char *)qname) + 1;
}

void set_info_packet(program_t *program, char *info) {
    // TODO
    //
    unsigned char *qname = program->dgram->sender + sizeof(dns_header_t);
    base32_encode((uint8_t *)info, (int)strlen(info), qname, QNAME_MAX_LENGTH);

    // qname before encoding
    strcat((char *)qname, ".\0");
    memcpy(qname + strlen((char *)qname), program->args->base_host, strlen(program->args->base_host));

    // qname after encoding
    get_dns_name_format(qname);

    program->dgram->sender_packet_len = sizeof(dns_header_t) + strlen((char *)qname) + 1;
}

void set_qname_based_on_packet_type(program_t *program) {
    if (program->dgram->packet_type == START) {
        set_info_packet(program, "START");
    } else if (program->dgram->packet_type == FILENAME) {
        set_qname_filename_packet(program);
    } else if (program->dgram->packet_type == DATA) {
        set_info_packet(program, "DATA");
    } else if (program->dgram->packet_type == SENDING) {
        set_qname_sending_packet(program);
    } else if (program->dgram->packet_type == END) {
        set_info_packet(program, "END");
    }
}

/******************************************************************************/
/**                             PREPARE DATAGRAMS                            **/
/******************************************************************************/
void prepare_question(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    memset(dgram->sender, 0, DGRAM_MAX_BUFFER_LENGTH);  // clean

    // Header
    dns_header_t *header = (dns_header_t *)dgram;
    header->id = ++dgram->id;

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
    (void)socket_len;

    do {
        // Q
        if (sendto(dgram->network_info.socket_fd, dgram->sender, dgram->sender_packet_len, CUSTOM_MSG_CONFIRM,
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
void send_info_packet(program_t *program, enum PACKET_TYPE type) {
    program->dgram->packet_type = type;
    prepare_question(program);
    send_packet(program);
}

void send_filename_packet(program_t *program, enum PACKET_TYPE type) {
    program->dgram->packet_type = type;
    while (program->args->tmp_ptr_filename != program->args->filename + strlen(program->args->filename)) {
        prepare_question(program);
        send_packet(program);
    }
}

void send_sending_packet(program_t *program, enum PACKET_TYPE type) {
    program->dgram->packet_type = type;
    while (!feof(program->args->file)) {
        prepare_question(program);
        send_packet(program);
    }
    program->dgram->data_len = 0;
}

void start_sending(program_t *program) {
    struct stat st = {0};
    stat(program->args->filename, &st);

    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_init,
                  (struct in_addr *)&program->dgram->network_info.socket_address.sin_addr);

    send_info_packet(program, START);
    send_filename_packet(program, FILENAME);
    send_info_packet(program, DATA);
    send_sending_packet(program, SENDING);
    send_info_packet(program, END);

    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_completed, program->args->dst_filepath,
                  (int)program->dgram->data_accumulated_len);
}
