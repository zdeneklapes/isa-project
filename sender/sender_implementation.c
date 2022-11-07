//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//
// Inspiration: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

/******************************************************************************/
/**                                 TODO                                     **/
/******************************************************************************/

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include "sender_implementation.h"

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
size_t get_qname_dns_name_format(const args_t *args, u_char *qname, dns_datagram_t *dgram) {
    prepare_qname(args, qname, dgram);
    size_t data_len = strlen((char *)qname);

    u_char base_host[QNAME_MAX_LENGTH] = {0};
    u_char subdomain[QNAME_MAX_LENGTH] = {0};

    if (packet_type == START || packet_type == END) {
        strcat((char *)base_host, (char *)qname);  // include filename info and START/END label
        strcat((char *)base_host, ".");            // include filename info and START/END label
    }

    // Base Host
    strcat((char *)base_host, args->base_host);
    DEBUG_PRINT("BASENAME encoded: %s\n", base_host);
    get_dns_name_format_base_host(base_host);

    // Data (Subdomain)
    if (packet_type == DATA) {  // no data in START or END packet - included in base_host (because parsing function)
        base32_encode(qname, strlen((const char *)qname), subdomain, QNAME_MAX_LENGTH);
        DEBUG_PRINT("DATA encoded: %s\n", subdomain);
        get_dns_name_format_subdomains(subdomain, args, dns_sender__on_chunk_encoded, dgram);
    }

    // Done
    memset((char *)qname, 0, strlen((char *)qname));  // clean before set
    strcat((char *)qname, (char *)subdomain);
    strcat((char *)qname, (char *)base_host);

    // Validate qname
    if (strlen((char *)qname) >= QNAME_MAX_LENGTH)  // qname max length
        ERROR_EXIT("Error: implementation error - qname too long, max size 255", EXIT_FAILURE);

    DEBUG_PRINT("QNAME encoded: %s\n", qname);

    return packet_type == DATA ? data_len : 0;
}

void get_file_data(const args_t *args, u_char *qname_data, dns_datagram_t *dgram) {
    int dns_name_len = QNAME_MAX_LENGTH - strlen(args->base_host);
    size_t len = BASE32_LENGTH_DECODE(dns_name_len);
    len = len - (size_t)(ceil((double)len / SUBDOMAIN_DATA_LENGTH) + 10);  // max qname len is 255
    fread(qname_data, (int)len, 1, args->file);
    dgram->file_data_accumulated_len += strlen((char *)qname_data);
}

/******************************************************************************/
/**                                 PREPARE DGRAMS                           **/
/******************************************************************************/
void prepare_qname(const args_t *args, u_char *qname_data, dns_datagram_t *dgram) {
    char delim[] = "./";

    if (packet_type == START) {
        char data[QNAME_MAX_LENGTH] = {0};
        strcat(data, "START.fstart.");
        if (strncmp(args->dst_filepath, delim, 2) == 0) {
            strcat(data, args->dst_filepath + 2);
        } else {
            strcat(data, args->dst_filepath);
        }
        strcat(data, ".fend");
        memcpy(qname_data, data, strlen(data));
    } else if (packet_type == DATA) {
        get_file_data(args, qname_data, dgram);
    } else if (packet_type == END) {
        char data[QNAME_MAX_LENGTH] = {0};
        strcat(data, "END.fstart.");
        if (strncmp(args->dst_filepath, delim, 2) == 0) {
            strcat(data, args->dst_filepath + 2);
        } else {
            strcat(data, args->dst_filepath);
        }
        strcat(data, ".fend");
        memcpy(qname_data, data, strlen(data));
    } else {
        ERROR_EXIT("Error: Implementation\n", EXIT_FAILURE);
    }
}

void prepare_question(const args_t *args, dns_datagram_t *dgram) {
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

    // Q
    u_char *question = (dgram->sender + sizeof(dns_header_t));

    // Q - qname
    uint8_t qname[QNAME_MAX_LENGTH] = {0};
    dgram->file_data_len = get_qname_dns_name_format(args, qname, dgram);  // if packet_type==DATA else 0
    memcpy(question, qname, strlen((char *)qname));

    // Q - type + class
    dns_question_fields_t *dns_question_fields = (dns_question_fields_t *)(question + strlen((char *)qname) + 1);
    dns_question_fields->qtype = (u_short)htons(DNS_TYPE_A);
    dns_question_fields->qclass = (u_short)htons(DNS_CLASS_IN);

    // Length
    dgram->sender_len = (uint16_t)((u_char *)(dns_question_fields + 1) - (u_char *)dgram->sender);
}

/******************************************************************************/
/**                                 SEND DGRAMS                              **/
/******************************************************************************/
void send_packet(const args_t *args, dns_datagram_t *dgram) {
    socklen_t socket_len = sizeof(struct sockaddr_in);

    do {
        // Q
        if (sendto(dgram->info.socket_fd, dgram, dgram->sender_len, CUSTOM_MSG_CONFIRM,
                   (struct sockaddr *)&dgram->info.socket_address,
                   sizeof(dgram->info.socket_address)) == FUNC_FAILURE) {
            PERROR_EXIT("Error: sendto()");
        } else {
            DEBUG_PRINT("Ok: sendto(), sender len: %lu\n", (size_t)dgram->sender_len);
        }

        if (packet_type == DATA) {
            CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_chunk_sent,
                          (struct in_addr *)&dgram->info.socket_address.sin_addr, (char *)args->dst_filepath, dgram->id,
                          dgram->file_data_len);
        }

        // A
        if ((dgram->receiver_len = recvfrom(dgram->info.socket_fd, dgram->receiver, sizeof(dgram->receiver),
                                            MSG_WAITALL, (struct sockaddr *)&dgram->info.socket_address, &socket_len)) <
            0) {
            PERROR_EXIT("Error: recvfrom() failed\n");
        } else {
            if (errno == EAGAIN) {  // Handle timeout
                DEBUG_PRINT("Error: EAGAIN recvfrom(), receiver len: %lu\n", (size_t)dgram->receiver_len);
                continue;
            } else {
                DEBUG_PRINT("Ok: recvfrom(), receiver len: %lu\n", (size_t)dgram->receiver_len);
            }
        }
        break;
    } while (1);
}

void prepare_and_send_packet(const args_t *args, dns_datagram_t *dgram) {
    prepare_question(args, dgram);

    // Send packets and ensure delivery
    while (1) {
        send_packet(args, dgram);

        // Repeat if UDP_DGRAM was missed
        if (((dns_header_t *)dgram)->id == dgram->id) break;  // FIXME
    }
}

void start_sending(program_t *program) {
    dns_datagram_t dgram = init_dns_datagram(true, program);
    struct stat st = {0};
    stat(program->filename, &st);

    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_init, (struct in_addr *)&dgram.info.socket_address.sin_addr);

    // Send
    //
    packet_type = START;
    dgram.id++;
    prepare_and_send_packet(program, &dgram);

    //
    packet_type = DATA;
    while (!feof(program->file)) {
        dgram.id++;
        prepare_and_send_packet(program, &dgram);
    }

    //
    packet_type = END;
    dgram.id++;
    prepare_and_send_packet(program, &dgram);
    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_completed, (char *)program->dst_filepath,
                  dgram.file_data_accumulated_len);

    //
    close(dgram.info.socket_fd);
}
