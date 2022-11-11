//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

/******************************************************************************
 * TODO
 ******************************************************************************/
// TODO: Check if file exists
// TODO: Allocate args_t on heap
// TODO: receiver check path of filepath and create it
// TODO: Allocate args_t on heap
// TODO: dir ../../create
// TODO: dir_path zanoreni
// TODO: recursive dir creation

/******************************************************************************
 * INCLUDES
 ******************************************************************************/
#include "receiver_implementation.h"

/******************************************************************************
 * FUNCTIONS DEFINITION
 ******************************************************************************/
bool is_resending_packet(program_t *program) {
    int previous_id = program->dgram->id;
    int current_id = ((dns_header_t *)(program->dgram->sender))->id;
    if (previous_id != current_id) {
        return false;
    } else {
        return true;
    }
}

bool is_resend_or_badbasehost_packet(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    return (dgram->packet_type == RESEND_OR_BADBASEHOST__AFTER_FILENAME ||
            dgram->packet_type == RESEND_OR_BADBASEHOST__AFTER_SENDING);
}

bool is_base_host_correct(program_t *program, char *base_host) {
    return (strcmp(base_host, program->args->base_host) == 0);
}

void write_content(program_t *program, char *data) {
    args_t *args = program->args;
    if (strlen(args->filename) > DGRAM_MAX_BUFFER_LENGTH) {
        dealocate_all_exit(program, EXIT_FAILURE, "ERROR: Filename is too long\n");
    }
    fwrite(data, strlen(data), sizeof(char), args->file);
}

/******************************************************************************
 * PROCESSING QUESTION
 ******************************************************************************/
void process_question_filename_packet(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    args_t *args = program->args;

    /////////////////////////////////
    // DECODE QNAME
    /////////////////////////////////
    char data[QNAME_MAX_LENGTH] = {0};
    char basehost[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(program, data, NULL, basehost);
    CALL_CALLBACK(EVENT, dns_receiver__on_transfer_init,
                  (struct in_addr *)&dgram->network_info.socket_address.sin_addr);

    strcat(args->filename, data);
    DEBUG_PRINT("Filename %s\n", args->filename);
}

void process_question_end_packet(program_t *program) {
    args_t *args = program->args;
    dns_datagram_t *dgram = program->dgram;

    /////////////////////////////////
    // PRINT
    /////////////////////////////////
    char filepath[2 * DGRAM_MAX_BUFFER_LENGTH] = {0};
    get_filepath(program, filepath);
    //
    struct stat st = {0};
    stat(filepath, &st);
    //
    CALL_CALLBACK(EVENT, dns_receiver__on_transfer_completed, filepath, st.st_size);

    /////////////////////////////////
    // REINITIALIZE
    /////////////////////////////////
    // dgram
    reinit_dns_datagram(program, true);

    // args
    memset(args->filename, 0, DGRAM_MAX_BUFFER_LENGTH);
    fclose(args->file);
    args->file = NULL;
    args->tmp_ptr_filename = NULL;
    memset(args->filename, 0, DGRAM_MAX_BUFFER_LENGTH);

    // Wait for next file
    dgram->packet_type = WAITING_NEXT_FILE;
}

void process_question_sending_packet(program_t *program) {
    /////////////////////////////////
    // DECODE QNAME
    /////////////////////////////////
    char data_decoded[QNAME_MAX_LENGTH] = {0};
    char data_encoded[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(program, data_decoded, data_encoded, NULL);

    /////////////////////////////////
    // UPDATE dns_datagram_t
    /////////////////////////////////
    program->dgram->data_len = strlen(data_decoded);
    program->dgram->data_accumulated_len += program->dgram->data_len;

    /////////////////////////////////
    // PRINT
    /////////////////////////////////
    if (program->dgram->packet_type == SENDING) {
        CALL_CALLBACK(EVENT, dns_receiver__on_chunk_received, &program->dgram->network_info.socket_address.sin_addr,
                      program->args->filename, ((dns_header_t *)program->dgram->sender)->id, program->dgram->data_len);
        CALL_CALLBACK(EVENT, dns_receiver__on_query_parsed, (char *)program->args->filename, (char *)data_encoded);
    }

    /////////////////////////////////
    // WRITE TO FILE
    /////////////////////////////////
    write_content(program, data_decoded);
}

void process_info_sending_packet(program_t *program) {
    args_t *args = program->args;
    /////////////////////////////////
    // WRITE TO FILE
    /////////////////////////////////
    // Only when info packet: DATA
    if (program->dgram->packet_type == DATA) {
        create_filepath(program);
        char filepath[2 * DGRAM_MAX_BUFFER_LENGTH] = {0};
        get_filepath(program, filepath);
        if (!(args->file = fopen(filepath, "w"))) {
            dealocate_all_exit(program, EXIT_FAILURE, "ERROR: fopen()\n");
        }
        write_content(program, "\0");
    }
}

void set_packet_type(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    /////////////////////////////////
    // DECODE QNAME
    /////////////////////////////////
    char data[QNAME_MAX_LENGTH] = {0};
    char basehost[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(program, data, NULL, basehost);

    /////////////////////////////////
    // Set packet type
    /////////////////////////////////
    if (!is_base_host_correct(program, basehost)) {
        DEBUG_PRINT("ERROR: different base_host; ID: %d\n", ((dns_header_t *)dgram->sender)->id);
        if (dgram->packet_type == SENDING) {
            dgram->packet_type = RESEND_OR_BADBASEHOST__AFTER_SENDING;
        } else if (dgram->packet_type == FILENAME) {
            dgram->packet_type = RESEND_OR_BADBASEHOST__AFTER_FILENAME;
        } else if (!is_resend_or_badbasehost_packet(program)) {
            dgram->packet_type = WAITING_NEXT_FILE;
        }
    } else if (is_resending_packet(program)) {
        if (dgram->packet_type == SENDING) {
            dgram->packet_type = RESEND_OR_BADBASEHOST__AFTER_SENDING;
        } else if (dgram->packet_type == FILENAME) {
            dgram->packet_type = RESEND_OR_BADBASEHOST__AFTER_FILENAME;
        }
    } else if (strcmp(data, "START") == 0) {
        dgram->packet_type = START;
    } else if (strcmp(data, "DATA") == 0) {
        dgram->packet_type = DATA;
    } else if (strcmp(data, "END") == 0) {
        dgram->packet_type = END;
    } else if (dgram->packet_type == RESEND_OR_BADBASEHOST__AFTER_FILENAME) {  // Return the receiving into normal
        DEBUG_PRINT("OK: continue base_host; ID: %d\n", ((dns_header_t *)dgram->sender)->id);
        dgram->packet_type = FILENAME;
    } else if (dgram->packet_type == RESEND_OR_BADBASEHOST__AFTER_FILENAME) {
        DEBUG_PRINT("OK: continue base_host; ID: %d\n", ((dns_header_t *)dgram->sender)->id);
        dgram->packet_type = SENDING;
    }
}

void process_question(program_t *program) {
    set_packet_type(program);

    /////////////////////////////////
    // HANDLE Resending packet
    /////////////////////////////////
    if (is_resend_or_badbasehost_packet(program)) {
        return;
    } else {
        program->dgram->id = ((dns_header_t *)program->dgram->sender)->id;
    }

    /////////////////////////////////
    // PROCESS By packet type
    /////////////////////////////////
    if (program->dgram->packet_type == START) {
        program->dgram->packet_type = FILENAME;
    } else if (program->dgram->packet_type == FILENAME) {
        process_question_filename_packet(program);
    } else if (program->dgram->packet_type == DATA) {
        process_info_sending_packet(program);
        program->dgram->packet_type = SENDING;
    } else if (program->dgram->packet_type == SENDING) {
        process_question_sending_packet(program);
    } else if (program->dgram->packet_type == END) {
        process_question_end_packet(program);
    }
}

void prepare_answer(dns_datagram_t *dgram) {
    memcpy(dgram->receiver, dgram->sender, DGRAM_MAX_BUFFER_LENGTH);

    // Header
    dns_header_t *header = (dns_header_t *)dgram->receiver;
    header->qr = 1;
    header->aa = 0;
    header->tc = 0;
    header->ra = 0;
    header->rcode = DNS_ANSWER_SUCCESS;
    header->ancount = htons(1);
    header->nscount = 0;
    header->arcount = 0;

    DEBUG_PRINT("Header id: %d\n", header->id);

    // Q
    u_char *question = (dgram->receiver + sizeof(dns_header_t));
    size_t qname_len = strlen((char *)question);

    // A qname
    u_char *dns_answer = (question + qname_len + 1 + sizeof(dns_question_fields_t));
    memcpy(dns_answer, question, qname_len);

    // A fields
    dns_answer_fields_t *dns_answer_fields = (dns_answer_fields_t *)(dns_answer + qname_len + 1);
    dns_answer_fields->type = htons(DNS_TYPE_A);
    dns_answer_fields->qclass = htons(DNS_CLASS_IN);
    dns_answer_fields->ttl = htons(TTL);
    dns_answer_fields->rdlength = htons(4);
    inet_pton(AF_INET, LOCALHOST, &dns_answer_fields->rdata);  // TODO: LOCALHOST?

    // Length
    dgram->receiver_packet_len = (int)((u_char *)(dns_answer_fields + 1) - (u_char *)header) - 2;
}

/***********************************************************************************************************************
 * RECEIVE AND SEND
 **********************************************************************************************************************/
void custom_sendto(program_t *program) {
    dns_datagram_t *dgram = program->dgram;

    // A
    if (sendto(dgram->network_info.socket_fd, dgram->receiver, dgram->receiver_packet_len, CUSTOM_MSG_CONFIRM,
               (const struct sockaddr *)&dgram->network_info.socket_address,
               sizeof(dgram->network_info.socket_address)) == FUNC_FAILURE) {
        PERROR_EXIT("Error: send_to()\n");
    } else {
        DEBUG_PRINT("Ok: send_to(): A len: %lu\n", (size_t)dgram->receiver_packet_len);
    }
}

void custom_recvfrom(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    if ((dgram->sender_packet_len = recvfrom(
             dgram->network_info.socket_fd, (char *)dgram->sender, DGRAM_MAX_BUFFER_LENGTH, MSG_WAITALL,
             (struct sockaddr *)&dgram->network_info.socket_address, &dgram->network_info.socket_address_len)) < 0) {
        PERROR_EXIT("Error: recvfrom()");
    } else {
        DEBUG_PRINT("Ok: recvfrom(): Q len: %lu\n", (size_t)dgram->sender_packet_len);
    }
}

void receive_packets(program_t *program) {
    dns_datagram_t *dgram = program->dgram;

    //
    while (1) {
        /////////////////////////////////
        // QUESTION
        /////////////////////////////////
        custom_recvfrom(program);
        process_question(program);
        DEBUG_PRINT("Ok: process_question():%s", "\n");

        /////////////////////////////////
        // PREPARE ANSWER
        /////////////////////////////////
        if (is_resend_or_badbasehost_packet(program)) {
            DEBUG_PRINT("CONTINUE%s", "\n");
            continue;
        } else {
            prepare_answer(dgram);
            DEBUG_PRINT("Ok: process_answer():%s", "\n");
        }

        /////////////////////////////////
        // ANSWER
        /////////////////////////////////
        custom_sendto(program);
        reinit_dns_datagram(program, false);
    }
}
