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

    // TODO: Fixme packet_type setup

    if (previous_id != current_id) {
        return false;
    }

    //    if (dgram->packet_type == START || dgram->packet_type == END) {
    //        dgram->packet_type = RESEND;
    //    } else if (dgram->packet_type == DATA) {
    //        dgram->packet_type = RESEND_DATA;
    //    } else {
    //        // Leave packet_type = packet_type
    //    }
    return true;
}

void parse_qname_to_data_and_basehost(program_t *program, char *_data_decoded, char *_data_encoded, char *_basehost) {
    int num_chunks = 0;
    char chunks[SUBDOMAIN_CHUNKS][SUBDOMAIN_NAME_LENGTH] = {0};
    dns_datagram_t *dgram = program->dgram;
    u_char *qname_ptr = (u_char *)(dgram->sender + sizeof(dns_header_t));
    uint8_t subdomain_size = *qname_ptr++;

    /////////////////////////////////
    // PARSE QNAME TO CHUNKS
    /////////////////////////////////
    while (subdomain_size) {
        // Validate qname
        if (subdomain_size > SUBDOMAIN_NAME_LENGTH || num_chunks >= SUBDOMAIN_CHUNKS) {
            dgram->packet_type = MALFORMED_PACKET;
            ERROR_RETURN("ERROR: qname - Malformed request\n", );
        }

        //
        memset(chunks[num_chunks], 0, SUBDOMAIN_NAME_LENGTH);
        memcpy(chunks[num_chunks++], (char *)qname_ptr, (int)subdomain_size);
        qname_ptr += subdomain_size + 1;
        subdomain_size = *(qname_ptr - 1);
    }

    if (num_chunks < 2) {
        // TODO: Fixme
        return;
    }

    /////////////////////////////////
    // DECODE DATA
    /////////////////////////////////
    char data_encoded[QNAME_MAX_LENGTH] = {0};
    for (int i = 0; i < num_chunks - 2; ++i) {
        strcat(data_encoded, chunks[i]);
    }

    if (_data_decoded) {
        base32_decode((uint8_t *)data_encoded, (uint8_t *)_data_decoded, QNAME_MAX_LENGTH);
    }

    if (_data_encoded) {
        strcpy(_data_encoded, data_encoded);
    }

    if (_basehost) {
        strcat(_basehost, chunks[num_chunks - 2]);
        strcat(_basehost, ".");
        strcat(_basehost, chunks[num_chunks - 1]);
    }
}

bool is_base_host_correct(program_t *program, char *base_host) {
    return (strcmp(base_host, program->args->base_host) == 0);
}

void create_filepath(char *filepath) {
    for (unsigned long i = 0; i < strlen(filepath); i++) {  // NOLINT
        if (filepath[i] == '/') {
            filepath[i] = '\0';
            if (access(filepath, F_OK) != 0) {
                mkdir(filepath, 0700);
            }
            filepath[i] = '/';
        }
    }
}

void get_filepath(program_t *program, char *filepath) {
    // TODO: Check handle "/" ot "./" or ".", atc...
    args_t *args = program->args;
    strcat(filepath, args->dst_filepath);
    strcat(filepath, "/\0");
    strcat(filepath, args->filename);
}

void write_content(program_t *program, char *data, char *fopen_mode) {
    args_t *args = program->args;
    if (strlen(args->filename) > DGRAM_MAX_BUFFER_LENGTH) {
        dealocate_all_exit(program, EXIT_FAILURE, "ERROR: Filename is too long\n");
    }

    /////////////////////////////////
    // WRITE TO FILE
    /////////////////////////////////
    char filepath[2 * DGRAM_MAX_BUFFER_LENGTH] = {0};
    get_filepath(program, filepath);

    // Only when info packet: DATA
    if (program->dgram->packet_type == DATA) {
        create_filepath(filepath);
    }

    if (!(args->file = fopen(filepath, fopen_mode))) {
        dealocate_all_exit(program, EXIT_FAILURE, "ERROR: fopen() failed\n");
    }
    fwrite(data, strlen(data), sizeof(char), args->file);
    fclose(args->file);
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
    parse_qname_to_data_and_basehost(program, data, NULL, basehost);
    CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_transfer_init,
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
    CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_transfer_completed, filepath, st.st_size);

    /////////////////////////////////
    // REINITIALIZE
    /////////////////////////////////
    // dgram
    reinit_dns_datagram(program, true);

    // args
    memset(args->filename, 0, DGRAM_MAX_BUFFER_LENGTH);
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
    parse_qname_to_data_and_basehost(program, data_decoded, data_encoded, NULL);

    /////////////////////////////////
    // UPDATE dns_datagram_t
    /////////////////////////////////
    program->dgram->data_len = strlen(data_decoded);
    program->dgram->data_accumulated_len += program->dgram->data_len;

    /////////////////////////////////
    // PRINT
    /////////////////////////////////
    if (program->dgram->packet_type == SENDING) {
        CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_chunk_received,
                      &program->dgram->network_info.socket_address.sin_addr, program->args->filename,
                      ((dns_header_t *)program->dgram->sender)->id, program->dgram->data_len);
        CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_query_parsed, (char *)program->args->filename,
                      (char *)data_encoded);
    }

    /////////////////////////////////
    // WRITE TO FILE
    /////////////////////////////////
    write_content(program, data_decoded, "a");
}

void set_packet_type(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    /////////////////////////////////
    // DECODE QNAME
    /////////////////////////////////
    char data[QNAME_MAX_LENGTH] = {0};
    char basehost[QNAME_MAX_LENGTH] = {0};
    parse_qname_to_data_and_basehost(program, data, NULL, basehost);

    // Set packet type
    if (!is_base_host_correct(program, basehost)) {
        if (dgram->packet_type == SENDING) {
            dgram->packet_type = NONE_AFTER_SENDING;
        } else if (dgram->packet_type == FILENAME) {
            dgram->packet_type = NONE_AFTER_FILENAME;
        }
    } else if (strcmp(data, "START") == 0) {
        dgram->packet_type = START;
    } else if (strcmp(data, "DATA") == 0) {
        dgram->packet_type = DATA;
    } else if (strcmp(data, "END") == 0) {
        dgram->packet_type = END;
    } else if (dgram->packet_type == NONE_AFTER_FILENAME) {  // Return the receiving into normal
        dgram->packet_type = FILENAME;
    } else if (dgram->packet_type == NONE_AFTER_SENDING) {
        dgram->packet_type = SENDING;
    }
}

void process_question_by_type(program_t *program) {
    set_packet_type(program);

    if (program->dgram->packet_type == START) {
        program->dgram->packet_type = FILENAME;
    } else if (program->dgram->packet_type == FILENAME) {
        process_question_filename_packet(program);
    } else if (program->dgram->packet_type == DATA) {
        // Clean file to write file TODO: Remove this line and have open file all time
        write_content(program, "\0", "w");
        program->dgram->packet_type = SENDING;
    } else if (program->dgram->packet_type == SENDING) {
        process_question_sending_packet(program);
    } else if (program->dgram->packet_type == END) {
        process_question_end_packet(program);
    }
}

void process_question(program_t *program) {
    dns_datagram_t *dgram = program->dgram;

    // Header
    dns_header_t *header = (dns_header_t *)(dgram->sender);

    if (is_resending_packet(program)) {
        return;
    }

    // set new header id
    dgram->id = header->id;

    // Q
    process_question_by_type(program);
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
        if (dgram->packet_type == END) {
            process_question_end_packet(program);
        }
    }
}

void custom_recvfrom(program_t *program) {
    // Q: TODO: Check if socket_address is server or client
    dns_datagram_t *dgram = program->dgram;
    if ((dgram->sender_packet_len = recvfrom(
             dgram->network_info.socket_fd, (char *)dgram->sender, DGRAM_MAX_BUFFER_LENGTH, MSG_WAITALL,
             (struct sockaddr *)&dgram->network_info.socket_address, &dgram->network_info.socket_address_len)) < 0) {
        PERROR_EXIT("Error: recvfrom()\n");
    } else {
        //
        //        dgram->packet_type = START;
        //        dgram->sender[dgram->sender_packet_len] = '\0';
        //        void dns_receiver__on_chunk_received(struct in_addr *source, char *filePath, int chunkId, int
        //        chunkSize);
        DEBUG_PRINT("Ok: recvfrom(): Q len: %lu\n", (size_t)dgram->sender_packet_len);
    }
}

void receive_packets(program_t *program) {
    dns_datagram_t *dgram = program->dgram;

    //
    while (1) {
        custom_recvfrom(program);
        process_question(program);
        DEBUG_PRINT("Ok: process_question():%s", "\n");

        //        if (is_problem_packet_packet(dgram->packet_type)) {
        //            continue;
        //        }

        if (is_not_resend_packet_type(dgram->packet_type)) {
            prepare_answer(dgram);
            DEBUG_PRINT("Ok: process_answer():%s", "\n");
        }

        // Send Answer
        custom_sendto(program);
        reinit_dns_datagram(program, false);
    }
}
