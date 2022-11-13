/**
 * Project: ISA - DNS Tunneling
 *
 * @file receiver_implementation.c
 *
 * @brief Implementation of ISA project
 *
 * @author Zdenek Lapes (xlapes02)
 */

/******************************************************************************
 * INCLUDES
 ******************************************************************************/
#include "receiver_implementation.h"

#if TEST_PACKET_LOSS
#include "../middleman/middleman.h"
#endif

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

bool is_resend_or_badbasehost_packet_type(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    return (dgram->packet_type == RESEND_OR_BADBASEHOST__AFTER_FILENAME ||
            dgram->packet_type == RESEND_OR_BADBASEHOST__AFTER_SENDING || dgram->packet_type == WAITING_NEXT_FILE);
}

bool is_base_host_correct(program_t *program, char *base_host) {
    return (strcmp(base_host, program->args->base_host) == 0);
}

void write_content(program_t *program, char *data) {
    args_t *args = program->args;
    if (strlen(args->filename) > DGRAM_MAX_BUFFER_LENGTH) {
        PERROR_EXIT(program, "Filename is too long");
    }
    fwrite(data, program->dgram->data_len, sizeof(char), args->file);
}

/******************************************************************************
 * PROCESSING QUESTION
 ******************************************************************************/
void process_filename_packet(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    args_t *args = program->args;

    /////////////////////////////////
    // DECODE QNAME
    /////////////////////////////////
    char data[QNAME_MAX_LENGTH] = {0};
    char basehost[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(NULL, (u_char *)(program->dgram->sender + sizeof(dns_header_t)), data, NULL, basehost);
    CALL_CALLBACK(EVENT, dns_receiver__on_transfer_init,
                  (struct in_addr *)&dgram->network_info.socket_address.sin_addr);

    strcat(args->filename, data);
    DEBUG_PRINT("Filename: %s\n", args->filename);
}

void process_info_end_packet(program_t *program) {
    char filepath[2 * DGRAM_MAX_BUFFER_LENGTH] = {0};
    get_filepath(program, filepath);
    CALL_CALLBACK(EVENT, dns_receiver__on_transfer_completed, filepath, program->dgram->data_accumulated_len);

    // Reinit program_t
    init_dns_datagram(program);
    reinit_args_struct(program);
}

void process_sending_packet(program_t *program) {
    /////////////////////////////////
    // DECODE QNAME
    /////////////////////////////////
    char data_decoded[QNAME_MAX_LENGTH] = {0};
    char data_encoded[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(program, (u_char *)(program->dgram->sender + sizeof(dns_header_t)), data_decoded,
                           data_encoded, NULL);

    /////////////////////////////////
    // UPDATE dns_datagram_t
    /////////////////////////////////
    program->dgram->data_accumulated_len += program->dgram->data_len;

    /////////////////////////////////
    // PRINT
    /////////////////////////////////
    if (program->dgram->packet_type == SENDING) {
        char filepath[2 * DGRAM_MAX_BUFFER_LENGTH] = {0};
        get_filepath(program, filepath);
        CALL_CALLBACK(EVENT, dns_receiver__on_chunk_received, &program->dgram->network_info.socket_address.sin_addr,
                      filepath, ((dns_header_t *)program->dgram->sender)->id, program->dgram->data_len);
        CALL_CALLBACK(EVENT, dns_receiver__on_query_parsed, filepath, (char *)data_encoded);
    }

    /////////////////////////////////
    // WRITE TO FILE
    /////////////////////////////////
    write_content(program, data_decoded);
}

void process_info_data_packet(program_t *program) {
    args_t *args = program->args;
    /////////////////////////////////
    // WRITE TO FILE
    /////////////////////////////////
    create_filepath(program);
    char filepath[2 * DGRAM_MAX_BUFFER_LENGTH] = {0};
    get_filepath(program, filepath);
    if (!(args->file = fopen(filepath, "w"))) {
        PERROR_EXIT(program, "fopen");
    }
    write_content(program, "\0");
}

bool is_badbasehost_or_resending(program_t *program) {
    char basehost[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(NULL, (u_char *)(program->dgram->sender + sizeof(dns_header_t)), NULL, NULL, basehost);

    //
    if (!is_base_host_correct(program, basehost) || is_resending_packet(program)) {
        return true;
    } else {
        return false;
    }
}

void set_packet_type(program_t *program) {
    dns_datagram_t *dgram = program->dgram;
    /////////////////////////////////
    // DECODE QNAME
    /////////////////////////////////
    char data[QNAME_MAX_LENGTH] = {0};
    char basehost[QNAME_MAX_LENGTH] = {0};
    parse_dns_packet_qname(NULL, (u_char *)(program->dgram->sender + sizeof(dns_header_t)), data, NULL, basehost);

    if (program->dgram->packet_type == WAITING_NEXT_FILE) {
        if (strcmp(data, "START") == 0) {
            dgram->packet_type = START;
        } else {
            return;
        }
    }

    /////////////////////////////////
    // Set packet type
    /////////////////////////////////
    // Step X
    if (dgram->packet_type == START) {
        program->dgram->packet_type = FILENAME;
    } else if (dgram->packet_type == DATA) {
        program->dgram->packet_type = SENDING;
    }

    // Step X
    if (is_badbasehost_or_resending(program)) {
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
        dgram->packet_type = FILENAME;
    } else if (dgram->packet_type == RESEND_OR_BADBASEHOST__AFTER_SENDING) {  // Return the receiving into normal
        dgram->packet_type = SENDING;
    }
}

void process_question(program_t *program) {
    set_packet_type(program);

    /////////////////////////////////
    // HANDLE Resending packet
    /////////////////////////////////
    if (is_resend_or_badbasehost_packet_type(program)) {
        return;
    } else {
        /////////////////////////////////
        // PROCESS By packet type
        /////////////////////////////////
        if (program->dgram->packet_type == START) {
            init_dns_datagram_before_info_start_packet(program);
        } else if (program->dgram->packet_type == FILENAME) {
            process_filename_packet(program);
        } else if (program->dgram->packet_type == DATA) {
            process_info_data_packet(program);
        } else if (program->dgram->packet_type == SENDING) {
            process_sending_packet(program);
        }

        /////////////////////////////////
        // UPDATE dns_datagram_t
        /////////////////////////////////
        // must be here because process* function cleaning it
        program->dgram->id = ((dns_header_t *)program->dgram->sender)->id;
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
void receive_packets(program_t *program) {
    dns_datagram_t *dgram = program->dgram;

    //
    while (1) {
        /////////////////////////////////
        // QUESTION
        /////////////////////////////////
        if ((dgram->sender_packet_len =
                 recvfrom(dgram->network_info.socket_fd, (char *)dgram->sender, DGRAM_MAX_BUFFER_LENGTH, MSG_WAITALL,
                          (struct sockaddr *)&dgram->network_info.socket_address,
                          &dgram->network_info.socket_address_len)) < 0) {
            PERROR_EXIT(program, "Error: recvfrom()");
        }

        /////////////////////////////////
        // PROCESS QUESTION
        /////////////////////////////////
        process_question(program);

        /////////////////////////////////
        // PREPARE ANSWER
        /////////////////////////////////
        if (is_resend_or_badbasehost_packet_type(program)) {
            DEBUG_PRINT("CONTINUE; Packet_id/Stored_id: %d/%d\n", ((dns_header_t *)dgram->sender)->id, dgram->id);
            continue;
        } else {
            prepare_answer(dgram);
        }

        /////////////////////////////////
        // ANSWER
        /////////////////////////////////
        /////////////////////////////////
        // TEST DROPPED PACKET
        /////////////////////////////////
#if TEST_PACKET_LOSS
        bool is_packet_dropped = middleman_drop_receiver_packets(program);
    sendto_answer:
#endif
        if (sendto(dgram->network_info.socket_fd, dgram->receiver, dgram->receiver_packet_len, CUSTOM_MSG_CONFIRM,
                   (const struct sockaddr *)&dgram->network_info.socket_address,
                   sizeof(dgram->network_info.socket_address)) == FUNC_FAILURE) {
            PERROR_EXIT(program, "Error: send_to()\n");
        } else {
#if TEST_PACKET_LOSS
            if (is_packet_dropped) {
                is_packet_dropped = middleman_fix_receiver_packets(program);
                goto sendto_answer;
            }
#endif
        }

        /////////////////////////////////
        // RESET - (Must be here, because sender need answer before clean whole dgram)
        /////////////////////////////////
        if (program->dgram->packet_type == END) {
            process_info_end_packet(program);
        } else {
            init_dns_datagram_after_info_end_packet(program);
        }
    }
}
