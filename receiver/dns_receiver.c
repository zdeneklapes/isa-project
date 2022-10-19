//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#include <netinet/in.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../common/base32.h"
#include "../common/debug.h"
#include "../common/dns_helper.h"
#include "arpa/inet.h"
#include "dns_receiver_events.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                GLOBAL VARS                               **/
/******************************************************************************/
enum PACKET_TYPE packet_type = START;

/******************************************************************************/
/**                                FUNCTIONS DECLARATION                     **/
/******************************************************************************/
void usage();
static args_t parse_args_or_exit(int, char *[]);
void parse_qname(const args_t *args, datagram_question_chunks_t *qname_by_subdomains, dns_datagram_t *dgram);
bool is_correct_base_host(const args_t *, datagram_question_chunks_t *);
void process_start_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks, const dns_datagram_t *dgram);
void process_last_dgram(args_t *args, dns_datagram_t *dgram);
void process_data_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks, dns_datagram_t *dgram);
void process_question(const args_t *args, dns_datagram_t *dgram);
void prepare_answer(dns_datagram_t *dgram);
void receive_packets(const args_t *);

/******************************************************************************/
/**                                FUNCTIONS DEFINITION                      **/
/******************************************************************************/
void usage() {
    printf(
        "Pouziti:\n"
        "\tdns_receiver {BASE_HOST} {DST_FILEPATH}\n"
        "Parametry:\n"
        "\t{BASE_HOST} slouží k nastavení bázové domény k příjmu dat\n"
        "\t{DST_FILEPATH} cesta pod kterou se budou všechny příchozí data/soubory ukládat (cesta specifikovaná "
        "klientem bude vytvořena pod tímto adresářem)\n"
        "Priklady:\n"
        "\tdns_receiver example.com ./data\n");
    exit(0);
}

static args_t parse_args_or_exit(int argc, char *argv[]) {
    args_t args = {.upstream_dns_ip = {0},
                   .base_host = {0},
                   .dst_filepath = {0},
                   .filename = {0},
                   .file = NULL,
                   .ip_type = IP_TYPE_ERROR};
    struct stat st = {0};

    int c;
    while ((c = getopt(argc, argv, "h")) != -1) {
        switch (c) {
            case 'h':
                usage();
                break;
            case '?' | ':':
            default:
                ERROR_EXIT("Error: Bad option | Missing arg | Some other error -> Run './dns_sender -h' for help\n",
                           EXIT_FAILURE);
        }
    }

    // Bad args
    if (argc != 3)
        ERROR_EXIT("Error: arguments for application\nRun ./sender --help for usage message\n", EXIT_FAILURE);

    // Parse
    // TODO: Validation
    strncpy(args.base_host, argv[1], sizeof(args.base_host));
    strncpy(args.dst_filepath, argv[2], sizeof(args.dst_filepath));

    // Folder not exists
    if (stat(args.dst_filepath, &st) == EXIT_FAILURE) mkdir("foo", 0700);

    return args;
}

void parse_qname(const args_t *args, datagram_question_chunks_t *qname_by_subdomains, dns_datagram_t *dgram) {
    u_char *qname_ptr = (u_char *)(dgram->sender + sizeof(dns_header_t));
    uint8_t subdomain_size = *qname_ptr++;

    //
    while (subdomain_size) {
        // Validate qname
        if (subdomain_size > SUBDOMAIN_NAME_LENGTH || qname_by_subdomains->num_chunks >= SUBDOMAIN_CHUNKS) {
            packet_type = PACKET_TYPE_ERROR;
            ERROR_RETURN("ERROR: qname - Malformed request\n", );
        }

        //
        memset(qname_by_subdomains->chunk[qname_by_subdomains->num_chunks], 0, SUBDOMAIN_NAME_LENGTH);
        memcpy(qname_by_subdomains->chunk[qname_by_subdomains->num_chunks++], (char *)qname_ptr, (int)subdomain_size);
        qname_ptr += subdomain_size + 1;
        subdomain_size = *(qname_ptr - 1);
    }

    // Set packet type
    if (!is_correct_base_host(args, qname_by_subdomains)) {
        packet_type = PACKET_TYPE_ERROR;
    } else if (strcmp(qname_by_subdomains->chunk[0], "START") == 0) {
        packet_type = START;
    } else if (strcmp(qname_by_subdomains->chunk[0], "END") == 0) {
        packet_type = END;
    } else if (strcmp(qname_by_subdomains->chunk[0], "END") != 0 &&
               strcmp(qname_by_subdomains->chunk[0], "START") != 0) {
        packet_type = DATA;
    }
}

bool is_correct_base_host(const args_t *args, datagram_question_chunks_t *qname_chunks) {
    if (qname_chunks->num_chunks < 2) {
        return false;
    }

    char check_base_host[QNAME_MAX_LENGTH] = {0};
    strcat(check_base_host, qname_chunks->chunk[qname_chunks->num_chunks - 2]);
    strcat(check_base_host, ".");
    strcat(check_base_host, qname_chunks->chunk[qname_chunks->num_chunks - 1]);
    return (strcmp(check_base_host, args->base_host) == 0);
}

void process_start_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks, const dns_datagram_t *dgram) {
    CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_transfer_init, (struct in_addr *)&dgram->info.socket_address.sin_addr);

    // Path + Filename
    strcat(UNCONST(args_t *, args)->filename, args->dst_filepath);
    strcat(UNCONST(args_t *, args)->filename, "/");
    strcat(UNCONST(args_t *, args)->filename, qname_chunks->chunk[2]);
    for (int i = 3; i < SUBDOMAIN_NAME_LENGTH; ++i) {
        if (strcmp(qname_chunks->chunk[i], "fend") == 0) break;
        strcat(UNCONST(args_t *, args)->filename, ".");
        strcat(UNCONST(args_t *, args)->filename, qname_chunks->chunk[i]);
    }

    // Recreate (Clean) file
    WRITE_CONTENT("", 0, args, "w");
}

void process_last_dgram(args_t *args, dns_datagram_t *dgram) {
    struct stat st = {0};
    stat(args->filename, &st);
    CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_transfer_completed, args->filename, st.st_size);

    // dgram
    *dgram = init_dns_datagram(args, false);

    // args
    memset(args->filename, 0, ARGS_LEN);
    args->file = NULL;
}

void process_data_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks, dns_datagram_t *dgram) {
    u_char data[QNAME_MAX_LENGTH] = {0};

    for (int i = 0; i + 2 < qname_chunks->num_chunks; ++i) strcat((char *)data, qname_chunks->chunk[i]);

    CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_query_parsed, (char *)args->filename, (char *)data);

    // Decode Data
    u_char data_decoded[QNAME_MAX_LENGTH] = {0};
    dgram->file_data_len = base32_decode(data, data_decoded, QNAME_MAX_LENGTH);

    // Write Data
    WRITE_CONTENT(data_decoded, dgram->file_data_len, args, "a");
}

void process_question(const args_t *args, dns_datagram_t *dgram) {
    // Header
    dns_header_t *dns_header = (dns_header_t *)(dgram->sender);
    if (dns_header->id == dgram->id) {  // FIXME
        packet_type = RESEND;
        return;
    } else {
        dgram->id = dns_header->id;
        packet_type = packet_type == RESEND ? DATA : packet_type;
    }

    // Q
    datagram_question_chunks_t qname_by_subdomains = {0, {{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}}};
    parse_qname(args, &qname_by_subdomains, dgram);
    if (packet_type == START) {
        process_start_dgram(args, &qname_by_subdomains, dgram);
    } else if (packet_type == END) {
        return;  // process_last_dgram(UNCONST(args_t *, args), dgram);
    } else if (packet_type == DATA) {
        process_data_dgram(args, &qname_by_subdomains, dgram);
    }
}

void prepare_answer(dns_datagram_t *dgram) {
    memcpy(dgram->receiver, dgram->sender, DGRAM_MAX_BUFFER_LENGTH);

    // Header
    dns_header_t *dns_header = (dns_header_t *)dgram->receiver;
    dns_header->qr = 1;
    dns_header->aa = 0;
    dns_header->tc = 0;
    dns_header->ra = 0;
    dns_header->rcode = DNS_ANSWER_SUCCESS;
    dns_header->ancount = htons(1);
    dns_header->nscount = 0;
    dns_header->arcount = 0;

    DEBUG_PRINT("Header id: %d\n", dns_header->id);

    // Q
    u_char *question = (dgram->receiver + sizeof(dns_header_t));
    int qname_len = strlen((char *)question);

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
    dgram->receiver_len =
        (int)((u_char *)(dns_answer_fields + 1) - (u_char *)dns_header) - 2;  // TODO: Why do I need (-2)?
}

void receive_packets(const args_t *args) {
    dns_datagram_t dgram = init_dns_datagram(args, false);

    // TODO: timeout

    // TODO: packet with same id

    //
    while (1) {
        // Q
        if ((dgram.sender_len = recvfrom(dgram.info.socket_fd, (char *)dgram.sender, DGRAM_MAX_BUFFER_LENGTH,
                                         MSG_WAITALL, (struct sockaddr *)&dgram.info.socket_address,
                                         &dgram.info.socket_address_len)) == (uint16_t)-1) {
            PERROR_EXIT("Error: recfrom()");
        } else {
            dgram.sender[dgram.sender_len] = '\0';  // TODO: maybe could be sigsegv
            DEBUG_PRINT("Ok: recvfrom(): Q len: %d\n", dgram.sender_len);
        }

        // Process
        process_question(args, &dgram);
        if (packet_type == PACKET_TYPE_ERROR) {
            continue;
        }
        if (packet_type != RESEND) {
            prepare_answer(&dgram);
        }

        if (packet_type == DATA) {
            CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_chunk_received,
                          (struct in_addr *)&dgram.info.socket_address.sin_addr, (char *)args->filename,
                          ((dns_header_t *)dgram.sender)->id, dgram.file_data_len);
        }

        CALL_CALLBACK(DEBUG_BUFFER, print_buffer, dgram.receiver, dgram.receiver_len);

        // A
        if (sendto(dgram.info.socket_fd, dgram.receiver, dgram.receiver_len, CUSTOM_MSG_CONFIRM,
                   (const struct sockaddr *)&dgram.info.socket_address,
                   sizeof(dgram.info.socket_address)) == EXIT_FAILURE) {
            PERROR_EXIT("Error: send_to()\n");
        } else {
            DEBUG_PRINT("Ok: send_to(): A len: %d\n", dgram.receiver_len);
            if (packet_type == END) {
                process_last_dgram(UNCONST(args_t *, args), &dgram);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    //
    args_t args = parse_args_or_exit(argc, argv);

    //
    receive_packets(&args);

    //
    return 0;
}
