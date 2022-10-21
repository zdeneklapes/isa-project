//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#include <netinet/in.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../common/base32.h"
#include "../common/dns_helper.h"
#include "arpa/inet.h"
#include "dns_receiver_events.h"
#include "errno.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                GLOBAL VARS                               **/
/******************************************************************************/
enum PACKET_TYPE packet_type = NOT_RECEIVED;

/******************************************************************************/
/**                                FUNCTIONS DECLARATION                     **/
/******************************************************************************/
/**
 * Print help message
 */
static void usage();

/**
 * Parse command line arguments and return its struct
 * @param argc
 * @param argv
 * @return Initialized args_t struct
 */
static args_t parse_args_or_exit(int argc, char *argv[]);

/**
 * Parse qname from received datagram and set packet type
 * @param args
 * @param qname_by_subdomains
 * @param dgram
 */
static void parse_qname(const args_t *args, datagram_question_chunks_t *qname_by_subdomains, dns_datagram_t *dgram);

/**
 * Check if base_host is same as we get from cli arguments
 * @param args
 * @param qname_chunks
 * @return
 */
static bool is_correct_base_host(const args_t *args, datagram_question_chunks_t *qname_chunks);

/**
 * Process first (START) datagram and create/clean args->dst_filepath
 * @param args
 * @param qname_chunks
 * @param dgram
 */
static void process_start_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks,
                                const dns_datagram_t *dgram);

/**
 * Process last (END) datagram and reinit dns_datagram_t
 * @param args
 * @param dgram
 */
static void process_last_dgram(args_t *args, dns_datagram_t *dgram);

/**
 * Process DATA datagram and append data into file
 * @param args
 * @param qname_chunks
 * @param dgram
 */
static void process_data_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks, dns_datagram_t *dgram);

/**
 * Process whole datagram
 * @param args
 * @param dgram
 */
static void process_question(const args_t *args, dns_datagram_t *dgram);

/**
 * Prepare datagram answer to answer the question, not used if datagram was resend
 * @param dgram
 */
static void prepare_answer(dns_datagram_t *dgram);

/**
 * Custom sento and handle UDP reliability
 * @param args
 * @param dgram
 */
static void custom_sendto(const args_t *args, dns_datagram_t *dgram);

/**
 * Custom receive to and handle UDP reliability
 * @param dgram
 */
static void custom_recvfrom(dns_datagram_t *dgram);

/**
 * Receiving packet + Procesing + Sending answers (Router)
 * @param args
 */
static void receive_packets(const args_t *args);

/**
 * Starting point of this file
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]);

/******************************************************************************/
/**                                FUNCTIONS DEFINITION                      **/
/******************************************************************************/
static void usage() {
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
    strncpy(args.base_host, argv[1], sizeof(args.base_host));
    strncpy(args.dst_filepath, argv[2], sizeof(args.dst_filepath));

    // Validate: base_host
    validate_base_host_exit(args.base_host);

    // Validate: dst_filepath - Folder not exists
    if (stat(args.dst_filepath, &st) == FUNC_FAILURE) {
        mkdir(args.dst_filepath, 0700);
    }

    return args;
}

static void parse_qname(const args_t *args, datagram_question_chunks_t *qname_by_subdomains, dns_datagram_t *dgram) {
    u_char *qname_ptr = (u_char *)(dgram->sender + sizeof(dns_header_t));
    uint8_t subdomain_size = *qname_ptr++;

    //
    while (subdomain_size) {
        // Validate qname
        if (subdomain_size > SUBDOMAIN_NAME_LENGTH || qname_by_subdomains->num_chunks >= SUBDOMAIN_CHUNKS) {
            packet_type = MALFORMED_PACKET;
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
        packet_type = NOT_RECEIVED;  // Bad BASE_HOST
    } else if (strcmp(qname_by_subdomains->chunk[0], "START") == 0) {
        packet_type = START;
    } else if (strcmp(qname_by_subdomains->chunk[0], "END") == 0) {
        packet_type = END;
    } else if (strcmp(qname_by_subdomains->chunk[0], "END") != 0 &&
               strcmp(qname_by_subdomains->chunk[0], "START") != 0) {
        packet_type = DATA;
    }
}

static bool is_correct_base_host(const args_t *args, datagram_question_chunks_t *qname_chunks) {
    if (qname_chunks->num_chunks < 2) {
        return false;
    }

    char check_base_host[QNAME_MAX_LENGTH] = {0};
    strcat(check_base_host, qname_chunks->chunk[qname_chunks->num_chunks - 2]);
    strcat(check_base_host, ".");
    strcat(check_base_host, qname_chunks->chunk[qname_chunks->num_chunks - 1]);
    return (strcmp(check_base_host, args->base_host) == 0);
}

static void process_start_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks,
                                const dns_datagram_t *dgram) {
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
    DEBUG_PRINT("Filename %s\n", args->filename);

    // Recreate (Clean) file
    WRITE_CONTENT("", 0, args, "w");
}

static void process_last_dgram(args_t *args, dns_datagram_t *dgram) {
    struct stat st = {0};
    stat(args->filename, &st);
    CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_transfer_completed, args->filename, st.st_size);

    // dgram
    close(dgram->info.socket_fd);  // Must be here
    *dgram = init_dns_datagram(args, false);

    // args
    memset(args->filename, 0, ARGS_LEN);
    args->file = NULL;

    // Wait for next file
    packet_type = NOT_RECEIVED;
}

static void process_data_dgram(const args_t *args, datagram_question_chunks_t *qname_chunks, dns_datagram_t *dgram) {
    u_char data[QNAME_MAX_LENGTH] = {0};

    for (int i = 0; i + 2 < qname_chunks->num_chunks; ++i) strcat((char *)data, qname_chunks->chunk[i]);

    CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_query_parsed, (char *)args->filename, (char *)data);

    // Decode Data
    u_char data_decoded[QNAME_MAX_LENGTH] = {0};
    dgram->file_data_len = base32_decode(data, data_decoded, QNAME_MAX_LENGTH);

    // Write Data
    WRITE_CONTENT(data_decoded, dgram->file_data_len, args, "a");
}

static void process_question(const args_t *args, dns_datagram_t *dgram) {
    // Header
    dns_header_t *header = (dns_header_t *)(dgram->sender);
    if (header->id == dgram->id) {  // FIXME
        if (packet_type == START || packet_type == END) {
            packet_type = RESEND;
        } else if (packet_type == DATA) {
            packet_type = RESEND_DATA;
        } else {
            // Leave packet_type = packet_type
        }
        return;
    }

    //
    dgram->id = header->id;

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

static void prepare_answer(dns_datagram_t *dgram) {
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
    dgram->receiver_len = (int)((u_char *)(dns_answer_fields + 1) - (u_char *)header) - 2;  // TODO: Why do I need (-2)?
}

static void custom_sendto(const args_t *args, dns_datagram_t *dgram) {
    if (packet_type == DATA || packet_type == RESEND_DATA) {
        CALL_CALLBACK(DEBUG_EVENT, dns_receiver__on_chunk_received,
                      (struct in_addr *)&dgram->info.socket_address.sin_addr, (char *)args->filename,
                      ((dns_header_t *)dgram->sender)->id, dgram->file_data_len);
    }

    DEBUG_PRINT("--\n", NULL);

    // A
    if (sendto(dgram->info.socket_fd, dgram->receiver, dgram->receiver_len, CUSTOM_MSG_CONFIRM,
               (const struct sockaddr *)&dgram->info.socket_address,
               sizeof(dgram->info.socket_address)) == FUNC_FAILURE) {
        PERROR_EXIT("Error: send_to()\n");
    } else {
        DEBUG_PRINT("Ok: send_to(): A len: %llu\n", dgram->receiver_len);
        if (packet_type == END) {
            process_last_dgram(UNCONST(args_t *, args), dgram);
        }
    }
}

static void custom_recvfrom(dns_datagram_t *dgram) {
    // Q
    if ((dgram->sender_len =
             recvfrom(dgram->info.socket_fd, (char *)dgram->sender, DGRAM_MAX_BUFFER_LENGTH, MSG_WAITALL,
                      (struct sockaddr *)&dgram->info.socket_address, &dgram->info.socket_address_len)) < 0) {
        PERROR_EXIT("Error: recvfrom()\n");
    } else {
        //
        packet_type = START;
        dgram->sender[dgram->sender_len] = '\0';  // TODO: maybe could be sigsegv
        DEBUG_PRINT("Ok: recvfrom(): Q len: %llu\n", dgram->sender_len);
    }
}

static void receive_packets(const args_t *args) {
    dns_datagram_t dgram = init_dns_datagram(args, false);

    // TODO: timeout

    // TODO: packet with same id

    //
    while (1) {
        // Q
        custom_recvfrom(&dgram);
        continue;

        // Process
        process_question(args, &dgram);
        DEBUG_PRINT("Ok: process_question():\n", NULL);

        if (is_problem_packet_packet(packet_type)) {
            continue;
        }

        // A
        if (is_not_resend_packet_type(packet_type)) {
            prepare_answer(&dgram);
            DEBUG_PRINT("Ok: process_answer():\n", NULL);
        }

        // A
        custom_sendto(args, &dgram);
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
