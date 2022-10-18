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
void process_qname_and_set_packet_type(u_char *dns_datagram, datagram_question_chunks_t *qname_chunks,
                                       const args_t *args);
bool is_correct_base_host(const args_t *, datagram_question_chunks_t *);
void process_start_datagram(const args_t *args, datagram_question_chunks_t *qname_chunks);
void process_end_datagram(args_t *);
void process_data_datagram(const args_t *, datagram_question_chunks_t *);
void process_datagram(u_char *dns_datagram, const args_t *args);
int set_next_dns_answer(u_char *);
void receive_packets(const args_t *);

/******************************************************************************/
/**                                FUNCTIONS DEFINITION                      **/
/******************************************************************************/
void usage() {
    printf("USAGE:");
    exit(0);
}

static args_t parse_args_or_exit(int argc, char *argv[]) {
    args_t args = {.base_host = {0}, .dst_filepath = {0}, .filename = {0}, .file = NULL, .sender_process_id = 0};
    struct stat st = {0};

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

void process_qname_and_set_packet_type(u_char *dns_datagram, datagram_question_chunks_t *qname_chunks,
                                       const args_t *args) {
    u_char *qname_ptr = (u_char *)(dns_datagram + sizeof(dns_header_t));
    uint8_t subdomain_size = *qname_ptr++;

    //
    while (subdomain_size) {
        // Validate qname
        if (subdomain_size > SUBDOMAIN_NAME_LENGTH || qname_chunks->num_chunks >= SUBDOMAIN_CHUNKS) {
            packet_type = PACKET_TYPE_ERROR;
            ERROR_RETURN("ERROR: qname - Malformed request\n", );
        }

        //
        memset(qname_chunks->chunk[qname_chunks->num_chunks], 0, SUBDOMAIN_NAME_LENGTH);
        memcpy(qname_chunks->chunk[qname_chunks->num_chunks++], (char *)qname_ptr, (int)subdomain_size);
        qname_ptr += subdomain_size + 1;
        subdomain_size = *(qname_ptr - 1);
    }

    // Set packet type
    if (!is_correct_base_host(args, qname_chunks)) {
        packet_type = PACKET_TYPE_ERROR;
        return;
    }
    if (strcmp(qname_chunks->chunk[0], "START") == 0) {
        packet_type = START;
    }
    if (strcmp(qname_chunks->chunk[0], "END") == 0) {
        packet_type = END;
    }
    if (strcmp(qname_chunks->chunk[0], "END") != 0  // prevent auto format
        && strcmp(qname_chunks->chunk[0], "START") != 0) {
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

void process_start_datagram(const args_t *args, datagram_question_chunks_t *qname_chunks) {
    // Path + Filename
    strcat(UNCONST(args_t *, args)->filename, args->dst_filepath);
    strcat(UNCONST(args_t *, args)->filename, "/");
    strcat(UNCONST(args_t *, args)->filename, qname_chunks->chunk[2]);
    for (int i = 3; i < SUBDOMAIN_NAME_LENGTH; ++i) {
        if (strcmp(qname_chunks->chunk[i], "fend") == 0) break;
        strcat(UNCONST(args_t *, args)->filename, ".");
        strcat(UNCONST(args_t *, args)->filename, qname_chunks->chunk[i]);
    }

    //
    WRITE_CONTENT("", 0, args, "w");  // Recreate (clean) file
}

void process_end_datagram(args_t *args) {
    args->sender_process_id = 0;
    memset(args->filename, 0, ARGS_LEN);
    args->file = NULL;
}

void process_data_datagram(const args_t *args, datagram_question_chunks_t *qname_chunks) {
    u_int8_t data[QNAME_MAX_LENGTH] = {0};

    for (int i = 0; i + 2 < qname_chunks->num_chunks; ++i) strcat((char *)data, qname_chunks->chunk[i]);

    // Decode Data
    uint8_t data_decoded[QNAME_MAX_LENGTH] = {0};
    int data_decoded_len = base32_decode(data, data_decoded, QNAME_MAX_LENGTH);

    // Write Data
    WRITE_CONTENT(data_decoded, data_decoded_len, args, "a");
}

void process_dgram_header_and_set_packet_type(u_char *dns_datagram, const args_t *args) {
    dns_header_t *dns_header = (dns_header_t *)(dns_datagram);
    if (dns_header->id == args->sender_process_id) {
        packet_type = RESEND;
    } else {
        UNCONST(args_t *, args)->sender_process_id = dns_header->id;
        packet_type = packet_type == RESEND ? DATA : packet_type;
    }
}

void process_datagram(u_char *dns_datagram, const args_t *args) {
    process_dgram_header_and_set_packet_type(dns_datagram, args);
    if (packet_type == RESEND) return;

    datagram_question_chunks_t qname_chunks = {0, {{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}}};
    process_qname_and_set_packet_type(dns_datagram, &qname_chunks, args);

    // Q
    if (packet_type == START) process_start_datagram(args, &qname_chunks);
    if (packet_type == END) process_end_datagram(UNCONST(args_t *, args));
    if (packet_type == DATA) process_data_datagram(args, &qname_chunks);
}

int set_next_dns_answer(u_char *dns_datagram) {
    // Header
    dns_header_t *dns_header = (dns_header_t *)dns_datagram;
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
    u_char *dns_question = (dns_datagram + sizeof(dns_header_t));
    size_t qname_len = strlen((char *)dns_question);

    // A qname
    u_char *dns_answer = (dns_question + qname_len + 1 + sizeof(dns_question_fields_t));
    memcpy(dns_answer, dns_question, qname_len);

    // A fields
    dns_answer_fields_t *dns_answer_fields = (dns_answer_fields_t *)(dns_answer + qname_len + 1);
    dns_answer_fields->type = htons(DNS_TYPE_A);
    dns_answer_fields->qclass = htons(DNS_CLASS_IN);
    dns_answer_fields->ttl = htons(TTL);
    dns_answer_fields->rdlength = htons(4);
    inet_pton(AF_INET, LOCALHOST, &dns_answer_fields->rdata);

    // Length
    return (int)((u_char *)(dns_answer_fields + 1) - (u_char *)dns_header) - 2;  // TODO: Why do I need (-2)?
}

void receive_packets(const args_t *args) {
    int socket_fd = 0;
    u_char dns_datagram[DGRAM_MAX_BUFFER_LENGTH] = {0};
    size_t dns_datagram_len = 0;
    struct sockaddr_in socket_address = {
        .sin_family = AF_INET, .sin_port = htons(DNS_PORT), .sin_addr.s_addr = INADDR_ANY};
    socklen_t len = sizeof(socket_address);
    int dns_datagram_len_new = 0;

    // TODO: timeout

    // TODO: packet with same id

    //
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == EXIT_FAILURE) PERROR("Error: socket()");

    DEBUG_PRINT("Ok: socket()\n", NULL);

    if (bind(socket_fd, (const struct sockaddr *)&socket_address, sizeof(socket_address)) == EXIT_FAILURE)
        PERROR("Error: bind()");

    DEBUG_PRINT("Ok: bind()\n", NULL);

    //
    while (1) {
        // Q
        if ((dns_datagram_len = recvfrom(socket_fd, (char *)dns_datagram, DGRAM_MAX_BUFFER_LENGTH, MSG_WAITALL,
                                         (struct sockaddr *)&socket_address, &len)) == (size_t)-1) {
            PERROR("Error: recfrom()");
        }
        dns_datagram[dns_datagram_len] = '\0';  // TODO: maybe could be sigsegv
        DEBUG_PRINT("Ok: recvfrom(): Q len: %zu\n", dns_datagram_len);

        // Process
        process_datagram(dns_datagram, args);
        if (packet_type == PACKET_TYPE_ERROR) continue;

        DEBUG_PRINT("Ok: process_datagram()\n", NULL);

        // A
        if (packet_type != RESEND) {
            dns_datagram_len_new = set_next_dns_answer(dns_datagram);
        }
        print_buffer(dns_datagram, dns_datagram_len_new);
        if (sendto(socket_fd, dns_datagram, dns_datagram_len_new, CUSTOM_MSG_CONFIRM,
                   (const struct sockaddr *)&socket_address, sizeof(socket_address)) == EXIT_FAILURE) {
            PERROR("Error: send_to()\n");
        }

        DEBUG_PRINT("Ok: send_to(): A len: %zu\n", dns_datagram_len);
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
