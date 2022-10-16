//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#include <netdb.h>
#include <netinet/in.h>
#include <openssl/aes.h>

#include "../common/base32.h"
#include "../common/debug.h"
#include "../common/dns_helper.h"
#include "arpa/inet.h"
#include "dns_receiver_events.h"
#include "getopt.h"
#include "netinet/ip_icmp.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                STRUCTS                                   **/
/******************************************************************************/
typedef struct {
    char base_host[ARGS_LEN];
    char dst_filepath[ARGS_LEN];

    // from datagram
    char filename[ARGS_LEN];
    FILE *file;
    uint16_t sender_process_id;
} args_t;

/******************************************************************************/
/**                                FUNCTIONS DECLARATION                     **/
/******************************************************************************/
void usage();
bool parse_args(int, char *[], args_t *);
enum PACKET_TYPE process_datagram(u_char *dns_datagram, const args_t *args);
int set_next_dns_answer(u_char *);
void receive_packets();

/******************************************************************************/
/**                                FUNCTIONS DEFINITION                      **/
/******************************************************************************/
void usage() {
    printf("USAGE:");
    exit(0);
}

bool parse_args(int argc, char *argv[], args_t *args) {
    if (argc != 3) return false;
    strncpy(args->base_host, argv[1], sizeof(args->base_host));
    strncpy(args->dst_filepath, argv[2], sizeof(args->dst_filepath));
    return true;
}

void decode_qname(u_char *dns_datagram, datagram_question_chunks_t *qname_chunks) {
    u_char *qname_ptr = (u_char *)(dns_datagram + sizeof(dns_header_t));
    uint8_t subdomain_size = *qname_ptr++;
    while (subdomain_size) {
        if (subdomain_size > SUBDOMAIN_NAME_LENGTH) {
            // TODO: Handle bad requests
            DEBUG_PRINT("ERROR: Malformed request%s", "\n");
        }
        memset(qname_chunks->chunk[qname_chunks->num_chunks], 0, SUBDOMAIN_NAME_LENGTH);
        memcpy(qname_chunks->chunk[qname_chunks->num_chunks++], (char *)qname_ptr, (int)subdomain_size);
        qname_ptr += subdomain_size + 1;
        subdomain_size = *(qname_ptr - 1);
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

void process_start_datagram(const args_t *args, datagram_question_chunks_t *qname_chunks, uint16_t id) {
    // TODO: Solve path better

    // Process ID
    UNCONST(args_t *, args)->sender_process_id = id;

    // Filename
    strcat(UNCONST(args_t *, args)->filename, args->dst_filepath);
    strcat(UNCONST(args_t *, args)->filename, "/");
    strcat(UNCONST(args_t *, args)->filename, qname_chunks->chunk[2]);
    for (int i = 3; i < SUBDOMAIN_NAME_LENGTH; ++i) {
        if (strcmp(qname_chunks->chunk[i], "fend") == 0) break;
        strcat(UNCONST(args_t *, args)->filename, ".");
        strcat(UNCONST(args_t *, args)->filename, qname_chunks->chunk[i]);
    }

    // Recreate (clean) file
    UNCONST(args_t *, args)->file = fopen(args->filename, "w");
    fclose(args->file);
}

void process_end_datagram(args_t *args) {
    args->sender_process_id = 0;
    memset(args->filename, 0, ARGS_LEN);
    args->file = NULL;
}

void process_data_datagram(const args_t *args, datagram_question_chunks_t *qname_chunks) {
    u_int8_t data[QNAME_MAX_LENGTH] = {0};
    for (int i = 0; i + 2 < qname_chunks->num_chunks; ++i) {
        strcat((char *)data, qname_chunks->chunk[i]);
    }

    // Decode Data
    uint8_t data_decoded[QNAME_MAX_LENGTH] = {0};
    int data_decoded_len = base32_decode(data, data_decoded, QNAME_MAX_LENGTH);
    (void)data_decoded_len;

    UNCONST(args_t *, args)->file = fopen(args->filename, "a");
    fwrite(data_decoded, data_decoded_len, sizeof(char), args->file);
    fclose(args->file);
}

enum PACKET_TYPE process_datagram(u_char *dns_datagram, const args_t *args) {
    datagram_question_chunks_t qname_chunks = {0, {{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}}};
    decode_qname(dns_datagram, &qname_chunks);

    // Bad datagram
    if (!is_correct_base_host(args, &qname_chunks)) {
        return UNKNOWN;
    }

    // Start datagram
    if (strcmp(qname_chunks.chunk[0], "START") == 0) {
        process_start_datagram(args, &qname_chunks, ((dns_header_t *)(dns_datagram))->id);
        return START;
    }

    // End datagram
    if (strcmp(qname_chunks.chunk[0], "END") == 0) {
        process_end_datagram(UNCONST(args_t *, args));
        return END;
    }

    // Data datagram
    process_data_datagram(args, &qname_chunks);
    return DATA;
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
    int qname_len = strlen((char *)dns_question);

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
    (void)args;
    int socket_fd = 0;
    u_char dns_datagram[DGRAM_MAX_BUFFER_LENGTH] = {0};
    int dns_datagram_len = 0;
    struct sockaddr_in socket_address = {
        .sin_family = AF_INET, .sin_port = htons(DNS_PORT), .sin_addr.s_addr = INADDR_ANY};
    socklen_t len = sizeof(socket_address);
    enum PACKET_TYPE packet_type = START;

    // TODO: base_host check are same

    //
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) ERROR_EXIT("socket creation failed", EXIT_FAILURE);
    DEBUG_PRINT("Created socket%s", "\n");
    if (bind(socket_fd, (const struct sockaddr *)&socket_address, sizeof(socket_address)) == -1)
        PERROR_EXIT("Error: bind failed", EXIT_FAILURE);
    DEBUG_PRINT("Bind socket%s", "\n");

    //
    while (1) {
        // Receive
        if ((dns_datagram_len = recvfrom(socket_fd, (char *)dns_datagram, DGRAM_MAX_BUFFER_LENGTH, MSG_WAITALL,
                                         (struct sockaddr *)&socket_address, &len)) == -1) {
            PERROR_EXIT("Error: recfrom", EXIT_FAILURE);
        }
        dns_datagram[dns_datagram_len] = '\0';
        DEBUG_PRINT("Received question len: %d\n", dns_datagram_len);

        // Process
        packet_type = process_datagram(dns_datagram, args);
        if (packet_type == UNKNOWN) continue;
        DEBUG_PRINT("Save data %s", "\n");

        // Send
        int dns_datagram_len_new = set_next_dns_answer(dns_datagram);
        print_buffer(dns_datagram, dns_datagram_len_new);
        if (sendto(socket_fd, dns_datagram, dns_datagram_len_new, CUSTOM_MSG_CONFIRM,
                   (const struct sockaddr *)&socket_address, sizeof(socket_address)) == -1) {
            PERROR_EXIT("Error: send socket", EXIT_FAILURE);
        }

        DEBUG_PRINT("Sent answer len: %d\n", dns_datagram_len_new);
    }
    //    close(socket_fd); // TODO: Close socket
}

static args_t init_args_struct() {
    args_t args = {.base_host = {0}, .dst_filepath = {0}, .filename = {0}, .file = NULL, .sender_process_id = 0};
    return args;
}

int main(int argc, char *argv[]) {
    args_t args = init_args_struct();

    //
    if (!parse_args(argc, argv, &args)) {
        printf("Error: arguments for application\nRun ./sender --help for usage message\n");
        return 1;
    }
    receive_packets(&args);

    //
    return 0;
}
