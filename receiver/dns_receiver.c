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
} args_t;

/******************************************************************************/
/**                                FUNCTIONS DECLARATION                     **/
/******************************************************************************/
void usage();
bool parse_args(int, char *[], args_t *);
void save_data(u_char *);
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

void save_data(u_char *dns_datagram) {
    DEBUG_PRINT("%s\n", dns_datagram);
    return;
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

    //
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) ERROR_EXIT("socket creation failed", EXIT_FAILURE);
    DEBUG_PRINT("Created socket%s", "\n");
    if (bind(socket_fd, (const struct sockaddr *)&socket_address, sizeof(socket_address)) == -1)
        PERROR_EXIT("Error: bind failed", EXIT_FAILURE);
    DEBUG_PRINT("Bind socket%s", "\n");

    //
    while (1) {
        if ((dns_datagram_len = recvfrom(socket_fd, (char *)dns_datagram, DGRAM_MAX_BUFFER_LENGTH, MSG_WAITALL,
                                         (struct sockaddr *)&socket_address, &len)) == -1) {
            PERROR_EXIT("Error: recfrom", EXIT_FAILURE);
        }
        dns_datagram[dns_datagram_len] = '\0';

        DEBUG_PRINT("Received question len: %d\n", dns_datagram_len);

        int dns_datagram_len_new = set_next_dns_answer(dns_datagram);
        print_buffer(dns_datagram, dns_datagram_len_new);
        save_data(dns_datagram);

        DEBUG_PRINT("Save data %s", "\n");

        if (sendto(socket_fd, dns_datagram, dns_datagram_len_new, CUSTOM_MSG_CONFIRM,
                   (const struct sockaddr *)&socket_address, sizeof(socket_address)) == -1) {
            PERROR_EXIT("Error: send socket", EXIT_FAILURE);
        }

        DEBUG_PRINT("Sent answer len: %d\n", dns_datagram_len_new);
    }
    //    close(socket_fd); // TODO: Close socket
}

int main(int argc, char *argv[]) {
    args_t args;

    if (!parse_args(argc, argv, &args)) {
        printf("Error: arguments for application\nRun ./sender --help for usage message\n");
        return 1;
    }

    receive_packets(&args);
    return 0;
}
