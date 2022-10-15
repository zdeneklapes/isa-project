//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#include <netdb.h>
#include <netinet/in.h>
#include <openssl/aes.h>

#include "../common/base32.h"
#include "../common/dns_helper.h"
#include "arpa/inet.h"
#include "dns.h"
#include "dns_receiver_events.h"
#include "getopt.h"
#include "netinet/ip_icmp.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

typedef struct {
    char base_host[ARGS_LEN];
    char dst_filepath[ARGS_LEN];
} args_t;

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

void receive_packets() {
    int socket_fd;
    char buffer[DNS_BUFFER_LENGTH];
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;  // IPv4
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;  // TODO: Why any?

    // Creating socket file descriptor
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        ERROR_EXIT("socket creation failed", EXIT_FAILURE);
    }
    socklen_t len = sizeof(server_addr);
    int dns_question_length =
        recvfrom(socket_fd, (char *)buffer, DNS_BUFFER_LENGTH, MSG_WAITALL, (struct sockaddr *)&server_addr, &len);
    buffer[dns_question_length] = '\0';

    sendto(socket_fd, (const char *)"Received", strlen("Received"), MSG_CONFIRM, (const struct sockaddr *)&server_addr,
           sizeof(server_addr));

    while (1) {
        break;
    }
    close(socket_fd);
}

int main(int argc, char *argv[]) {
    args_t args;

    if (!parse_args(argc, argv, &args)) {
        printf("Error: arguments for application\nRun ./sender --help for usage message\n");
        return 1;
    }

    receive_packets();
    return 0;
}
