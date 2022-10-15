//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

// TODO: Includes: https://sites.uclouvain.be/SystInfo/usr/include/bits/socket.h.html
// TODO: Inspiration: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

#include <netdb.h>
#include <netinet/in.h>
#include <openssl/aes.h>

#include "../common/base32.h"
#include "../common/dns_helper.h"
#include "arpa/inet.h"
#include "dns.h"
#include "dns_sender_events.h"
#include "getopt.h"
#include "math.h"
#include "netinet/ip_icmp.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define ARGS_LEN 1000
#define DOMAIN_NAME_LENGTH
#define BASE32_LENGTH_ENCODE(src_size) (((src_size)*8 + 4) / 5)
#define BASE32_LENGTH_DECODE(src_size) (ceil(src_size / 1.6))

#define MSG_CONFIRM 0x800
#define ERROR_EXIT(msg, exit_code) \
    do {                           \
        fprintf(stderr, (msg));    \
        exit(exit_code);           \
    } while (0)

typedef struct {
    char upstream_dns_ip[ARGS_LEN];
    char base_host[ARGS_LEN];
    char dst_filepath[ARGS_LEN];
    char src_filepath[ARGS_LEN];
} args_t;

void usage() {
    printf("USAGE:");
    exit(0);
}

bool parse_args(int argc, char *argv[], args_t *args) {
    // Useful tutorial: https://azrael.digipen.edu/~mmead/www/Courses/CS180/getopt.html
    opterr = 1;

    int c;
    while ((c = getopt(argc, argv, "u:h")) != -1) {
        switch (c) {
            case 'u':
                strncpy(args->upstream_dns_ip, optarg, sizeof(args->upstream_dns_ip));
                break;
            case 'h':
                usage();
                break;
            case '?':
                printf("Unknown option: %c\n", optopt);
                return 1;
            case ':':
                printf("Missing arg for %c\n", optopt);
                return 1;
            default:
                return 1;
        }
    }

    if (optind + 2 == argc || optind + 3 == argc) {
        strncpy(args->base_host, argv[optind++], sizeof(args->base_host));
        strncpy(args->src_filepath, argv[optind++], sizeof(args->src_filepath));
        if (optind + 1 == argc) strncpy(args->dst_filepath, argv[optind++], sizeof(args->dst_filepath));
        return true;
    } else {
        return false;
    }
}

void init_args_struct(args_t *args) {
    memset(args->base_host, '\0', sizeof(args->base_host));
    memset(args->dst_filepath, '\0', sizeof(args->dst_filepath));
    memset(args->src_filepath, '\0', sizeof(args->src_filepath));
    memset(args->upstream_dns_ip, '\0', sizeof(args->upstream_dns_ip));
}

bool get_dns_servers(args_t *args) {
    FILE *fp;
    char line[200], *p;
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
        printf("Failed opening /etc/resolv.conf file \n");
        return false;
    }

    while (fgets(line, 200, fp)) {
        if (line[0] == '#') {
            continue;
        }
        if (strncmp(line, "nameserver", 10) == 0) {
            p = strtok(line, " ");
            p = strtok(NULL, " ");
        }
    }

    if (strcmp(p, "") == 0) {
        return false;
    } else {
        strcpy(args->upstream_dns_ip, p);
    }

    return true;
}

/**
 * Odesila paketu na server.
 * @param file File pointer if specified, stdin pointer otherwise
 * @param args Struct pointer to application arguments
 */
void send_packets(FILE *file, const args_t *args) {
    char dns_buffer[DOMAIN_NAME_LENGTH] = {0};
    while (feof(file)) {
        // TODO: encode
        fread(dns_buffer, 2, 1, file);
        printf("1-%s", dns_buffer);
    }  // TODO: Move sending paxket into while loop

    int buffer_length = 0;  // TODO

    // Set Header field
    struct dns_header_s *dns_header = NULL;
    dns_header->id = htons(1000);    // TODO: how to set unique id?
    dns_header->rd = 1;              // TODO: What
    dns_header->qdcount = htons(1);  // TODO: What

    // Set Question name

    // Finally set Question other fields

    // Create Socket
    int socket_fd;
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        ERROR_EXIT("socket creation failed", EXIT_FAILURE);
    }

    // in_addr
    struct in_addr ip;
    inet_aton(args->upstream_dns_ip, &ip);

    // sockaddr_in
    struct sockaddr_in socket_addr;
    socket_addr.sin_addr = ip;
    socket_addr.sin_family = AF_INET;  // IPv4
    socket_addr.sin_port = htons(DNS_PORT);
    if (sendto(socket_fd, dns_buffer, buffer_length, MSG_CONFIRM, (struct sockaddr *)&socket_addr,
               sizeof(struct sockaddr_in)) == -1) {
        ERROR_EXIT("sendto failed", EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    args_t args;
    init_args_struct(&args);

    if (!parse_args(argc, argv, &args)) {
        ERROR_EXIT("Error: arguments for application\nRun ./sender --help for usage message\n", EXIT_FAILURE);
    }

    FILE *file = strcmp(args.src_filepath, "") != 0 ? fopen(args.src_filepath, "r") : stdin;
    if (!file) {
        ERROR_EXIT("Error: file path\n", EXIT_FAILURE);
    }

    if (strncmp(args.upstream_dns_ip, "", sizeof(args.upstream_dns_ip)) == 0) {
        if (!get_dns_servers(&args)) ERROR_EXIT("Error: get dns server from /etc/resolv.conf\n", EXIT_FAILURE);
    }

    send_packets(file, &args);

    fclose(file);
    return 0;
}
