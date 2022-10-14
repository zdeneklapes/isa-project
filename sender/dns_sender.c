//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#include "arpa/inet.h"
#include "dns.h"
#include "dns_sender_events.h"
#include "getopt.h"
#include "netinet/ip_icmp.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define ARGS_LEN 1000
#define MTU 1500

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
        strncpy(args->dst_filepath, argv[optind++], sizeof(args->dst_filepath));
        if (optind + 1 == argc) strncpy(args->src_filepath, argv[optind++], sizeof(args->src_filepath));
        return true;
    } else {
        return false;
    }
}

int main(int argc, char *argv[]) {
    args_t args;

    if (!parse_args(argc, argv, &args)) {
        printf("Bad arguments for application\nRun ./sender --help for usage message\n");
        return 1;
    }

    // Prepare host structure, getaddrinfo

    //

    // send data

    printf("%s\n", args.upstream_dns_ip);
    printf("%s\n", args.base_host);
    printf("%s\n", args.dst_filepath);
    printf("%s\n", args.src_filepath);

    return 0;
}
