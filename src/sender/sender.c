//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

#include "dns.h"
#include "getopt.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define ARGS_LEN 1000

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
    // TODO: handle bad arguments
    opterr = 1;

    int c;
    while (optind < argc) {
        if ((c = getopt(argc, argv, "u:")) != -1) {
            switch (c) {
                case 'u':
                    strncpy(args->base_host, optarg, sizeof(args->base_host));
                    break;
                default:
                    break;
            }
        } else {
            //            printf("%s", optarg);
            optind++;
        }
    }
    printf("%s", args->base_host);
    return true;
}

int main(int argc, char *argv[]) {
    args_t args;

    if (!parse_args(argc, argv, &args)) {
        printf("Bad arguments for application\nRun ./sender --help for usage message\n");
        return 1;
    }
    return 0;
}
