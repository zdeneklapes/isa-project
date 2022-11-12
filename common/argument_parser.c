//
// Created by Zdeněk Lapeš on 07/11/2022.
//
/******************************************************************************/
/**                                 INCLUDES                                 **/
/******************************************************************************/
#include "argument_parser.h"

#include "initializations.h"

/******************************************************************************/
/**                                 FUNCTIONS DEFINITION                     **/
/******************************************************************************/
int check_switchers_and_argc(int argc, char *argv[], int i, args_t *args) {
    if (argc == i) {
        return i;
    }

    if (strcmp(argv[i], "-u") == 0) {
        if (argc == i + 1) {
            ERROR_EXIT("Missing argument for -u", EXIT_FAILURE);
        }
        strcpy(args->upstream_dns_ip, argv[i + 1]);
        return i + 2;
    }

    if (strcmp(argv[i], "-h") == 0) {
        usage();
    }

    return i;
}

void get_dns_servers_from_system(program_t *program) {
    FILE *fp = NULL;
    char line[QNAME_MAX_LENGTH] = {0};
    char *p = NULL;
    const char finding_name[] = "nameserver";

    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
        ERROR_EXIT("Failed opening /etc/resolv.conf file \n", EXIT_FAILURE);
    }

    while (fgets(line, 200, fp)) {
        if (line[0] == '#') {
            continue;
        }

        //
        if (strncmp(line, finding_name, strlen(finding_name)) == 0) {
            if (line[strlen(finding_name)] && line[strlen(finding_name)] == '\t') {
                p = strtok(line, "\t");
                p = strtok(NULL, "\t");
            } else if (line[strlen(finding_name)] && line[strlen(finding_name)] == ' ') {
                p = strtok(line, " ");
                p = strtok(NULL, " ");
            }
            if (p && p[strlen(p) - 1] && p[strlen(p) - 1] == '\n') {
                p[strlen(p) - 1] = '\0';
            }
            if (ip_version(p) == IPv4) {
                break;
            }
        }
    }

    if (!p) {
        dealocate_all_exit(program, EXIT_FAILURE, "Failed parsing /etc/resolv.conf file \n");
    } else if (!is_empty_str(p) && ip_version(p) == IPv4) {
        strcpy(program->args->upstream_dns_ip, p);
    } else {
        dealocate_all_exit(program, EXIT_FAILURE, "Failed parsing /etc/resolv.conf file \n");
    }
}

void validate_base_host_exit(program_t *program) {
    char *base_host = program->args->base_host;
    char *next_token = NULL;
    char base_host_copy[DGRAM_MAX_BUFFER_LENGTH] = {0};
    char *delim = ".";
    memcpy(base_host_copy, base_host, strlen(base_host));

    // BASE not set
    if (strcmp(base_host, "") == 0) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host\n");
    }

    // BASE_HOST URL max len
    next_token = strtok(base_host_copy, delim);
    if (strlen(next_token) > SUBDOMAIN_NAME_LENGTH) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host - Run ./dns_sender --help \n");
    }

    // EXTENSION of url
    next_token = strtok(NULL, delim);
    if (strlen(next_token) > SUBDOMAIN_NAME_LENGTH) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host - Run ./dns_sender --help \n");
    }

    // END of BASE_HOST URL
    next_token = strtok(NULL, delim);
    if (next_token) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host - Run ./dns_sender --help \n");
    }
}

void validate_dst_filepath(program_t *program) {
    args_t *args = program->args;

    if (strlen(args->dst_filepath) > DGRAM_MAX_BUFFER_LENGTH || strcmp(args->dst_filepath, "") == 0) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: dst_filepath - Run ./dns_sender --help \n");
    }
}

const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";
    return dot + 1;
}

void validate_filename(program_t *program) {
    args_t *args = program->args;

    if (strcmp(args->filename, "") != 0) {
        if (access(args->filename, F_OK) == FUNC_FAILURE) {
            dealocate_all_exit(program, EXIT_FAILURE, "Error: filename\n");
        }
    }

    // Set and Validate: file, filename (Open)
    if (strcmp(args->filename, "") == 0) {
        args->file = stdin;
        //    } else if (strcmp(get_filename_ext(program->args->filename), "") == 0) {
        //        if ((args->file = fopen(args->filename, "rb")) == NULL) {
        //            dealocate_all_exit(program, EXIT_FAILURE, "Error: filename\n");
        //        }
    } else {
        if ((args->file = fopen(args->filename, "r")) == NULL) {
            dealocate_all_exit(program, EXIT_FAILURE, "Error: filename\n");
        }
    }
}

void validate_upstream_dns_ip(program_t *program) {
    args_t *args = program->args;
    if (strcmp(args->upstream_dns_ip, "") == 0) {
        get_dns_servers_from_system(program);  // exit on failure
    }
    if ((args->ip_type = ip_version(args->upstream_dns_ip)) == IP_TYPE_ERROR) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: Invalid IP format\n");
    }
}

void validate_args(int i, program_t *program) {
    //
    if (i > program->argc || i < 3 || i > 6) {
        dealocate_all_exit(program, EXIT_FAILURE, "Bad arguments for dns_sender\n");
    }

    //
    validate_upstream_dns_ip(program);
    validate_dst_filepath(program);
    validate_filename(program);
    validate_base_host_exit(program);
}

void set_args_sender(program_t *program) {
    int argc = program->argc;
    char **argv = program->argv;
    init_args_struct(program);

    int i = 1;
    for (; i < argc;) {
        if ((i = check_switchers_and_argc(argc, argv, i, program->args)) == FUNC_OK) {
            break;
        }
        CHECK_NULL(argv[i])
        program->args->base_host = argv[i++];
        CHECK_NULL(argv[i])
        if ((i = check_switchers_and_argc(argc, argv, i, program->args)) == FUNC_OK) {
            break;
        }
        CHECK_NULL(argv[i])
        program->args->dst_filepath = argv[i++];
        CHECK_NULL(argv[i])
        if ((i = check_switchers_and_argc(argc, argv, i, program->args)) == FUNC_OK) {
            break;
        }
        CHECK_NULL(argv[i])
        //
        if (strlen(argv[i]) >= DGRAM_MAX_BUFFER_LENGTH) {
            dealocate_all_exit(program, EXIT_FAILURE, "Error: filename too long.\n");
        }
        strcpy(program->args->filename, argv[i++]);
        //
        if ((i = check_switchers_and_argc(argc, argv, i, program->args)) == argc) {
            break;
        }
    }

    validate_args(i, program);
}

void set_args_receiver(program_t *program) {
    struct stat st = {0};
    init_args_struct(program);

    int c;
    while ((c = getopt(program->argc, program->argv, "h")) != -1) {
        switch (c) {
            case 'h':
                usage();
                break;
            case '?' | ':':
            default:
                dealocate_all_exit(program, EXIT_FAILURE, "Bad arguments for dns_receiver\n");
        }
    }

    // Bad args
    if (program->argc != 3) {
        dealocate_all_exit(program, EXIT_FAILURE, "Bad arguments for dns_receiver\n");
    }

    // Parse
    program->args->base_host = program->argv[1];
    program->args->dst_filepath = program->argv[2];

    // Validate: base_host
    validate_base_host_exit(program);

    // Validate: dst_filepath - Folder not exists
    if (stat(program->args->dst_filepath, &st) == FUNC_FAILURE) {
        mkdir(program->args->dst_filepath, 0700);
    }
    if (strlen(program->args->dst_filepath) > DGRAM_MAX_BUFFER_LENGTH) {
        char msg[DGRAM_MAX_BUFFER_LENGTH];
        snprintf(msg, sizeof(msg), "Error: dst_filepath too long. Max: %d\n", DGRAM_MAX_BUFFER_LENGTH);
        dealocate_all_exit(program, EXIT_FAILURE, msg);
    }
}
