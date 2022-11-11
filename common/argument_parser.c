//
// Created by Zdeněk Lapeš on 07/11/2022.
//
/******************************************************************************/
/**                                 INCLUDES                                 **/
/******************************************************************************/
#include "argument_parser.h"

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
        args->upstream_dns_ip = argv[i + 1];
        return i + 2;
    }

    if (strcmp(argv[i], "-h") == 0) {
        usage();
    }

    return i;
}

bool get_dns_servers_from_system(args_t *args) {
    FILE *fp = NULL;
    char line[QNAME_MAX_LENGTH] = {0};
    char *p = NULL;
    const char finding_name[] = "nameserver ";
    const char delimiter[] = " ";

    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL)
        ERROR_EXIT("Failed opening /etc/resolv.conf file \n", EXIT_FAILURE);

    while (fgets(line, 200, fp)) {
        if (line[0] == '#') continue;

        //
        if (strncmp(line, finding_name, strlen(finding_name)) == 0) {
            p = strtok(line, delimiter);  // Divide string based on delimiter
            p = strtok(NULL, delimiter);  // Go to next item after delimiter
            p[strcspn(p, "\n")] = 0;
            if (ip_version(p) == IPv4) break;
        }
    }

    if (!is_empty_str(p) && ip_version(p) == IPv4) {
        strcpy(args->upstream_dns_ip, p);
        return true;
    } else {
        ERROR_EXIT("Error: None server found in /etc/resolv.conf file for IPv4.\n", EXIT_FAILURE);
    }
}

void validate_base_host_exit(program_t *program) {
    char *base_host = program->args->base_host;

    char *base_host_token = NULL;
    char base_host_test[DGRAM_MAX_BUFFER_LENGTH] = {0};
    char *base_host_delim = ".";

    // TODO: Validate base_host_test format (character etc...) Bad examples: example..com
    // base_host_test is set
    if (strcmp(base_host, "") == 0) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host - Run ./dns_sender --help \n");
    }

    memcpy(base_host_test, base_host, strlen(base_host));

    // base_host_test max length
    if (strlen(base_host_token = strtok(base_host_test, base_host_delim)) > SUBDOMAIN_NAME_LENGTH) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host - Run ./dns_sender --help \n");
    }

    if (strlen(base_host_token = strtok(NULL, base_host_delim)) > SUBDOMAIN_NAME_LENGTH) {  // extension max length
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host - Run ./dns_sender --help \n");
    }

    if ((base_host_token = strtok(NULL, base_host_delim)) != NULL) {  // nothing else
        dealocate_all_exit(program, EXIT_FAILURE, "Error: base_host - Run ./dns_sender --help \n");
    }
}

void validate_dst_filepath(program_t *program) {
    args_t *args = program->args;

    if (strlen(args->dst_filepath) > DGRAM_MAX_BUFFER_LENGTH || strcmp(args->dst_filepath, "") == 0) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: dst_filepath - Run ./dns_sender --help \n");
    }
}

void validate_filename(program_t *program) {
    args_t *args = program->args;

    if (strcmp(args->filename, "") == 0) {
        // This is possible (STDIN)
    } else {
        if (access(args->filename, F_OK) == FUNC_FAILURE) {
            dealocate_all_exit(program, EXIT_FAILURE, "Error: filename - Run ./dns_sender --help \n");
        }
    }

    // Set and Validate: file, filename (Open)
    if (!(args->file = (strcmp(args->filename, "") != 0) ? fopen(args->filename, "r") : stdin)) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: filename - Run ./dns_sender --help \n");
    }
}

void validate_upstream_dns_ip(program_t *program) {
    args_t *args = program->args;
    if (strcmp(args->upstream_dns_ip, "") == 0) {
        if (!get_dns_servers_from_system(args)) deinit_args_struct(args);
        dealocate_all_exit(program, EXIT_FAILURE, "Error: Get dns server from /etc/resolv.conf\n");
    }
}

void validate_ip_type(program_t *program) {
    args_t *args = program->args;
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
    validate_ip_type(program);
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
        program->args->base_host = argv[i++];
        if ((i = check_switchers_and_argc(argc, argv, i, program->args)) == FUNC_OK) {
            break;
        }
        program->args->dst_filepath = argv[i++];
        if ((i = check_switchers_and_argc(argc, argv, i, program->args)) == FUNC_OK) {
            break;
        }

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
                dealocate_all_exit(program, EXIT_FAILURE, "Bad arguments for dns_sender\n");
        }
    }

    // Bad args
    if (program->argc != 3) {
        dealocate_all_exit(program, EXIT_FAILURE, "Bad arguments for dns_sender\n");
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
