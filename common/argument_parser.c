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
int check_switchers_and_argc(int argc, char *argv[], int idx, args_t *args) {
    if (argc == idx) {
        return FUNC_OK;
    }

    if (strcmp(argv[idx], "-u") == 0) {
        if (argc == idx + 1) {
            ERROR_EXIT("Missing argument for -u", EXIT_FAILURE);
        }
        args->upstream_dns_ip = argv[idx + 1];
        return idx + 2;
    }

    if (strcmp(argv[idx], "-h") == 0) {
        usage();
    }

    return idx;
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

void validate_base_host_exit(char *str) {
    args_t *args_test = init_args_struct();  // for validation

    char *base_host_token = NULL;
    char base_host[DGRAM_MAX_BUFFER_LENGTH] = {0};
    char *base_host_delim = ".";

    // TODO: Validate base_host format (character etc...) Bad examples: example..com

    // Validate: base_host
    if (strcmp(str, args_test->base_host) == 0)  // base_host is set
        ERROR_EXIT("Error: base_host - Run ./dns_sender --help \n", EXIT_FAILURE);

    memcpy(base_host, str, strlen(str));

    if (strlen(base_host_token = strtok(base_host, base_host_delim)) > SUBDOMAIN_NAME_LENGTH)  // base_host max
        // length
        ERROR_EXIT("Error: base_host too long - Run ./dns_sender --help \n", EXIT_FAILURE);

    if (strlen(base_host_token = strtok(NULL, base_host_delim)) > SUBDOMAIN_NAME_LENGTH)  // extension max length
        ERROR_EXIT("Error: base_host extension too long - Run ./dns_sender --help \n", EXIT_FAILURE);

    if ((base_host_token = strtok(NULL, base_host_delim)) != NULL)  // nothing else
        ERROR_EXIT("Error: base_host - Run ./dns_sender --help \n", EXIT_FAILURE);

    deinit_args_struct(args_test);
}

void validate_dst_filepath(args_t *args, args_t *args_test) {
    if (strlen(args->dst_filepath) > SUBDOMAIN_NAME_LENGTH            // len for subdomain
        || strcmp(args->dst_filepath, args_test->dst_filepath) == 0)  // not set
        ERROR_EXIT("Error: dst_filepath - Run ./dns_sender --help \n", EXIT_FAILURE);
    // TODO: Deallocate memory, when error occurs
}

void validate_filename(args_t *args, args_t *args_test) {
    if (strcmp(args->filename, args_test->filename) == 0) {
        // This is possible (STDIN)
    } else if (strcmp(args->filename, args_test->filename) != 0) {
        if (access(args->filename, F_OK) == FUNC_FAILURE) {
            ERROR_EXIT("Error: filename does not exist\n", EXIT_FAILURE);
        }
    }

    // Set and Validate: file, filename (Open)
    if (!(args->file = (strcmp(args->filename, "") != 0) ? fopen(args->filename, "r") : stdin))
        ERROR_EXIT("Error: filename or stdin can't be opened\n", EXIT_FAILURE);

    // TODO: Deallocate memory, when error occurs
}

void validate_upstream_dns_ip(args_t *args) {
    if (strcmp(args->upstream_dns_ip, "") == 0) {
        if (!get_dns_servers_from_system(args))
            ERROR_EXIT("Error: Get dns server from /etc/resolv.conf\n", EXIT_FAILURE);
    }
    // TODO: Deallocate memory, when error occurs
}

void validate_ip_type(args_t *args) {
    if ((args->ip_type = ip_version(args->upstream_dns_ip)) == IP_TYPE_ERROR)
        ERROR_EXIT("Error: IP version bad format", EXIT_FAILURE);
    // TODO: Deallocate memory, when error occurs
}

void validate_args(int i, program_t *program) {
    if (i > program->argc || i < 3 || i > 5) {
        dealocate_all_exit(program, EXIT_FAILURE, "Bad arguments for dns_sender\n");
    }

    args_t *args = program->args;
    args_t *args_test = init_args_struct();  // for validation

    validate_upstream_dns_ip(args);
    validate_ip_type(args);
    validate_dst_filepath(args, args_test);
    validate_base_host_exit(args->base_host);

    // Deallocate testing args
    deinit_args_struct(args_test);
}

void set_args_sender(program_t *program) {
    int argc = program->argc;
    char **argv = program->argv;
    program->args = init_args_struct();

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
        program->args->filename = argv[i++];
        if ((i = check_switchers_and_argc(argc, argv, i, program->args)) == FUNC_OK) {
            break;
        }
    }

    validate_args(i, program);
}

args_t *parse_args_receiver(int argc, char *argv[]) {
    //    args_t args = {.upstream_dns_ip = {0},
    //                   .base_host = {0},
    //                   .dst_filepath = {0},
    //                   .filename = {0},
    //                   .file = NULL,
    //                   .ip_type = IP_TYPE_ERROR};
    args_t *args = NULL;
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
    strcpy(args->base_host, argv[1]);
    strcpy(args->dst_filepath, argv[2]);

    // Validate: base_host
    validate_base_host_exit(args->base_host);

    // Validate: dst_filepath - Folder not exists
    if (stat(args->dst_filepath, &st) == FUNC_FAILURE) {
        mkdir(args->dst_filepath, 0700);
    }

    return args;
}
