/******************************************************************************/
/**                                 INCLUDES                            **/
/******************************************************************************/
#include "initializations.h"

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
void deinit_args_struct(args_t *args) {
    if (args) {
        if (args->upstream_dns_ip) {
            free(args->upstream_dns_ip);
        }
        if (args->base_host) {
            free(args->base_host);
        }
        if (args->dst_filepath) {
            free(args->dst_filepath);
        }
        if (args->filename) {
            free(args->filename);
        }
        free(args);
    }
}

args_t *init_args_struct() {
    args_t *args = NULL;

    // Allocate
    if (!(args = calloc(1, sizeof(args_t)))) {
        exit(EXIT_FAILURE);
    }
    if (!(args->filename = calloc(ARGS_LEN, sizeof(char)))) {
        deinit_args_struct(args);
        exit(EXIT_FAILURE);
    }
    if (!(args->upstream_dns_ip = calloc(ARGS_LEN, sizeof(char)))) {
        deinit_args_struct(args);
        exit(EXIT_FAILURE);
    }
    if (!(args->dst_filepath = calloc(ARGS_LEN, sizeof(char)))) {
        deinit_args_struct(args);
        exit(EXIT_FAILURE);
    }
    if (!(args->base_host = calloc(ARGS_LEN, sizeof(char)))) {
        deinit_args_struct(args);
        exit(EXIT_FAILURE);
    }

    // Set value
    memset(args->upstream_dns_ip, 0, ARGS_LEN);
    memset(args->dst_filepath, 0, ARGS_LEN);
    memset(args->filename, 0, ARGS_LEN);
    memset(args->base_host, 0, ARGS_LEN);
    args->file = NULL;
    args->ip_type = IP_TYPE_ERROR;

    return args;
}

void deinit_dns_datagram(dns_datagram_t *dgram) {
    if (dgram) {
        if (dgram->sender) {
            free(dgram->sender);
        }
        if (dgram->receiver) {
            free(dgram->receiver);
        }
        free(dgram);
    }
}

dns_datagram_t *init_dns_datagram(bool is_sender, program_t *program) {
    args_t *args = program->args;

    // Timeout for Sender
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};

    // Create IP
    struct in_addr ip;
    inet_aton(args->upstream_dns_ip, &ip);

    // Create sockaddrs
    struct sockaddr_in sa_sender = {.sin_addr = ip, .sin_family = AF_INET, .sin_port = htons(DNS_PORT)};
    struct sockaddr_in sa_receiver = {
        .sin_addr.s_addr = INADDR_ANY, .sin_family = AF_INET, .sin_port = htons(DNS_PORT)};

    // Create datagram
    dns_datagram_t *dgram = calloc(1, sizeof(dns_datagram_t));
    if (!dgram) {
        ERROR_EXIT("Error: calloc failed\n", EXIT_FAILURE);
    }
    if (!(dgram->sender = calloc(1, DGRAM_MAX_BUFFER_LENGTH))) {
        deinit_dns_datagram(dgram);
        ERROR_EXIT("Error: calloc failed\n", EXIT_FAILURE);
    }
    if (!(dgram->receiver = calloc(1, DGRAM_MAX_BUFFER_LENGTH))) {
        deinit_dns_datagram(dgram);
        ERROR_EXIT("Error: calloc failed\n", EXIT_FAILURE);
    }
    memset(dgram->receiver, 0, sizeof(struct sockaddr_in));
    memset(dgram->sender, 0, sizeof(struct sockaddr_in));
    dgram->id = 0;
    dgram->sender_packet_len = 0;
    dgram->receiver_packet_len = 0;
    dgram->data_len = 0;
    dgram->data_accumulated_len = 0;
    dgram->network_info.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    dgram->network_info.socket_address = is_sender ? sa_sender : sa_receiver;
    dgram->network_info.socket_address_len = sizeof(struct sockaddr_in);

    //
    if (dgram->network_info.socket_fd == FUNC_FAILURE) {
        PERROR_EXIT("Error: socket()");
    } else {
        DEBUG_PRINT("Ok: socket()%s", "\n");
    }

    if (is_sender) {
        if (setsockopt(dgram->network_info.socket_fd, SOL_SOCKET, SO_RCVTIMEO | SO_REUSEADDR, &timeout,
                       sizeof timeout) == FUNC_FAILURE) {
            PERROR_EXIT("Error: setsockopt() ");
        } else {
            DEBUG_PRINT("Ok: setsockopt()%s", "\n");
        }
    }

    if (!is_sender) {
        if (bind(dgram->network_info.socket_fd, (const struct sockaddr *)&dgram->network_info.socket_address,
                 sizeof(dgram->network_info.socket_address)) == FUNC_FAILURE) {
            PERROR_EXIT("Error: bind()");
        } else {
            DEBUG_PRINT("Ok: bind()%s", "\n");
        }
    }

    return dgram;
}

void dealocate_all_exit(program_t *program, int exit_code, char *msg) {
    if (exit_code != 0) {
        fprintf(stderr, "%s", msg);
    }
    fclose(program->args->file);
    deinit_args_struct(program->args);
    deinit_dns_datagram(program->dgram);
    exit(exit_code);
}
