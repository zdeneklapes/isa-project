/******************************************************************************/
/**                                 INCLUDES                            **/
/******************************************************************************/
#include "initializations.h"

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
void deinit_args_struct(args_t *args) {
    if (args) {
        free(args);
        args = NULL;
    }
}

args_t *init_args_struct() {
    args_t *args = NULL;

    // Allocate
    if (!(args = calloc(1, sizeof(args_t)))) {
        exit(EXIT_FAILURE);
    }

    args->filename = NULL;
    args->upstream_dns_ip = NULL;
    args->dst_filepath = NULL;
    args->base_host = NULL;
    args->file = NULL;
    args->ip_type = IP_TYPE_ERROR;

    return args;
}

void deinit_dns_datagram(dns_datagram_t *dgram) {
    if (dgram) {
        close(dgram->network_info.socket_fd);
        free(dgram);
        dgram = NULL;
    }
}

void set_dns_datagram(program_t *program, bool is_sender) {
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
    memset(dgram->receiver, 0, DGRAM_MAX_BUFFER_LENGTH);
    memset(dgram->sender, 0, DGRAM_MAX_BUFFER_LENGTH);
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
        DEBUG_PRINT("Ok: socket()%d\n", dgram->network_info.socket_fd);
    }

    if (is_sender) {
        if (setsockopt(dgram->network_info.socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
                FUNC_FAILURE ||
            setsockopt(dgram->network_info.socket_fd, SOL_SOCKET, SO_REUSEADDR, &timeout, sizeof(timeout)) ==
                FUNC_FAILURE) {
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

    program->dgram = dgram;
}

void dealocate_all_exit(program_t *program, int exit_code, char *msg) {
    if (msg) {
        DEBUG_PRINT("%s", msg);
    }

    if (program) {
        // Program args
        deinit_args_struct(program->args);

        // Program dgram
        deinit_dns_datagram(program->dgram);

        // Program
        free(program);
        program = NULL;
    }

    exit(exit_code);
}
