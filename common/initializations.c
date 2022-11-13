/******************************************************************************/
/**                                 INCLUDES                            **/
/******************************************************************************/
#include "initializations.h"

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
void deinit_args_struct(args_t *args) {
    if (args->file) {
        fclose(args->file);
        args->file = NULL;
    }

    if (args) {
        free(args);
        args = NULL;
    }
}

void init_args_struct(program_t *program) {
    args_t *args = NULL;

    // Allocate
    if (!(args = calloc(1, sizeof(args_t)))) {
        dealocate_all_exit(program, EXIT_FAILURE, "Failed to allocate memory for args");
    }

    memset(args->filename, 0, DGRAM_MAX_BUFFER_LENGTH);
    memset(args->upstream_dns_ip, 0, QNAME_MAX_LENGTH);
    args->dst_filepath = NULL;
    args->base_host = NULL;
    args->file = NULL;
    args->tmp_ptr_filename = NULL;
    args->ip_type = IP_TYPE_ERROR;

    program->args = args;
}

void deinit_dns_datagram(dns_datagram_t *dgram) {
    if (dgram) {
        close(dgram->network_info.socket_fd);
        free(dgram);
        dgram = NULL;
    }
}

void reinit_dns_datagram(program_t *program, bool is_new_file) {
    dns_datagram_t *dgram = program->dgram;
    memset(dgram->receiver, 0, DGRAM_MAX_BUFFER_LENGTH);
    memset(dgram->sender, 0, DGRAM_MAX_BUFFER_LENGTH);
    dgram->sender_packet_len = 0;
    dgram->receiver_packet_len = 0;
    dgram->data_len = 0;

    if (is_new_file) {
        dgram->id = 0;
        dgram->data_accumulated_len = 0;
    }
}

void set_dns_datagram(program_t *program, bool is_sender) {
    args_t *args = program->args;
    struct sockaddr_in socket_address_in = {0};
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};  // TODO: change to - 1 sec

    // dgram
    dns_datagram_t *dgram = calloc(1, sizeof(dns_datagram_t));
    if (!dgram) {
        ERROR_EXIT("Error: calloc failed\n", EXIT_FAILURE);
    } else {
        program->dgram = dgram;
    }

    // socket_address_in
    if (is_sender) {
        // Create IP
        struct in_addr ip;
        inet_aton(args->upstream_dns_ip, &ip);

        // Create sockaddrs
        socket_address_in.sin_addr = ip;
        socket_address_in.sin_family = AF_INET;
        socket_address_in.sin_port = htons(DNS_PORT);
    } else {
        socket_address_in.sin_addr.s_addr = INADDR_ANY;
        socket_address_in.sin_family = AF_INET;
        socket_address_in.sin_port = htons(DNS_PORT);
    }

    ////////////////////////////////
    // Initialize
    ////////////////////////////////
    reinit_dns_datagram(program, false);
    dgram->network_info.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    dgram->network_info.socket_address = socket_address_in;
    dgram->network_info.socket_address_len = sizeof(struct sockaddr_in);

    // socket_fd check
    if (dgram->network_info.socket_fd == FUNC_FAILURE) {
        dealocate_all_exit(program, EXIT_FAILURE, "Error: socket failed\n");
    } else {
        DEBUG_PRINT("Ok: socket(), socket_fd: %d\n", dgram->network_info.socket_fd);
    }

    if (is_sender) {
        ////////////////////////////////
        // SO_RCVTIMEO
        ////////////////////////////////
#if !DEBUG || TEST_PACKET_LOSS
        if (setsockopt(dgram->network_info.socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
            FUNC_FAILURE) {
            dealocate_all_exit(program, EXIT_FAILURE, "Error: setsockopt() failed\n");
        }
#endif

        ////////////////////////////////
        // SO_REUSEADDR
        ////////////////////////////////
        if (setsockopt(dgram->network_info.socket_fd, SOL_SOCKET, SO_REUSEADDR, &timeout, sizeof(timeout)) ==
            FUNC_FAILURE) {
            dealocate_all_exit(program, EXIT_FAILURE, "Error: setsockopt() failed\n");
        }

        //
        DEBUG_PRINT("Ok: setsockopt()%s", "\n");
    }

    if (!is_sender) {
        if (bind(dgram->network_info.socket_fd, (const struct sockaddr *)&dgram->network_info.socket_address,
                 sizeof(dgram->network_info.socket_address)) == FUNC_FAILURE) {
            dealocate_all_exit(program, EXIT_FAILURE, "Error: bind() failed\n");
        } else {
            DEBUG_PRINT("Ok: bind()%s", "\n");
        }
    }
}

void dealocate_all_exit(program_t *program, int exit_code, char *msg) {
    if (program) {
        // Program args
        deinit_args_struct(program->args);

        // Program dgram
        deinit_dns_datagram(program->dgram);

        // Program
        free(program);
        program = NULL;
    }

    if (msg) {
        fprintf(stderr, "%s:%d:%s(): %s", __FILE__, __LINE__, __func__, msg);
        if (errno) {
            perror(msg);
        }
    }

    exit(exit_code);
}
