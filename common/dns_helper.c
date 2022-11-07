#include "dns_helper.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

/******************************************************************************/
/**                                FUNCTIONS DEFINITION                      **/
/******************************************************************************/

void get_dns_name_format_subdomains(u_char *qname, const args_t *args, void (*callback)(char *, int, char *),
                                    dns_datagram_t *dgram) {
    u_char dns_qname_data_copy[QNAME_MAX_LENGTH] = {0};
    memcpy(dns_qname_data_copy, qname, strlen((char *)qname));
    memset(qname, 0, strlen((char *)qname));
    u_char *dns_qname_data_ptr = qname;

    size_t domain_len = strlen((char *)dns_qname_data_copy);
    size_t num_labels = ceil((double)domain_len / SUBDOMAIN_DATA_LENGTH);
    for (size_t i = 0; i < num_labels; ++i) {
        //
        size_t start = i * SUBDOMAIN_DATA_LENGTH;
        size_t count = (start + SUBDOMAIN_DATA_LENGTH <= domain_len) ? SUBDOMAIN_DATA_LENGTH : domain_len - start;

        // Set data
        *(dns_qname_data_ptr) = (unsigned char)count;
        memcpy(dns_qname_data_ptr + 1, dns_qname_data_copy + start, count);

        dns_qname_data_ptr += count + 1;  // next subdomain
    }

    CALL_CALLBACK(DEBUG_EVENT, callback, (char *)args->dst_filepath, dgram->id, (char *)qname);
}

void get_dns_name_format_base_host(u_char *domain) {
    u_char final_string[QNAME_MAX_LENGTH] = {0};
    char *ptr = strstr((char *)domain, ".");
    char *ptr_prev = (char *)domain;
    while (ptr != ptr_prev) {
        int number = (int)(ptr - ptr_prev);
        *(final_string + strlen((char *)final_string)) = (u_char)number;
        memcpy(final_string + strlen((char *)final_string), ptr_prev, ptr - ptr_prev);
        ptr_prev = ptr + 1;
        ptr = strstr(ptr + 1, ".");
        if (!ptr && !strstr(ptr_prev, ".")) {
            ptr = ptr_prev + strlen(ptr_prev);
        }
    }
    *(final_string + strlen((char *)final_string)) = (u_char)0;
    memset(domain, 0, strlen((char *)domain));
    memcpy(domain, final_string, strlen((char *)final_string));
}

enum IP_TYPE ip_version(const char *src) {
    char buf[16];
    if (inet_pton(AF_INET, src, buf)) {
        return IPv4;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return IPv6;
    }
    return IP_TYPE_ERROR;
}

bool is_not_resend_packet_type(enum PACKET_TYPE pkt_type) {
    return pkt_type == START || pkt_type == DATA || pkt_type == END;
}

bool is_problem_packet_packet(enum PACKET_TYPE pkt_type) {
    return pkt_type == MALFORMED_PACKET || pkt_type == BAD_BASE_HOST;
}

void validate_base_host_exit(char *str) {
    args_t *args_test = init_args_struct();  // for validation

    char *base_host_token = NULL;
    char base_host[ARGS_LEN] = {0};
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

/******************************************************************************/
/**                         ALLOCATIONS                                      **/
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

dns_datagram_t *init_dns_datagram(const args_t *args, bool is_sender) {
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
    if (!(dgram->receiver = calloc(1, DGRAM_MAX_BUFFER_LENGTH))) {
        deinit_dns_datagram(dgram);
        ERROR_EXIT("Error: calloc failed\n", EXIT_FAILURE);
    }
    if (!(dgram->sender = calloc(1, DGRAM_MAX_BUFFER_LENGTH))) {
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
            PERROR_EXIT("Error: setsockopt()\n");
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

void dealocate_all_exit(args_t *args, dns_datagram_t *dgram, int exit_code) {
    deinit_args_struct(args);
    (void)dgram;  // TODO: free dgram
    exit(exit_code);
}
