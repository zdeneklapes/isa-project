//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

// TODO: Includes: https://sites.uclouvain.be/SystInfo/usr/include/bits/socket.h.html
// TODO: Inspiration: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/aes.h>

#include "../common/base32.h"
#include "../common/debug.h"
#include "../common/dns_helper.h"
#include "arpa/inet.h"
#include "dns_sender_events.h"
#include "getopt.h"
#include "math.h"
#include "netinet/ip_icmp.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                STRUCTS                                   **/
/******************************************************************************/
typedef struct {
    char upstream_dns_ip[ARGS_LEN];
    char base_host[ARGS_LEN];
    char dst_filepath[ARGS_LEN];
    char src_filepath[ARGS_LEN];
} args_t;

/******************************************************************************/
/**                                FUNCTION DECLARATION                      **/
/******************************************************************************/
static void usage();
static bool get_dns_servers_from_system(args_t *);
static args_t parse_args_or_exit(int, char *[]);
static args_t init_args_struct();
static void create_dns_name_format_subdomains(char *);
static void create_dns_name_format_base_host(uint8_t *domain);
static void set_dns_qname(uint8_t *, const args_t *, FILE *);
static void set_dns_header(dns_header_t *);
static bool is_empty_str(char *str);
static uint16_t set_next_dns_buffer(u_char[1024], const args_t *args, FILE *file);
static void send_packets(FILE *, const args_t *);
int main(int, char *[]);

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
static void usage() {
    printf("USAGE:");
    exit(0);
}

static args_t init_args_struct() {
    args_t args = {.base_host = {0}, .dst_filepath = {0}, .src_filepath = {0}, .upstream_dns_ip = {0}};
    return args;
}

static bool is_empty_str(char *str) { return str[0] == '\0'; }

static bool get_dns_servers_from_system(args_t *args) {
    FILE *fp;
    char line[DOMAIN_NAME_LENGTH];
    char *p = NULL;
    const char finding_name[] = "nameserver ";
    const char delimiter[] = " ";

    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) ERROR_EXIT("Failed opening /etc/resolv.conf file \n", 1);

    while (fgets(line, 200, fp)) {
        if (line[0] == '#') continue;

        //
        if (strncmp(line, finding_name, strlen(finding_name)) == 0) {
            // TODO: Break and check what nameserver is ready
            p = strtok(line, delimiter);  // Divide string based on delimiter
            p = strtok(NULL, delimiter);  // Go to next item after delimiter
            break;
        }
    }

    if (!is_empty_str(p)) {
        strcpy(args->upstream_dns_ip, p);
        return true;
    } else {
        ERROR_EXIT("Error: None server found in /etc/resolv.conf file\n", 1);
    }
}

static args_t parse_args_or_exit(int argc, char *argv[]) {
    // Useful tutorial: https://azrael.digipen.edu/~mmead/www/Courses/CS180/getopt.html

    args_t args = init_args_struct();
    opterr = 1;

    int c;
    while ((c = getopt(argc, argv, "u:h")) != -1) {
        switch (c) {
            case 'u':
                strncpy(args.upstream_dns_ip, optarg, sizeof(args.upstream_dns_ip));
                break;
            case 'h':
                usage();
                break;
            case '?' | ':':
            default:
                ERROR_EXIT("Error: Bad option | Missing arg | Some other error\n", EXIT_FAILURE);
        }
    }

    // Get dns server from system, because not provide on cli
    if (strncmp(args.upstream_dns_ip, "", sizeof(args.upstream_dns_ip)) == 0) {
        if (!get_dns_servers_from_system(&args))
            ERROR_EXIT("Error: Get dns server from /etc/resolv.conf\n", EXIT_FAILURE);
    }

    if (optind + 2 == argc || optind + 3 == argc) {
        strncpy(args.base_host, argv[optind++], sizeof(args.base_host));  // TODO: Maximum 63 length
        strncpy(args.src_filepath, argv[optind++], sizeof(args.src_filepath));
        if (optind + 1 == argc) strncpy(args.dst_filepath, argv[optind++], sizeof(args.dst_filepath));
    } else {
        ERROR_EXIT("Error: Bad arguments: Run ./dns_sender --help \n", EXIT_FAILURE);
    }

    args_t args_test = init_args_struct();
    if (strcmp(args.upstream_dns_ip, args_test.upstream_dns_ip) == 0 &&
        strcmp(args.src_filepath, args_test.src_filepath) == 0 &&
        strcmp(args.dst_filepath, args_test.dst_filepath) == 0 && strcmp(args.base_host, args_test.base_host) == 0) {
        ERROR_EXIT("Error: Bad arguments: Run ./dns_sender --help \n", EXIT_FAILURE);
    }

    return args;
}

/**
 * Source: https://github.com/tbenbrahim/dns-tunneling-poc
 * @param dns_qname_data
 */
static void create_dns_name_format_subdomains(char *dns_qname_data) {
    // TODO: Change this function before source

    size_t domain_len = strlen(dns_qname_data);
    unsigned char *dns_buf_ptr = (u_char *)dns_qname_data;
    size_t num_labels = domain_len / 60 + (domain_len % 60 ? 1 : 0);
    for (size_t i = 0; i < num_labels; ++i) {
        size_t start = i * 60;
        size_t count = (start + 60 <= domain_len) ? 60 : domain_len - start;
        *dns_buf_ptr = (unsigned char)count;
        memcpy(dns_buf_ptr + 1, dns_qname_data + start, count);
        dns_buf_ptr += count + 1;
    }
}

static void create_dns_name_format_base_host(uint8_t *domain) {
    char final_string[DOMAIN_NAME_LENGTH] = {0};
    char *ptr = strstr((char *)domain, ".");
    char *ptr_prev = (char *)domain;
    while (ptr) {
        int number = ptr - ptr_prev;
        *(final_string + strlen(final_string)) = (u_char)number;
        memcpy(final_string + strlen(final_string), ptr_prev, ptr - ptr_prev);
        ptr_prev = ptr;
        ptr = strstr(ptr + 1, ".");
        if (!ptr && strstr(ptr_prev, ".")) {
            ptr = ptr_prev + strlen(ptr_prev);
            ptr_prev++;
        }
    }
    *(final_string + strlen(final_string)) = (u_char)((int)0);
    memset(domain, 0, strlen((char *)domain));
    memcpy(domain, final_string, strlen(final_string));
}

static void set_dns_qname(uint8_t *dns_qname, const args_t *args, FILE *file) {
    // TODO: set max len 255 whole dns name
    uint8_t dns_transfering_data[DOMAIN_NAME_LENGTH] = {0};
    uint8_t base_host[SUBDOMAIN_NAME_LENGTH] = {0};
    uint8_t subdomains[SUBDOMAIN_NAME_LENGTH] = {0};

    // Base Host
    memcpy(base_host, args->base_host, strlen(args->base_host));
    create_dns_name_format_base_host(base_host);

    // Subdomains (Data)
    // len
    int dns_name_len = DOMAIN_NAME_LENGTH - strlen(args->base_host);
    dns_name_len -= dns_name_len / 60 == 4 ? 8 : 6;

    // file
    fread(dns_transfering_data, BASE32_LENGTH_ENCODE(dns_name_len), 1, file);
    base32_encode(dns_transfering_data, strlen((const char *)dns_transfering_data), subdomains, DOMAIN_NAME_LENGTH);
    create_dns_name_format_subdomains((char *)dns_qname);

    // Create dns_name
    strcat((char *)dns_qname, (char *)subdomains);
    strcat((char *)dns_qname, (char *)base_host);
}

static void set_dns_header(dns_header_t *dns_header) {
    dns_header->id = (uint16_t)htons(getpid());

    dns_header->qr = 0;      // This is a query
    dns_header->opcode = 0;  // This is a standard query
    dns_header->aa = 0;      // Not Authoritative
    dns_header->tc = 0;      // This message is
    dns_header->rd = 1;      // Recursion Desired

    dns_header->ra = 0;  // Recursion not available!
    dns_header->z = 0;
    dns_header->rcode = 0;

    dns_header->qdcount = htons(1);  // One question
    dns_header->ancount = 0;
    dns_header->nscount = 0;
    dns_header->arcount = 0;
}

/**
 * Prepare packet buffer to transfer and return size of buffer
 * @param dns_buffer
 * @param args
 * @param file
 * @return Size of dns_buffer
 */
static uint16_t set_next_dns_buffer(u_char dns_buffer[DNS_BUFFER_LENGTH], const args_t *args, FILE *file) {
    // Header
    dns_header_t *dns_header = (dns_header_t *)dns_buffer;
    set_dns_header(dns_header);

    // Create Domain Name

    // Question
    uint8_t base32_data_buffer[DOMAIN_NAME_LENGTH] = {0};
    set_dns_qname(base32_data_buffer, args, file);

    DEBUG_PRINT("DOMAIN_NAME: %s\n", base32_data_buffer);

    // qname
    u_char *dns_question = (dns_buffer + sizeof(dns_header_t));
    memcpy(dns_question, base32_data_buffer, strlen((char *)base32_data_buffer));

    // type + class
    dns_question_fields_t *dns_question_fields =
        (dns_question_fields_t *)(dns_question + strlen((char *)base32_data_buffer) + 1);
    dns_question_fields->qtype = (u_short)htons(DNS_TYPE_A);
    dns_question_fields->qclass = (u_short)htons(DNS_CLASS_IN);

    //
    return (uint16_t)((u_char *)(dns_question_fields + 1) - (u_char *)dns_header);
}

static struct sockaddr_in create_socket_address(const args_t *args) {
    // Prepare IP
    struct in_addr ip;
    inet_aton(args->upstream_dns_ip, &ip);
    //
    struct sockaddr_in socket_address = {.sin_addr = ip, .sin_family = AF_INET, .sin_port = htons(DNS_PORT)};
    return socket_address;
}

/**
 * Sending packets to receiver
 * @param file File pointer if specified, stdin pointer otherwise
 * @param args Struct pointer to application arguments
 */
static void send_packets(FILE *file, const args_t *args) {
    int socket_fd;
    u_char dns_answer[DNS_BUFFER_LENGTH] = {0};
    u_char dns_response[DNS_BUFFER_LENGTH] = {0};
    int dns_response_length = 0;
    socklen_t socklen = sizeof(struct sockaddr_in);
    const struct sockaddr_in socket_addr = create_socket_address(args);
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) ERROR_EXIT("Error: socket() failed", EXIT_FAILURE);

    while (!feof(file)) {
        uint16_t dns_buffer_size = set_next_dns_buffer(dns_answer, args, file);  // Create dns_answer + buffer size

        // Question
        if (sendto(socket_fd, dns_answer, dns_buffer_size, CUSTOM_MSG_CONFIRM, (struct sockaddr *)&socket_addr,
                   sizeof(struct sockaddr_in)) == -1) {
            // TODO: timeout + resend
            ERROR_EXIT("sendto failed", EXIT_FAILURE);
        }
        DEBUG_PRINT("Send question%s", "\n");

        // Answer
        if ((dns_response_length = recvfrom(socket_fd, dns_response, sizeof(dns_response), MSG_WAITALL,
                                            (struct sockaddr *)&socket_addr, &socklen)) == -1) {
            ERROR_EXIT("Error: recvfrom() failed", EXIT_FAILURE);
        }
        DEBUG_PRINT("Receive answer%s%d", "\n", dns_response_length);

        // Clean for next packet
        memset(dns_answer, 0, sizeof(char[DNS_BUFFER_LENGTH]));
    }
    close(socket_fd);
}

int main(int argc, char *argv[]) {
    args_t args = parse_args_or_exit(argc, argv);
    FILE *file;

    //
    if (!(file = strcmp(args.src_filepath, "") != 0 ? fopen(args.src_filepath, "r") : stdin))
        ERROR_EXIT("Error: file path\n", EXIT_FAILURE);

    send_packets(file, &args);

    //
    fclose(file);
    return 0;
}
