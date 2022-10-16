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
void usage();
bool get_dns_servers_from_system(args_t *);
bool parse_args(int, char *[], args_t *);
void init_args_struct(args_t *);
void create_dns_name_format(char *);
void create_dns_name_format_from_base(uint8_t *domain);
void set_dns_qname(uint8_t *, const args_t *, FILE *);
void set_dns_header(dns_header_t *);
uint16_t set_dns_buffer(u_char[], const args_t *, FILE *);
void send_packets(FILE *, const args_t *);
int main(int, char *[]);

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
void usage() {
    printf("USAGE:");
    exit(0);
}

bool get_dns_servers_from_system(args_t *args) {
    FILE *fp;
    char line[DOMAIN_NAME_LENGTH], *p;
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
        printf("Failed opening /etc/resolv.conf file \n");
        return false;
    }

    while (fgets(line, 200, fp)) {
        if (line[0] == '#') {
            continue;
        }
        if (strncmp(line, "nameserver", 10) == 0) {
            p = strtok(line, " ");
            p = strtok(NULL, " ");
            // TODO: Break and check what nameserver is ready
        }
    }

    if (strcmp(p, "") == 0) {
        return false;
    } else {
        strcpy(args->upstream_dns_ip, p);
    }

    return true;
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

    // Get dns server from system, because not provide on cli
    if (strncmp(args->upstream_dns_ip, "", sizeof(args->upstream_dns_ip)) == 0) {
        if (!get_dns_servers_from_system(args))
            ERROR_EXIT("Error: get dns server from /etc/resolv.conf\n", EXIT_FAILURE);
    }

    if (optind + 2 == argc || optind + 3 == argc) {
        strncpy(args->base_host, argv[optind++], sizeof(args->base_host));  // TODO: Maximum 63 length
        strncpy(args->src_filepath, argv[optind++], sizeof(args->src_filepath));
        if (optind + 1 == argc) strncpy(args->dst_filepath, argv[optind++], sizeof(args->dst_filepath));
        return true;
    } else {
        return false;
    }
}

void init_args_struct(args_t *args) {
    memset(args->base_host, '\0', sizeof(args->base_host));
    memset(args->dst_filepath, '\0', sizeof(args->dst_filepath));
    memset(args->src_filepath, '\0', sizeof(args->src_filepath));
    memset(args->upstream_dns_ip, '\0', sizeof(args->upstream_dns_ip));
}

/**
 * Source: https://github.com/tbenbrahim/dns-tunneling-poc
 * @param dns_qname_data
 */
void create_dns_name_format(char *dns_qname_data) {
    // TODO: Change this function

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

void create_dns_name_format_from_base(uint8_t *domain) {
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
    //    *(final_string + strlen(final_string) + 1) = '\0';
    memset(domain, 0, strlen((char *)domain));
    memcpy(domain, final_string, strlen(final_string));
}

void set_dns_qname(uint8_t *dns_qname, const args_t *args, FILE *file) {
    // TODO: set max len 255 whole dns name
    // Base host
    uint8_t base_host[SUBDOMAIN_NAME_LENGTH] = {0};
    memcpy(base_host, args->base_host, strlen(args->base_host));
    create_dns_name_format_from_base(base_host);

    // Data
    int dns_name_len = DOMAIN_NAME_LENGTH - strlen(args->base_host);
    if (dns_name_len / 60 == 4) {  // strlen(base_host) >63
        dns_name_len -= 4 * 2;
    } else {  // strlen(base_host) < 4
        dns_name_len -= 3 * 2;
    }

    uint8_t dns_transfering_data[DOMAIN_NAME_LENGTH] = {0};
    fread(dns_transfering_data, BASE32_LENGTH_ENCODE(dns_name_len), 1, file);
    base32_encode(dns_transfering_data, strlen((const char *)dns_transfering_data), dns_qname, DOMAIN_NAME_LENGTH);
    create_dns_name_format((char *)dns_qname);

    // Create dns_name
    strcat((char *)dns_qname, (char *)base_host);
}

void set_dns_header(dns_header_t *dns_header) {
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
uint16_t set_dns_buffer(u_char dns_buffer[DNS_BUFFER_LENGTH], const args_t *args, FILE *file) {
    // Set Header
    dns_header_t *dns_header = (dns_header_t *)dns_buffer;
    set_dns_header(dns_header);

    // Create Domain Name
    uint8_t base32_data_buffer[DOMAIN_NAME_LENGTH] = {0};
    set_dns_qname(base32_data_buffer, args, file);
    DEBUG_PRINT("DOMAIN_NAME: %s\n", base32_data_buffer);

    // Set Question
    u_char *dns_question = (dns_buffer + sizeof(dns_header_t));
    memcpy(dns_question, base32_data_buffer, strlen((char *)base32_data_buffer));
    //    DEBUG_PRINT("%d\n", (int)strlen((char *)dns_question));

    int dns_question_len = (int)strlen((char *)dns_question) + 1;
    //    print_buffer(dns_buffer,
    //                 (dns_question + strlen((char *)dns_question) + 3 * sizeof(u_short)) - (u_char *)dns_header);

    *((u_short *)(dns_question + dns_question_len)) = (u_short)htons(DNS_TYPE_A);
    //    print_buffer(dns_buffer,
    //                 (dns_question + strlen((char *)dns_question) + 3 * sizeof(u_short)) - (u_char *)dns_header);

    *((u_short *)(dns_question + dns_question_len + sizeof(u_short))) = (u_short)htons(DNS_CLASS_IN);
    //    print_buffer(dns_buffer,
    //                 (dns_question + strlen((char *)dns_question) + 3 * sizeof(u_short)) - (u_char *)dns_header);

    //    DEBUG_PRINT("%d\n", (int)strlen((char *)dns_question));
    // TODO: set class and type
    //        struct QUESTION *qinfo = NULL;
    //        qinfo = (struct QUESTION *)(dns_question + strlen((char *)base32_data_buffer) + 1);  // fill it
    //        qinfo->qtype = htons(DNS_TYPE_A);     // type of the query , A , MX , CNAME , NS etc
    //        qinfo->qclass = htons(DNS_CLASS_IN);  // its internet (lol)

    // Return size
    uint16_t dns_buffer_size =
        (dns_question + strlen((char *)dns_question) + 1 + 2 * sizeof(u_short)) - (u_char *)dns_header;
    return dns_buffer_size;
}

/**
 * Sending packets to receiver
 * @param file File pointer if specified, stdin pointer otherwise
 * @param args Struct pointer to application arguments
 */
void send_packets(FILE *file, const args_t *args) {
    int socket_fd;

    while (!feof(file)) {
        u_char dns_buffer[DNS_BUFFER_LENGTH] = {0};
        uint16_t dns_buffer_size = set_dns_buffer(dns_buffer, args, file);  // Prepare dns_buffer and return buf size
        print_buffer(dns_buffer, dns_buffer_size);

        if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {  // Create Socket
            ERROR_EXIT("Error: socket() failed", EXIT_FAILURE);
        }

        // Prepare IP
        struct in_addr ip;
        inet_aton(args->upstream_dns_ip, &ip);

        // Create socket_addr
        struct sockaddr_in socket_addr;
        socket_addr.sin_addr = ip;
        socket_addr.sin_family = AF_INET;  // IPv4
        socket_addr.sin_port = htons(DNS_PORT);
        if (sendto(socket_fd, dns_buffer, dns_buffer_size, CUSTOM_MSG_CONFIRM, (struct sockaddr *)&socket_addr,
                   sizeof(struct sockaddr_in)) == -1) {
            ERROR_EXIT("sendto failed", EXIT_FAILURE);
        }

        DEBUG_PRINT("Sent packet%s", "\n");

        unsigned char response[DNS_BUFFER_LENGTH];
        int response_length;
        socklen_t socklen = sizeof(struct sockaddr_in);
        if ((response_length = recvfrom(socket_fd, response, sizeof(response), MSG_WAITALL,
                                        (struct sockaddr *)&socket_addr, &socklen)) == -1) {
            ERROR_EXIT("Error: recvfrom() failed", EXIT_FAILURE);
        }

        DEBUG_PRINT("Got answer%s%d", "\n", response_length);
    }
    close(socket_fd);
}

int main(int argc, char *argv[]) {
    args_t args;
    FILE *file;

    //
    init_args_struct(&args);
    if (!parse_args(argc, argv, &args)) {
        ERROR_EXIT("Error: arguments for application\nRun ./sender --help for usage message\n", EXIT_FAILURE);
    }

    //
    if (!(file = strcmp(args.src_filepath, "") != 0 ? fopen(args.src_filepath, "r") : stdin)) {
        ERROR_EXIT("Error: file path\n", EXIT_FAILURE);
    }

    //
    send_packets(file, &args);

    //
    fclose(file);
    return 0;
}
