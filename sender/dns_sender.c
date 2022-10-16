//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

// TODO: Includes: https://sites.uclouvain.be/SystInfo/usr/include/bits/socket.h.html
// TODO: Inspiration: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include <netinet/in.h>
#include <openssl/aes.h>

#include "../common/base32.h"
#include "../common/debug.h"
#include "../common/dns_helper.h"
#include "arpa/inet.h"
#include "getopt.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                GLOBAL VARS                               **/
/******************************************************************************/
enum PACKET_TYPE packet_type = START;

/******************************************************************************/
/**                                STRUCTS                                   **/
/******************************************************************************/
typedef struct {
    char upstream_dns_ip[ARGS_LEN];
    char base_host[ARGS_LEN];
    char dst_filepath[ARGS_LEN];
    char src_filepath[ARGS_LEN];
    FILE *file;
} args_t;

/******************************************************************************/
/**                                FUNCTION DECLARATION                      **/
/******************************************************************************/
static void usage();
static bool get_dns_servers_from_system(args_t *);
static args_t parse_args_or_exit(int, char *[]);
static args_t init_args_struct();
static void set_dns_qname(uint8_t *, const args_t *);
static void set_dns_header(dns_header_t *);
static bool is_empty_str(const char *str);
static void prepare_question(u_char *, const args_t *);
static uint16_t prepare_datagram(u_char *, const args_t *args);
static void send_packet(u_char *, int, int, struct sockaddr_in);
int main(int, char *[]);

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
static void usage() {
    printf("USAGE:");
    exit(0);
}

static args_t init_args_struct() {
    args_t args = {.base_host = {0}, .dst_filepath = {0}, .src_filepath = {0}, .upstream_dns_ip = {0}, .file = NULL};
    return args;
}

static bool is_empty_str(const char *str) { return str[0] == '\0'; }

static bool get_dns_servers_from_system(args_t *args) {
    FILE *fp;
    char line[QNAME_MAX_LENGTH];
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

static void set_dns_qname(uint8_t *dns_qname_file_data, const args_t *args) {
    // TODO: set max len 255 whole dns name
    u_char base_host[QNAME_MAX_LENGTH] = {0};
    u_char subdomain[QNAME_MAX_LENGTH] = {0};

    if (packet_type == START || packet_type == END) {
        strcat((char *)base_host, (char *)dns_qname_file_data);  // include filename info and START/END label
        strcat((char *)base_host, ".");                          // include filename info and START/END label
    }

    // Base Host
    strcat((char *)base_host, args->base_host);
    DEBUG_PRINT("HOSTNAME before num_chunks: %s\n", subdomain);
    get_dns_name_format_base_host(base_host);

    // Subdomains (Data)
    if (packet_type == DATA) {
        base32_encode(dns_qname_file_data, strlen((const char *)dns_qname_file_data), subdomain, QNAME_MAX_LENGTH);
        DEBUG_PRINT("SUBDOMAIN before num_chunks: %s\n", subdomain);
        get_dns_name_format_subdomains(subdomain);
    }

    // Clean
    memset((char *)dns_qname_file_data, 0, strlen((char *)dns_qname_file_data));

    // Done
    strcat((char *)dns_qname_file_data, (char *)subdomain);
    strcat((char *)dns_qname_file_data, (char *)base_host);

    if (strlen((char *)dns_qname_file_data) > QNAME_MAX_LENGTH)
        ERROR_EXIT("ERROR: qname too long, max size 255", EXIT_FAILURE);

    DEBUG_PRINT("DOMAIN: %s\n", dns_qname_file_data);
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

static struct sockaddr_in create_socket_address(const args_t *args) {
    // Prepare IP
    struct in_addr ip;
    inet_aton(args->upstream_dns_ip, &ip);
    //
    struct sockaddr_in socket_address = {.sin_addr = ip, .sin_family = AF_INET, .sin_port = htons(DNS_PORT)};
    return socket_address;
}

void get_file_data(const args_t *args, u_char *qname_data) {
    // TODO: Make better
    int dns_name_len = QNAME_MAX_LENGTH - strlen(args->base_host);
    int len = BASE32_LENGTH_DECODE(dns_name_len);
    (void )len;
    len -= len / 60 == 4 ? 8 : 6;
    fread(qname_data, len, 1, args->file);
}

/******************************************************************************/
/**                                 PREPARE DGRAMS                           **/
/******************************************************************************/
static void prepare_question(u_char *qname_data, const args_t *args) {
    // TODO: Handle max len of filename
    //    char *p = NULL;
    char delim[] = "./";

    if (packet_type == START) {
        char data[QNAME_MAX_LENGTH] = {0};
        strcat(data, "START.fstart.");
        if (strncmp(args->dst_filepath, delim, 2) == 0) {
            strcat(data, args->dst_filepath + 2);
        } else {
            strcat(data, args->dst_filepath);
        }
        strcat(data, ".fend");
        memcpy(qname_data, data, strlen(data));
    } else if (packet_type == DATA) {
        get_file_data(args, qname_data);
    } else if (packet_type == END) {
        char data[QNAME_MAX_LENGTH] = {0};
        strcat(data, "END.filename.");
        strcat(data, args->dst_filepath);
        memcpy(qname_data, data, strlen(data));
    } else {
        ERROR_EXIT("Error: Implementation\n", EXIT_FAILURE);
    }
}

static uint16_t prepare_datagram(u_char *dns_datagram, const args_t *args) {
    // Header
    dns_header_t *dns_header = (dns_header_t *)dns_datagram;
    set_dns_header(dns_header);

    // Question
    uint8_t qname_data[QNAME_MAX_LENGTH] = {0};
    prepare_question(qname_data, args);
    set_dns_qname(qname_data, args);

    // qname_data
    u_char *dns_question = (dns_datagram + sizeof(dns_header_t));
    memcpy(dns_question, qname_data, strlen((char *)qname_data));

    // type + class
    dns_question_fields_t *dns_question_fields =
        (dns_question_fields_t *)(dns_question + strlen((char *)qname_data) + 1);
    dns_question_fields->qtype = (u_short)htons(DNS_TYPE_A);
    dns_question_fields->qclass = (u_short)htons(DNS_CLASS_IN);

    //
    return (uint16_t)((u_char *)(dns_question_fields + 1) - (u_char *)dns_header);
}

/******************************************************************************/
/**                                 SEND DGRAMS                              **/
/******************************************************************************/
/**
 * Sending packets to receiver
 * @param file File pointer if specified, stdin pointer otherwise
 * @param args Struct pointer to application arguments
 */
static void send_packet(u_char *dns_datagram, int dns_datagram_len, int socket_fd,
                        const struct sockaddr_in socket_addr) {
    u_char dns_answer[DGRAM_MAX_BUFFER_LENGTH] = {0};
    size_t dns_response_length = 0;
    socklen_t socket_len = sizeof(struct sockaddr_in);

    while (1) {  // TODO : Check errors from sending datagrams
        // Question
        if (sendto(socket_fd, dns_datagram, dns_datagram_len, CUSTOM_MSG_CONFIRM, (struct sockaddr *)&socket_addr,
                   sizeof(struct sockaddr_in)) == -1) {
            // TODO: timeout + resend
            PERROR_EXIT("Error: sendto failed", EXIT_FAILURE);
        }
        DEBUG_PRINT("Send question len: %d\n", dns_datagram_len);

        // Answer
        if ((dns_response_length = recvfrom(socket_fd, dns_answer, sizeof(dns_answer), MSG_WAITALL,
                                            (struct sockaddr *)&socket_addr, &socket_len)) == (size_t)-1) {
            PERROR_EXIT("Error: recvfrom() failed", EXIT_FAILURE);
        }
        DEBUG_PRINT("Receive answer len: %zu\n", dns_response_length);
        break;
    }
}

void send_packet_based_on_type(args_t *args, datagram_socket_info_t *dgram_info) {
    u_char dns_datagram[DGRAM_MAX_BUFFER_LENGTH] = {0};
    uint16_t dns_question_len = prepare_datagram(dns_datagram, args);

    //
    print_buffer(dns_datagram, strlen((char *)dns_datagram));  // TODO: Remove debug
    send_packet(dns_datagram, dns_question_len, dgram_info->socket_fd,
                dgram_info->socket_addr);  // Send packets and ensure delivery
}

void send_data(args_t *args) {
    datagram_socket_info_t dgram_info = {.socket_fd = socket(AF_INET, SOCK_DGRAM, 0),
                                         .socket_addr = create_socket_address(args)};

    //
    if (dgram_info.socket_fd == -1) PERROR_EXIT("Error: socket() failed", EXIT_FAILURE);
    DEBUG_PRINT("Created socket%s", "\n");

    // Sending
    packet_type = START;
    send_packet_based_on_type(args, &dgram_info);

    packet_type = DATA;
    while (!feof(args->file)) {
        send_packet_based_on_type(args, &dgram_info);
    }

    packet_type = END;
    send_packet_based_on_type(args, &dgram_info);

    //
    close(dgram_info.socket_fd);
}

int main(int argc, char *argv[]) {
    args_t args = parse_args_or_exit(argc, argv);

    //
    if (!(args.file = strcmp(args.src_filepath, "") != 0 ? fopen(args.src_filepath, "r") : stdin))
        ERROR_EXIT("Error: file path\n", EXIT_FAILURE);

    // send file or stdin input
    send_data(&args);

    //
    fclose(args.file);
    return 0;
}
