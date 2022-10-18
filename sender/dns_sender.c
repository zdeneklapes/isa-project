//
// Created by Zdeněk Lapeš on 13/10/22.
// Copyright 2022 <Zdenek Lapes>
//

/******************************************************************************/
/**                                 TODO                                     **/
/******************************************************************************/
// TODO: Includes: https://sites.uclouvain.be/SystInfo/usr/include/bits/socket.h.html
// TODO: Inspiration: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168

// TODO: Printing action by dolejska (ID)
// TODO: test timeout
// TODO: filename max len?

/******************************************************************************/
/**                                INCLUDES                                  **/
/******************************************************************************/
#include <netinet/in.h>

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
/**                                FUNCTION DECLARATION                      **/
/******************************************************************************/
static void usage();
static bool get_dns_servers_from_system(args_t *);
static args_t parse_args_or_exit(int, char *[]);
static void set_dns_qname(uint8_t *, const args_t *);
static void set_dns_header(dns_header_t *dns_header, const args_t *args);
static bool is_empty_str(const char *str);
static void prepare_question(u_char *, const args_t *);
static uint16_t prepare_datagram(u_char *, const args_t *args);
static void send_packet(u_char *dns_datagram, int dns_datagram_len, const datagram_socket_info_t *dgram_info);
int main(int, char *[]);

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
static void usage() {
    printf("USAGE:");
    exit(0);
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
            // TODO: Take the first nameserver or check what nameserver is ready to connect
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
    char *base_host_token = NULL;
    char base_host[ARGS_LEN] = {0};
    char *base_host_delim = ".";
    args_t args = init_args_struct();
    args_t args_test = init_args_struct();  // for validation
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
                ERROR_EXIT("Error: Bad option | Missing arg | Some other error -> Run './dns_sender -h' for help\n",
                           EXIT_FAILURE);
        }
    }

    // Set and Validate: upstream_dns_ip (Get dns server from system)
    if (strncmp(args.upstream_dns_ip, "", sizeof(args.upstream_dns_ip)) == 0) {
        if (!get_dns_servers_from_system(&args))
            ERROR_EXIT("Error: Get dns server from /etc/resolv.conf\n", EXIT_FAILURE);
    }

    // Set and Validate: ip_type
    if ((args.ip_type = ip_version(args.upstream_dns_ip)) == IP_TYPE_ERROR)
        ERROR_EXIT("Error: IP version bad format", EXIT_FAILURE);

    // Set and Validate: Required arguments
    if (optind + 2 == argc || optind + 3 == argc) {
        strncpy(args.base_host, argv[optind++], sizeof(args.base_host));
        strncpy(args.filename, argv[optind++], sizeof(args.filename));
        if (optind + 1 == argc) strncpy(args.dst_filepath, argv[optind++], sizeof(args.dst_filepath));
    } else {
        ERROR_EXIT("Error: Too few/many arguments - Run ./dns_sender --help \n", EXIT_FAILURE);
    }

    // TODO: Support infinite filename
    // Validate dst_filepath
    if (strlen(args.dst_filepath) > SUBDOMAIN_NAME_LENGTH           // len for subdomain
        || strcmp(args.dst_filepath, args_test.dst_filepath) == 0)  // not set
        ERROR_EXIT("Error: dst_filepath - Run ./dns_sender --help \n", EXIT_FAILURE);

    // Validate: filename
    if (strcmp(args.filename, args_test.filename) == 0)
        ERROR_EXIT("Error: filename - Run ./dns_sender --help \n", EXIT_FAILURE);

    // Validate: base_host
    if (strcmp(args.base_host, args_test.base_host) == 0)  // base_host is set
        ERROR_EXIT("Error: base_host - Run ./dns_sender --help \n", EXIT_FAILURE);

    memcpy(base_host, args.base_host, strlen(args.base_host));
    if (strlen(base_host_token = strtok(base_host, base_host_delim)) > SUBDOMAIN_NAME_LENGTH)  // base_host max length
        ERROR_EXIT("Error: base_host too long - Run ./dns_sender --help \n", EXIT_FAILURE);

    if (strlen(base_host_token = strtok(NULL, base_host_delim)) > SUBDOMAIN_NAME_LENGTH)  // extension max length
        ERROR_EXIT("Error: base_host extension too long - Run ./dns_sender --help \n", EXIT_FAILURE);

    if ((base_host_token = strtok(NULL, base_host_delim)) != NULL)  // extension max length
        ERROR_EXIT("Error: base_host - Run ./dns_sender --help \n", EXIT_FAILURE);

    // Set and Validate: file, filename (Open)
    if (!(args.file = (strcmp(args.filename, "") != 0) ? fopen(args.filename, "r") : stdin))
        ERROR_EXIT("Error: filename or stdin can't be opened\n", EXIT_FAILURE);

    return args;
}

static void set_dns_qname(uint8_t *dns_qname_file_data, const args_t *args) {
    u_char base_host[QNAME_MAX_LENGTH] = {0};
    u_char subdomain[QNAME_MAX_LENGTH] = {0};

    if (packet_type == START || packet_type == END) {
        strcat((char *)base_host, (char *)dns_qname_file_data);  // include filename info and START/END label
        strcat((char *)base_host, ".");                          // include filename info and START/END label
    }

    // base_host encode + make chunks
    strcat((char *)base_host, args->base_host);
    DEBUG_PRINT("BASENAME encoded: %s\n", base_host);
    get_dns_name_format_base_host(base_host);

    // subdomains(data) encode + make chunk
    if (packet_type == DATA) {  // no data in START or END packet - included in base_host (because parsing function)
        base32_encode(dns_qname_file_data, strlen((const char *)dns_qname_file_data), subdomain, QNAME_MAX_LENGTH);
        DEBUG_PRINT("DATA encoded: %s\n", subdomain);
        get_dns_name_format_subdomains(subdomain);
    }

    // Done
    memset((char *)dns_qname_file_data, 0, strlen((char *)dns_qname_file_data));  // clean before set
    strcat((char *)dns_qname_file_data, (char *)subdomain);
    strcat((char *)dns_qname_file_data, (char *)base_host);

    // Validate qname
    if (strlen((char *)dns_qname_file_data) >= QNAME_MAX_LENGTH)  // qname max length
        ERROR_EXIT("Error: implementation error - qname too long, max size 255", EXIT_FAILURE);

    DEBUG_PRINT("QNAME encoded: %s\n", dns_qname_file_data);
}

static void set_dns_header(dns_header_t *dns_header, const args_t *args) {
    dns_header->id = args->sender_process_id;

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

static struct sockaddr_in init_socket_address(const args_t *args) {
    // Prepare IP
    struct in_addr ip;
    inet_aton(args->upstream_dns_ip, &ip);
    //
    struct sockaddr_in socket_address = {.sin_addr = ip, .sin_family = AF_INET, .sin_port = htons(DNS_PORT)};
    return socket_address;
}

void get_file_data(const args_t *args, u_char *qname_data) {
    int dns_name_len = QNAME_MAX_LENGTH - strlen(args->base_host);
    int len = BASE32_LENGTH_DECODE(dns_name_len);
    len = len - (ceil((double)len / 60) + 3);  // max qname len is 255
    fread(qname_data, (int)len, 1, args->file);
}

/******************************************************************************/
/**                                 PREPARE DGRAMS                           **/
/******************************************************************************/
static void prepare_question(u_char *qname_data, const args_t *args) {
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
        strcat(data, "END.fstart.");
        if (strncmp(args->dst_filepath, delim, 2) == 0) {
            strcat(data, args->dst_filepath + 2);
        } else {
            strcat(data, args->dst_filepath);
        }
        strcat(data, ".fend");
        memcpy(qname_data, data, strlen(data));
    } else {
        ERROR_EXIT("Error: Implementation\n", EXIT_FAILURE);
    }
}

static uint16_t prepare_datagram(u_char *dns_datagram, const args_t *args) {
    memset(dns_datagram, 0, DGRAM_MAX_BUFFER_LENGTH);  // clean

    // Header
    dns_header_t *dns_header = (dns_header_t *)dns_datagram;
    set_dns_header(dns_header, args);

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
static void send_packet(u_char *dns_datagram, int dns_datagram_len, const datagram_socket_info_t *dgram_info) {
    u_char dns_answer[DGRAM_MAX_BUFFER_LENGTH] = {0};
    size_t dns_response_length = 0;
    socklen_t socket_len = sizeof(struct sockaddr_in);
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};

    //
    if (setsockopt(dgram_info->socket_fd, SOL_SOCKET, SO_SNDTIMEO | SO_RCVTIMEO | SO_REUSEADDR, &timeout,
                   sizeof timeout) == EXIT_FAILURE) {
        PERROR("Error: setsockopt()\n");
    }

    DEBUG_PRINT("Ok: setsockopt()\n", NULL);

    // TODO: timeout

    // TODO: packet with same id

    // Q
    if (sendto(dgram_info->socket_fd, dns_datagram, dns_datagram_len, CUSTOM_MSG_CONFIRM,
               (struct sockaddr *)&dgram_info->socket_addr, sizeof(struct sockaddr_in)) == EXIT_FAILURE) {
        PERROR("Error: sendto()");
    }
    DEBUG_PRINT("Ok: send_to(), question len: %d\n", dns_datagram_len);

    // A
    if ((dns_response_length = recvfrom(dgram_info->socket_fd, dns_answer, sizeof(dns_answer), MSG_WAITALL,
                                        (struct sockaddr *)&dgram_info->socket_addr, &socket_len)) == (size_t)-1) {
        PERROR("Error: recvfrom() failed");
    }
    DEBUG_PRINT("Ok: recvfrom(), answer len: %zu\n", dns_response_length);
}

void send_packet_based_on_type(const args_t *args, datagram_socket_info_t *dgram_info, const int _id) {
    UNCONST(args_t *, args)->sender_process_id = _id;  // Must be before prepare_datagram()

    //
    u_char dns_datagram[DGRAM_MAX_BUFFER_LENGTH] = {0};
    uint16_t dns_question_len = prepare_datagram(dns_datagram, args);

    //
    print_buffer(dns_datagram, strlen((char *)dns_datagram));  // TODO: Remove debug

    // Send packets and ensure delivery
    while (1) {
        send_packet(dns_datagram, dns_question_len, dgram_info);

        // Repeat if UDP_DGRAM was missed
        if (((dns_header_t *)dns_datagram)->id == args->sender_process_id) break;
    }
}

void send_data(const args_t *args) {
    uint16_t id = 1;
    datagram_socket_info_t dgram_info = {.socket_fd = socket(AF_INET, SOCK_DGRAM, 0),
                                         .socket_addr = init_socket_address(args)};

    //
    if (dgram_info.socket_fd == EXIT_FAILURE) PERROR("Error: socket()");
    DEBUG_PRINT("Ok: socket()\n", NULL);

    // Sending
    packet_type = START;
    send_packet_based_on_type(args, &dgram_info, id++);

    packet_type = DATA;
    for (; !feof(args->file); id++) {
        send_packet_based_on_type(args, &dgram_info, id);
    }

    packet_type = END;
    send_packet_based_on_type(args, &dgram_info, ++id);

    //
    close(dgram_info.socket_fd);
}

int main(int argc, char *argv[]) {
    //
    const args_t args = parse_args_or_exit(argc, argv);

    //
    send_data(&args);

    //
    fclose(args.file);

    //
    return 0;
}
