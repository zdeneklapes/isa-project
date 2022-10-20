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
#include <sys/stat.h>

#include "../common/base32.h"
#include "../common/debug.h"
#include "../common/dns_helper.h"
#include "dns_sender_events.h"
#include "errno.h"
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
/**
 * Print help message
 */
static void usage();

/**
 * Check if string is empty
 * @param str
 * @return true string is empty, else false
 */
static bool is_empty_str(const char *str);

/**
 * Retrieve dns server from system /etc.resolv.conf
 * @param args
 * @return true if was successful else false
 */
static bool get_dns_servers_from_system(args_t *args);

/**
 * Helper for parsing cli arguments for each switcher
 * @param argc
 * @param argv
 * @param idx
 * @param args
 * @return -1 if all cli arguments was parsed else idx of next parsed argument
 */
static int check_switchers_and_argc(int argc, char *argv[], int idx, args_t *args);

/**
 * Parse all cli arguments
 * @param argc
 * @param argv
 * @return Initialized args_t struct
 */
static args_t parse_args_or_exit(int argc, char *argv[]);

/**
 * Get encoded qname right dns name format
 * @param args
 * @param qname
 * @param dgram
 * @return Length of qname
 */
static uint16_t get_qname_dns_name_format(const args_t *args, u_char *qname, dns_datagram_t *dgram);

/**
 * Get next chunk data from file
 * @param args
 * @param qname_data
 * @param dgram
 */
static void get_file_data(const args_t *args, u_char *qname_data, dns_datagram_t *dgram);

/**
 * Prepare qname
 * @param args
 * @param qname_data
 * @param dgram
 */
static void prepare_qname(const args_t *args, u_char *qname_data, dns_datagram_t *dgram);

/**
 * Prepare datagram question
 * @param args
 * @param dgram
 */
static void prepare_question(const args_t *args, dns_datagram_t *dgram);

/**
 * Send datagram packet
 * @param args
 * @param dgram
 */
static void send_packet(const args_t *args, dns_datagram_t *dgram);

/**
 * Prepare packet and send it
 * @param args
 * @param dgram
 */
static void prepare_and_send_packet(const args_t *args, dns_datagram_t *dgram);

/**
 * Start sending packets based on packet_type
 * @param args
 */
static void start_sending(const args_t *args);

/**
 * Starting point of this application
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]);

/******************************************************************************/
/**                                FUNCTION DEFINITION                       **/
/******************************************************************************/
static void usage() {
    printf(
        "Pouziti:\n"
        "\tdns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]\n"
        "Parametry:\n"
        "\t-u slouží k vynucení vzdáleného DNS server (pokud není specifikováno, program využije výchozí DNS server "
        "nastavený v systému)\n"
        "\t{BASE_HOST} slouží k nastavení bázové domény všech přenosů (tzn. dotazy budou odesílány na adresy "
        "*.{BASE_HOST}, tedy např. edcba.32.1.example.com)\n"
        "\t{DST_FILEPATH} cesta pod kterou se data uloží na serveru\n"
        "\t[SRC_FILEPATH] cesta k souboru který bude odesílán (pokud není specifikováno pak program čte data ze "
        "STDIN)\n"
        "Priklady:\n"
        "\tdns_sender -u 127.0.0.1 example.com data.txt ./data.txt\n"
        "\techo \"abc\" | dns_sender -u 127.0.0.1 example.com data.txt\n");
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
        args->upstream_dns_ip[strcspn(args->upstream_dns_ip, "\n")] = 0;
        return true;
    } else {
        ERROR_EXIT("Error: None server found in /etc/resolv.conf file\n", 1);
    }
}

static int check_switchers_and_argc(int argc, char *argv[], int idx, args_t *args) {
    if (argc == idx) {
        return -1;
    }

    if (strcmp(argv[idx], "-u") == 0) {
        memcpy(args->upstream_dns_ip, argv[idx + 1], strlen(argv[idx + 1]));
        return argc == idx + 2 ? -1 : idx + 2;
    }

    if (strcmp(argv[idx], "-h") == 0) {
        usage();
    }

    return idx;
}

static args_t parse_args_or_exit(int argc, char *argv[]) {
    char *base_host_token = NULL;
    char base_host[ARGS_LEN] = {0};
    char *base_host_delim = ".";
    args_t args = init_args_struct();
    args_t args_test = init_args_struct();  // for validation
    opterr = 1;

    int i = 1;
    for (; i < argc;) {
        if ((i = check_switchers_and_argc(argc, argv, i, &args)) == FUNC_FAILURE) {
            break;
        }
        strncpy(args.base_host, argv[i++], sizeof(args.base_host));
        if ((i = check_switchers_and_argc(argc, argv, i, &args)) == FUNC_FAILURE) {
            break;
        }
        strncpy(args.dst_filepath, argv[i++], sizeof(args.base_host));
        if ((i = check_switchers_and_argc(argc, argv, i, &args)) == FUNC_FAILURE) {
            break;
        }
        strncpy(args.filename, argv[i++], sizeof(args.base_host));
    }

    if (i != FUNC_FAILURE) {
        ERROR_EXIT("Error: bad arguments - Run ./dns_sender -h\n", EXIT_FAILURE);
    }

    // Set and Validate: upstream_dns_ip (Get dns server from system)
    if (strncmp(args.upstream_dns_ip, "", sizeof(args.upstream_dns_ip)) == 0) {
        if (!get_dns_servers_from_system(&args))
            ERROR_EXIT("Error: Get dns server from /etc/resolv.conf\n", EXIT_FAILURE);
    }

    // Set and Validate: ip_type
    if ((args.ip_type = ip_version(args.upstream_dns_ip)) == IP_TYPE_ERROR)
        ERROR_EXIT("Error: IP version bad format", EXIT_FAILURE);

    // TODO: Support infinite filename
    // Validate dst_filepath
    if (strlen(args.dst_filepath) > SUBDOMAIN_NAME_LENGTH           // len for subdomain
        || strcmp(args.dst_filepath, args_test.dst_filepath) == 0)  // not set
        ERROR_EXIT("Error: dst_filepath - Run ./dns_sender --help \n", EXIT_FAILURE);

    // Validate: filename
    if (strcmp(args.filename, args_test.filename) == 0) {
        // This is possible (STDIN)
    } else if (strcmp(args.filename, args_test.filename) != 0) {
        if (access(args.filename, F_OK) == FUNC_FAILURE) {
            ERROR_EXIT("Error: filename does not exist\n", EXIT_FAILURE);
        }
    }

    // Validate: base_host
    if (strcmp(args.base_host, args_test.base_host) == 0)  // base_host is set
        ERROR_EXIT("Error: base_host - Run ./dns_sender --help \n", EXIT_FAILURE);

    memcpy(base_host, args.base_host, strlen(args.base_host));
    if (strlen(base_host_token = strtok(base_host, base_host_delim)) > SUBDOMAIN_NAME_LENGTH)  // base_host max
                                                                                               // length
        ERROR_EXIT("Error: base_host too long - Run ./dns_sender --help \n", EXIT_FAILURE);

    if (strlen(base_host_token = strtok(NULL, base_host_delim)) > SUBDOMAIN_NAME_LENGTH)  // extension max length
        ERROR_EXIT("Error: base_host extension too long - Run ./dns_sender --help \n", EXIT_FAILURE);

    if ((base_host_token = strtok(NULL, base_host_delim)) != NULL)  // nothing else
        ERROR_EXIT("Error: base_host - Run ./dns_sender --help \n", EXIT_FAILURE);

    // Set and Validate: file, filename (Open)
    if (!(args.file = (strcmp(args.filename, "") != 0) ? fopen(args.filename, "r") : stdin))
        ERROR_EXIT("Error: filename or stdin can't be opened\n", EXIT_FAILURE);

    return args;
}

static uint16_t get_qname_dns_name_format(const args_t *args, u_char *qname, dns_datagram_t *dgram) {
    prepare_qname(args, qname, dgram);
    int data_len = strlen((char *)qname);

    u_char base_host[QNAME_MAX_LENGTH] = {0};
    u_char subdomain[QNAME_MAX_LENGTH] = {0};

    if (packet_type == START || packet_type == END) {
        strcat((char *)base_host, (char *)qname);  // include filename info and START/END label
        strcat((char *)base_host, ".");            // include filename info and START/END label
    }

    // Base Host
    strcat((char *)base_host, args->base_host);
    DEBUG_PRINT("BASENAME encoded: %s\n", base_host);
    get_dns_name_format_base_host(base_host);

    // Data (Subdomain)
    if (packet_type == DATA) {  // no data in START or END packet - included in base_host (because parsing function)
        base32_encode(qname, strlen((const char *)qname), subdomain, QNAME_MAX_LENGTH);
        DEBUG_PRINT("DATA encoded: %s\n", subdomain);
        get_dns_name_format_subdomains(subdomain, args, dns_sender__on_chunk_encoded, dgram);
    }

    // Done
    memset((char *)qname, 0, strlen((char *)qname));  // clean before set
    strcat((char *)qname, (char *)subdomain);
    strcat((char *)qname, (char *)base_host);

    // Validate qname
    if (strlen((char *)qname) >= QNAME_MAX_LENGTH)  // qname max length
        ERROR_EXIT("Error: implementation error - qname too long, max size 255", EXIT_FAILURE);

    DEBUG_PRINT("QNAME encoded: %s\n", qname);

    return packet_type == DATA ? data_len : 0;
}

static void get_file_data(const args_t *args, u_char *qname_data, dns_datagram_t *dgram) {
    int dns_name_len = QNAME_MAX_LENGTH - strlen(args->base_host);
    int len = BASE32_LENGTH_DECODE(dns_name_len);
    len = len - (ceil((double)len / SUBDOMAIN_DATA_LENGTH) + 10);  // max qname len is 255
    fread(qname_data, (int)len, 1, args->file);
    dgram->file_data_accumulated_len += strlen((char *)qname_data);
}

/******************************************************************************/
/**                                 PREPARE DGRAMS                           **/
/******************************************************************************/
static void prepare_qname(const args_t *args, u_char *qname_data, dns_datagram_t *dgram) {
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
        get_file_data(args, qname_data, dgram);
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

static void prepare_question(const args_t *args, dns_datagram_t *dgram) {
    memset(dgram->sender, 0, DGRAM_MAX_BUFFER_LENGTH);  // clean

    // Header
    dns_header_t *header = (dns_header_t *)dgram;
    header->id = dgram->id;

    header->qr = 0;      // This is a query
    header->opcode = 0;  // This is a standard query
    header->aa = 0;      // Not Authoritative
    header->tc = 0;      // This message is
    header->rd = 1;      // Recursion Desired

    header->ra = 0;  // Recursion not available!
    header->z = 0;
    header->rcode = 0;

    header->qdcount = htons(1);  // One sender
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    DEBUG_PRINT("Header id: %d\n", header->id);

    // Q
    u_char *question = (dgram->sender + sizeof(dns_header_t));

    // Q - qname
    uint8_t qname[QNAME_MAX_LENGTH] = {0};
    dgram->file_data_len = get_qname_dns_name_format(args, qname, dgram);  // if packet_type==DATA else 0
    memcpy(question, qname, strlen((char *)qname));

    // Q - type + class
    dns_question_fields_t *dns_question_fields = (dns_question_fields_t *)(question + strlen((char *)qname) + 1);
    dns_question_fields->qtype = (u_short)htons(DNS_TYPE_A);
    dns_question_fields->qclass = (u_short)htons(DNS_CLASS_IN);

    // Length
    dgram->sender_len = (uint16_t)((u_char *)(dns_question_fields + 1) - (u_char *)dgram->sender);
}

/******************************************************************************/
/**                                 SEND DGRAMS                              **/
/******************************************************************************/
static void send_packet(const args_t *args, dns_datagram_t *dgram) {
    socklen_t socket_len = sizeof(struct sockaddr_in);

    do {
        // Q
        if (sendto(dgram->info.socket_fd, dgram, dgram->sender_len, CUSTOM_MSG_CONFIRM,
                   (struct sockaddr *)&dgram->info.socket_address,
                   sizeof(dgram->info.socket_address)) == FUNC_FAILURE) {
            PERROR_EXIT("Error: sendto()");
        } else {
            DEBUG_PRINT("Ok: sendto(), sender len: %d\n", dgram->sender_len);
        }

        if (packet_type == DATA) {
            CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_chunk_sent,
                          (struct in_addr *)&dgram->info.socket_address.sin_addr, (char *)args->dst_filepath, dgram->id,
                          dgram->file_data_len);
        }

        // A
        if ((dgram->receiver_len = recvfrom(dgram->info.socket_fd, dgram->receiver, sizeof(dgram->receiver),
                                            MSG_WAITALL, (struct sockaddr *)&dgram->info.socket_address, &socket_len)) <
            0) {
            if (errno == EAGAIN) {  // Handle timeout
                DEBUG_PRINT("Error: EAGAIN recvfrom(), receiver len: %d\n", dgram->receiver_len);
                continue;
            } else {
                PERROR_EXIT("Error: recvfrom() failed\n");
            }
        } else {
            DEBUG_PRINT("Ok: recvfrom(), receiver len: %d\n", dgram->receiver_len);
        }
        break;
    } while (1);
}

static void prepare_and_send_packet(const args_t *args, dns_datagram_t *dgram) {
    prepare_question(args, dgram);

    //
    CALL_CALLBACK(DEBUG_BUFFER, print_buffer, dgram->sender, strlen((char *)dgram));  // TODO: Remove debug

    // Send packets and ensure delivery
    while (1) {
        send_packet(args, dgram);

        // Repeat if UDP_DGRAM was missed
        if (((dns_header_t *)dgram)->id == dgram->id) break;  // FIXME
    }
}

static void start_sending(const args_t *args) {
    dns_datagram_t dgram = init_dns_datagram(args, true);
    struct stat st = {0};
    stat(args->filename, &st);

    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_init, (struct in_addr *)&dgram.info.socket_address.sin_addr);

    // Send
    //
    packet_type = START;
    dgram.id++;
    prepare_and_send_packet(args, &dgram);

    //
    packet_type = DATA;
    while (!feof(args->file)) {
        dgram.id++;
        prepare_and_send_packet(args, &dgram);
    }

    //
    packet_type = END;
    dgram.id++;
    prepare_and_send_packet(args, &dgram);
    CALL_CALLBACK(DEBUG_EVENT, dns_sender__on_transfer_completed, (char *)args->dst_filepath,
                  dgram.file_data_accumulated_len);

    //
    close(dgram.info.socket_fd);
}

int main(int argc, char *argv[]) {
    //
    const args_t args = parse_args_or_exit(argc, argv);

    //
    start_sending(&args);

    //
    fclose(args.file);

    //
    return 0;
}
