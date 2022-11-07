#ifndef COMMON_DNS_HELPER_H_
#define COMMON_DNS_HELPER_H_ 1

#include <netinet/in.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../common/base32.h"
#include "math.h"
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"

/******************************************************************************/
/**                                MACROS                                    **/
/******************************************************************************/
// Return Code
#define RET_OK 0
#define RET_FAILURE 1

#define FUNC_FAILURE (-1)
#define FUNC_OK (-10)

#define UNCONST(type, var) (*(type *)&(var))

// Calculations
#define BASE32_LENGTH_ENCODE(src_size) (((src_size)*8 + 4) / 5)
#define BASE32_LENGTH_DECODE(src_size) (ceil((src_size) / 1.6))

#define ARGS_LEN 1000  // CLI arguments length

#define LOCALHOST "127.0.0.1"
#define IP_ADDRESS_PLACE_HOLDER "0.0.0.0"

#define DNS_PORT 53  // Port

#define TTL 10

// Responses
#define DNS_ANSWER_SUCCESS 0

// Type
#define DNS_TYPE_A 1      // IPv4
#define DNS_TYPE_AAAA 28  // IPv6

// Class
#define DNS_CLASS_IN 1  // Internet

// Sizes
#define QNAME_MAX_LENGTH 255
#define SUBDOMAIN_NAME_LENGTH 63
#define SUBDOMAIN_DATA_LENGTH 60
#define SUBDOMAIN_CHUNKS 10
#define DGRAM_MAX_BUFFER_LENGTH 1024

// Flags sendto()
#define CUSTOM_MSG_CONFIRM 0x800

/******************************************************************************/
/**                                DEBUG VARS                                **/
/******************************************************************************/
#define TEST_RESEND 0
#define DEBUG 0
#define DEBUG_INFO 0
#define DEBUG_EVENT 1   // TODO leave it ON
#define DEBUG_BUFFER 0  // TODO leave it ON?

/******************************************************************************/
/**                                DEBUG                                     **/
/******************************************************************************/
#define ERROR_EXIT(msg, exit_code)                                         \
    do {                                                                   \
        fprintf(stderr, "%s:%d:%s(): " msg, __FILE__, __LINE__, __func__); \
        exit(exit_code);                                                   \
    } while (0)

#define PERROR_EXIT(msg)                                                   \
    do {                                                                   \
        fprintf(stderr, "%s:%d:%s(): " msg, __FILE__, __LINE__, __func__); \
        perror(msg);                                                       \
        exit(EXIT_FAILURE);                                                \
    } while (0)

#define ERROR_RETURN(msg, return_value) \
    do {                                \
        fprintf(stderr, (msg));         \
        return return_value;            \
    } while (0)

#define DEBUG_PRINT(fmt, ...)                                                               \
    do {                                                                                    \
        if (DEBUG_INFO) {                                                                   \
            fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, __VA_ARGS__); \
        } else if (DEBUG) {                                                                 \
            fprintf(stderr, fmt, __VA_ARGS__);                                              \
        }                                                                                   \
    } while (0)

#define ERROR_CALLBACK_MSG_EXIT(msg, callback_type, callback, ...) \
    do {                                                           \
        if (callback_type) {                                       \
            callback(__VA_ARGS__);                                 \
        }                                                          \
        PERROR_EXIT(msg);                                          \
    } while (0)

#define CALL_CALLBACK(callback_type, callback, ...) \
    do {                                            \
        if (callback_type) {                        \
            callback(__VA_ARGS__);                  \
        }                                           \
    } while (0)

// recvfrom msg
#define WRITE_CONTENT(data_decoded, data_decoded_len, args, mode)               \
    do {                                                                        \
        UNCONST(args_t *, args)->file = fopen((args)->filename, (mode));        \
        if (!(args)->file) {                                                    \
            ERROR_EXIT("Error: file ptr in null\n", EXIT_FAILURE);              \
        }                                                                       \
        fwrite((data_decoded), (data_decoded_len), sizeof(char), (args)->file); \
        fclose((args)->file);                                                   \
    } while (0)

/******************************************************************************/
/**                                 ENUMS                                    **/
/******************************************************************************/
enum PACKET_TYPE {
    START,             // Initialization packet
    DATA,              // Data packet
    END,               // Last packet
    RESEND,            // Packet was resend, somewhere problem occur
    RESEND_DATA,       // Data packet was resend, somewhere problem occur
    MALFORMED_PACKET,  // Packet in bad format
    BAD_BASE_HOST,     // The packet was for another BASE_HOST
    NOT_RECEIVED       // No packet was received yet.
};
enum IP_TYPE { IPv4, IPv6, IP_TYPE_ERROR };

/******************************************************************************/
/**                                 STRUCTS                                  **/
/******************************************************************************/
// All uint16 are in network byte order!!!
typedef struct {
    uint16_t id;

    // Flags
    unsigned int rd : 1;      // Recursion Desired
    unsigned int tc : 1;      // Truncation
    unsigned int aa : 1;      // Authoritative receiver
    unsigned int opcode : 4;  // Kind of query
    unsigned int qr : 1;      // Query or Response

    unsigned int rcode : 4;  // Response code
    unsigned int z : 3;      // Reserved for future use
    unsigned int ra : 1;     // Recursion available

    uint16_t qdcount;  // Question records
    uint16_t ancount;  // Answer records
    uint16_t nscount;  // Name server records
    uint16_t arcount;  // Resource records
} dns_header_t;

typedef struct {
    uint16_t type;
    uint16_t qclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;
} dns_answer_fields_t;

typedef struct {
    u_short qclass;
    u_short qtype;
} dns_question_fields_t;

typedef struct {
    int socket_fd;
    struct sockaddr_in socket_address;
    socklen_t socket_address_len;
} datagram_socket_info_t;

typedef struct {
    int num_chunks;
    char chunk[SUBDOMAIN_CHUNKS][SUBDOMAIN_NAME_LENGTH];
} datagram_question_chunks_t;

typedef struct {
    // Cli
    char *upstream_dns_ip;
    char *base_host;
    char *dst_filepath;
    char *filename;

    // Datagram
    FILE *file;
    enum IP_TYPE ip_type;
} args_t;

typedef struct dns_datagram_s {
    u_char *sender;
    u_char *receiver;
    int64_t sender_packet_len;
    int64_t receiver_packet_len;
    u_int64_t data_len;
    u_int64_t data_accumulated_len;
    datagram_socket_info_t network_info;
    uint16_t id;
    enum PACKET_TYPE packet_type;
} dns_datagram_t;

typedef struct program_s {
    args_t *args;
    dns_datagram_t *dgram;
} program_t;

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
/**
 * Create the dns name format for data part of domain
 * @param qname unsigned char data
 * @param args args_t structure
 * @param callback events callback form API for sender/receiver
 */
void get_dns_name_format_subdomains(u_char *qname, const args_t *args, void (*callback)(char *, int, char *),
                                    dns_datagram_t *dgram);

/**
 * Create the dns name format for base_host part of domain
 * @param domain unsigned char base_host
 */
void get_dns_name_format_base_host(uint8_t *);

/**
 * Get and Validate Ip version from string
 * Inspiration: https://stackoverflow.com/a/3736378/14471542
 * @param src IP address
 * @return IP version
 */
enum IP_TYPE ip_version(const char *src);

/**
 *  Check if current packet was already once processed
 * @param pkt_type
 * @return true if was current packet already processed else false
 */
bool is_not_resend_packet_type(enum PACKET_TYPE pkt_type);

/**
 * Check is was any problem with current processing packet
 * @param pkt_type
 * @return true if problem occur else false
 */
bool is_problem_packet_packet(enum PACKET_TYPE pkt_type);

/**
 * Validate base_host, exit on validation failed
 * @param str
 */
void validate_base_host_exit(char *str);

/**
 * Deallocate memory for args_t
 * @param args
 */
void deinit_args_struct(args_t *args);

/**
 * Initialize args_t
 * @return args_t
 */
args_t *init_args_struct();

/**
 * Initialize dns_datagram_t
 * @param args
 * @return dns_datagram_t
 */
dns_datagram_t *init_dns_datagram(const args_t *args, bool is_sender);

/**
 * Deallocate all memory on allocated on heap
 * @param dgram
 */
void dealocate_all_exit(args_t *args, dns_datagram_t *dgram, int exit_code);

#endif  // COMMON_DNS_HELPER_H_
