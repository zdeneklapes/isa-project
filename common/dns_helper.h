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
#define PARSED_QNAME_CHUNKS_RECEIVER 2
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
    // Types
    START,     // Initialization packet
    FILENAME,  // Send Filename
    DATA,      // Data packet
    SENDING,   // Send data
    END,       // Last packet

    //
    NONE_AFTER_FILENAME,  // Packet with different basehost after while FILENAME packets
    NONE_AFTER_SENDING,   // Packet with different basehost after while SENDING packets

    //
    MALFORMED_PACKET,   // Packet in bad format
    WAITING_NEXT_FILE,  // Waiting for next file
};
enum IP_TYPE { IPv4, IPv6, IP_TYPE_ERROR };

/******************************************************************************/
/**                                 STRUCTS                                  **/
/******************************************************************************/
// All uint16 are in network byte order!!!
typedef struct {
    unsigned short id;  // NOLINT

    // Flags
    unsigned int rd : 1;      // Recursion Desired  // NOLINT
    unsigned int tc : 1;      // Truncation // NOLINT
    unsigned int aa : 1;      // Authoritative receiver // NOLINT
    unsigned int opcode : 4;  // Kind of query // NOLINT
    unsigned int qr : 1;      // Query or Response // NOLINT
                              // NOLINT
    unsigned int rcode : 4;   // Response code // NOLINT
    unsigned int z : 3;       // Reserved for future use // NOLINT
    unsigned int ra : 1;      // Recursion available // NOLINT
                              // NOLINT
    unsigned short qdcount;   // Question records // NOLINT
    unsigned short ancount;   // Answer records // NOLINT
    unsigned short nscount;   // Name server records // NOLINT
    unsigned short arcount;   // Resource records // NOLINT
} dns_header_t;

typedef struct {
    unsigned short type;      // NOLINT
    unsigned short qclass;    // NOLINT
    unsigned short ttl;       // NOLINT
    unsigned short rdlength;  // NOLINT
    unsigned short rdata;     // NOLINT
} dns_answer_fields_t;

typedef struct {
    unsigned short qclass;  // NOLINT
    unsigned short qtype;   // NOLINT
} dns_question_fields_t;

typedef struct {
    int socket_fd;
    struct sockaddr_in socket_address;
    socklen_t socket_address_len;
} datagram_socket_info_t;

typedef struct {
    // Cli Arguments
    char *upstream_dns_ip;
    char *base_host;
    char *dst_filepath;
    char filename[DGRAM_MAX_BUFFER_LENGTH];
    char *tmp_ptr_filename;

    // Current packet type
    enum IP_TYPE ip_type;

    // File descriptor
    FILE *file;
} args_t;

typedef struct dns_datagram_s {
    // Datagram Info
    unsigned char sender[DGRAM_MAX_BUFFER_LENGTH];    // NOLINT
    unsigned char receiver[DGRAM_MAX_BUFFER_LENGTH];  // NOLINT
    long long int sender_packet_len;                  // NOLINT
    long long int receiver_packet_len;                // NOLINT
    unsigned long long int data_len;                  // NOLINT
    unsigned long long int data_accumulated_len;      // NOLINT
    datagram_socket_info_t network_info;              // NOLINT
    unsigned short id;                                // NOLINT

    // Current packet type
    enum PACKET_TYPE packet_type;
} dns_datagram_t;

typedef struct program_s {
    int argc;
    char **argv;
    args_t *args;
    dns_datagram_t *dgram;
} program_t;

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
/**
 * Print help message
 */
void usage();

/**
 * Check if string is empty
 * @param str
 * @return true string is empty, else false
 */
bool is_empty_str(const char *str);

/**
 * Create the dns name format for data part of domain
 * @param qname unsigned char data
 * @param args args_t structure
 * @param callback events callback form API for sender/receiver
 */
void prepare_data_dns_qname_format(program_t *program, void (*callback)(char *, int, char *));

/**
 * Create the dns name format for base_host part of domain
 * @param domain unsigned char base_host
 */
void get_dns_name_format(uint8_t *domain);

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
// bool is_problem_packet_packet(enum PACKET_TYPE pkt_type);

/**
 * Calculate length that can be encoded into qname
 * @param program_t
 * @return length that can be put into qname
 */
unsigned int get_length_to_send(program_t *program);

/**
 * Parse qname from received datagram into base_host, data_encoded and data_decoded
 * @param args
 * @param qname_by_subdomains
 * @param dgram
 */
void parse_dns_packet_qname(program_t *program, char *_data_decoded, char *_data_encoded, char *_basehost);

#endif  // COMMON_DNS_HELPER_H_
