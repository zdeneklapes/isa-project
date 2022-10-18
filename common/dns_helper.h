/**
 * Copyright (c) 2021 Tony BenBrahim
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef COMMON_DNS_HELPER_H_
#define COMMON_DNS_HELPER_H_ 1

#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>

#include "math.h"

/******************************************************************************/
/**                                MACROS                                    **/
/******************************************************************************/
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
#define DNS_ANSWER_FORMAT_ERROR 1
#define DNS_ANSWER_FAILURE 2
#define DNS_ANSWER_NAME_ERROR 3
#define DNS_ANSWER_REFUSED 5

// Type
#define DNS_TYPE_A 1      // IPv4
#define DNS_TYPE_AAAA 28  // IPv6

// Class
#define DNS_CLASS_IN 1  // Internet

// Sizes
#define QNAME_MAX_LENGTH 255
#define SUBDOMAIN_NAME_LENGTH 63
#define EXTENSION_NAME_LENGTH 3
#define SUBDOMAIN_CHUNKS 10
#define DGRAM_MAX_BUFFER_LENGTH 1024

// Flags sendto()
#define CUSTOM_MSG_CONFIRM 0x800

// recvfrom msg
#define WRITE_CONTENT(data_decoded, data_decoded_len, args)                     \
    do {                                                                        \
        UNCONST(args_t *, args)->file = fopen((args)->filename, "a");           \
        fwrite((data_decoded), (data_decoded_len), sizeof(char), (args)->file); \
        fclose((args)->file);                                                   \
    } while (0)

/******************************************************************************/
/**                                DEBUG VARS                                **/
/******************************************************************************/
#define DEBUG 1
#define DEBUG_INFO 1
#define ACTION 1

/******************************************************************************/
/**                                DEBUG                                     **/
/******************************************************************************/
#define ERROR_EXIT(msg, exit_code)                                         \
    do {                                                                   \
        fprintf(stderr, "%s:%d:%s(): " msg, __FILE__, __LINE__, __func__); \
        exit(exit_code);                                                   \
    } while (0)

#define PERROR_EXIT(msg, exit_code)                                    \
    do {                                                               \
        fprintf(stderr, "%s:%d:%s(): ", __FILE__, __LINE__, __func__); \
        perror(msg);                                                   \
        exit(exit_code);                                               \
    } while (0)

#define ERROR_RETURN(msg, return_value) \
    do {                                \
        fprintf(stderr, (msg));         \
        return return_value;            \
    } while (0)

#define DEBUG_PRINT(fmt, ...)                  \
    do {                                       \
        if (DEBUG) {                           \
            fprintf(stderr, fmt, __VA_ARGS__); \
        }                                      \
    } while (0)

#define DEBUG_PRINT_WITH_INFO(fmt, ...)                                                                 \
    do {                                                                                                \
        if (DEBUG_INFO) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } while (0)

#define PRINT_ACTION(callback, ...) \
    do {                            \
        if (ACTION) {               \
            callback(__VA_ARGS__);  \
        }                           \
    } while (0)

/******************************************************************************/
/**                                 STRUCTS                                  **/
/******************************************************************************/
// All uint16 are in network byte order!!!
typedef struct {
    uint16_t id;

    // Flags
    unsigned int rd : 1;      // Recursion Desired
    unsigned int tc : 1;      // Truncation
    unsigned int aa : 1;      // Authoritative answer
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
    //    uint8_t *name;
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
    struct sockaddr_in socket_addr;
} datagram_socket_info_t;

typedef struct {
    int num_chunks;
    char chunk[SUBDOMAIN_CHUNKS][SUBDOMAIN_NAME_LENGTH];
} datagram_question_chunks_t;

/******************************************************************************/
/**                                 ENUMS                                    **/
/******************************************************************************/
enum PACKET_TYPE { START, DATA, END, PACKET_TYPE_ERROR };
enum IP_TYPE { IPv4, IPv6, IP_TYPE_ERROR };

/******************************************************************************/
/**                                 FUNCTIONS DECLARATION                    **/
/******************************************************************************/
void get_dns_name_format_subdomains(u_char *);
void get_dns_name_format_base_host(uint8_t *);

/**
 * Get and Validate Ip version from string
 * Source: https://stackoverflow.com/a/3736378/14471542
 *
 * @return IP version
 */
enum IP_TYPE ip_version(const char *);

#endif  // COMMON_DNS_HELPER_H_
