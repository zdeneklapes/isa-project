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

#ifndef _DNS_HELPER
#define _DNS_HELPER 1

#include <stdint.h>
#include <sys/types.h>

/******************************************************************************/
/**                                MACROS                                    **/
/******************************************************************************/
// Calculations
#define BASE32_LENGTH_ENCODE(src_size) (((src_size)*8 + 4) / 5)
#define BASE32_LENGTH_DECODE(src_size) (ceil(src_size / 1.6))

#define ARGS_LEN 1000  // CLI arguments length

#define DNS_PORT 53  // Port

#define TTL 500

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
#define DOMAIN_NAME_LENGTH 255
#define SUBDOMAIN_NAME_LENGTH 60
#define DNS_BUFFER_LENGTH 1024

// Flags sendto()
#define CUSTOM_MSG_CONFIRM 0x800

/******************************************************************************/
/**                                MACROS                                    **/
/******************************************************************************/
#define ERROR_EXIT(msg, exit_code)                                         \
    do {                                                                   \
        fprintf(stderr, "%s:%d:%s(): " msg, __FILE__, __LINE__, __func__); \
        exit(exit_code);                                                   \
    } while (0)

#define PERROR_EXIT(msg, exit_code) \
    do {                            \
        perror(msg);                \
        exit(exit_code);            \
    } while (0)

#define ERROR_RETURN(msg, return_value) \
    do {                                \
        fprintf(stderr, (msg));         \
        return return_value;            \
    } while (0)

/******************************************************************************/
/**                                DEBUG VARS                                **/
/******************************************************************************/
#define DEBUG 1
#define DEBUG_INFO 1
#define ACTION 1

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
/**                                STRUCTS                                   **/
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
    uint16_t arcount;  // Resource records // TODO: ?
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
    unsigned short qclass;
    unsigned short qtype;
} dns_question_fields_t;

/******************************************************************************/
/**                                FUNCTIONS DECLARATION                     **/
/******************************************************************************/
void create_dns_name_format_subdomains(char *);
void create_dns_name_format_base_host(uint8_t *);


#endif  // _DNS_HELPER
