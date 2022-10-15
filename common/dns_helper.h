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
#define ARGS_LEN 1000  // CLI arguments length

#define DNS_PORT 53  // Port

// Responses
#define RESPONSE_SUCCESS 0
#define RESPONSE_FORMAT_ERROR 1
#define RESPONSE_FAILURE 2
#define RESPONSE_NAME_ERROR 3
#define RESPONSE_REFUSED 5

// Type
#define DNS_TYPE_A 1      // IPv4
#define DNS_TYPE_AAAA 28  // IPv6

// Class
#define DNS_CLASS_IN 1  // Internet

// Sizes
#define DOMAIN_NAME_LENGTH 256
#define DNS_BUFFER_LENGTH 1024

// Flags sendto()
#define CUSTOM_MSG_CONFIRM 0x800

#define ERROR_EXIT(msg, exit_code) \
    do {                           \
        fprintf(stderr, (msg));    \
        exit(exit_code);           \
    } while (0)

#define PERROR_EXIT(msg, exit_code) \
    do {                            \
        perror(msg);                \
        exit(exit_code);            \
    } while (0)

/******************************************************************************/
/**                                DEBUG VARS                                **/
/******************************************************************************/
#define DEBUG 1
#define DEBUG_INFO 1

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

/******************************************************************************/
/**                                STRUCTS                                   **/
/******************************************************************************/
// All uint16 are in network byte order!!!
typedef struct {
    uint16_t id;

    // Flags
    unsigned int qr : 1;
    unsigned int opcode : 4;
    unsigned int aa : 1;
    unsigned int tc : 1;
    unsigned int rd : 1;
    unsigned int ra : 1;
    unsigned int z : 3;
    unsigned int rcode : 4;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct {
    unsigned char name[256];
    uint16_t type;
    uint16_t qclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;
} dns_answer_t;

typedef struct {
    uint8_t name[256];
    uint16_t type;
    uint16_t qclass;
} dns_question_t;

/******************************************************************************/
/**                                FUNCTIONS                                 **/
/******************************************************************************/

// void extract_dns_query(unsigned char *dns_buffer, struct dns_query_s *name_query);
// void debug_header(struct dns_header_s *header);
// void debug_name(struct dns_query_s *name_query);
// size_t prepare_response(struct dns_query_s *name_query, unsigned char *buffer, size_t num_received, uint32_t ttl,
//                         char *ip);

#endif  // _DNS_HELPER
