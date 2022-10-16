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
#include "dns_helper.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******************************************************************************/
/**                                FUNCTIONS DEFINITION                      **/
/******************************************************************************/

/**
 * Source: https://github.com/tbenbrahim/dns-tunneling-poc
 * @param dns_qname_data
 */
void get_dns_name_format_subdomains(u_char *dns_qname_data) {
    // TODO: Change this function before source
    u_char dns_qname_data_copy[QNAME_MAX_LENGTH] = {0};
    memcpy(dns_qname_data_copy, dns_qname_data, strlen((char *)dns_qname_data));
    memset(dns_qname_data, 0, strlen((char *)dns_qname_data));
    u_char *dns_qname_data_ptr = dns_qname_data;

    size_t domain_len = strlen((char *)dns_qname_data_copy);
    size_t num_labels = domain_len / 60 + (domain_len % 60 ? 1 : 0);
    for (size_t i = 0; i < num_labels; ++i) {
        size_t start = i * 60;
        size_t count = (start + 60 <= domain_len) ? 60 : domain_len - start;
        *(dns_qname_data_ptr) = (unsigned char)count;
        memcpy(dns_qname_data_ptr + 1, dns_qname_data_copy + start, count);
        dns_qname_data_ptr += count + 1;
    }
}

void get_dns_name_format_base_host(u_char *domain) {
    char final_string[QNAME_MAX_LENGTH] = {0};
    char *ptr = strstr((char *)domain, ".");
    char *ptr_prev = (char *)domain;
    while (ptr != ptr_prev) {
        int number = ptr - ptr_prev;
        *(final_string + strlen(final_string)) = (u_char)number;
        memcpy(final_string + strlen(final_string), ptr_prev, ptr - ptr_prev);
        ptr_prev = ptr + 1;
        ptr = strstr(ptr + 1, ".");
        if (!ptr && !strstr(ptr_prev, ".")) {
            ptr = ptr_prev + strlen(ptr_prev);
        }
    }
    *(final_string + strlen(final_string)) = (u_char)0;
    memset(domain, 0, strlen((char *)domain));
    memcpy(domain, final_string, strlen(final_string));
}
