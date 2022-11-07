#include "dns_helper.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

/******************************************************************************/
/**                                FUNCTIONS DEFINITION                      **/
/******************************************************************************/
void usage() {
    printf(
        "==========================================\n"
        "========== Pouziti 'dns_sender' ==========\n"
        "==========================================\n"
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
        "\techo \"abc\" | dns_sender -u 127.0.0.1 example.com data.txt\n\n\n"
        "============================================\n"
        "========== Pouziti 'dns_receiver' ==========\n"
        "============================================\n"
        "\tdns_receiver {BASE_HOST} {DST_FILEPATH}\n"
        "Parametry:\n"
        "\t{BASE_HOST} slouží k nastavení bázové domény k příjmu dat\n"
        "\t{DST_FILEPATH} cesta pod kterou se budou všechny příchozí data/soubory ukládat (cesta specifikovaná "
        "klientem bude vytvořena pod tímto adresářem)\n"
        "Priklady:\n"
        "\tdns_receiver example.com ./data\n");
    exit(0);
}

bool is_empty_str(const char *str) { return str[0] == '\0'; }

void get_dns_name_format_subdomains(u_char *qname, const args_t *args, void (*callback)(char *, int, char *),
                                    dns_datagram_t *dgram) {
    u_char dns_qname_data_copy[QNAME_MAX_LENGTH] = {0};
    memcpy(dns_qname_data_copy, qname, strlen((char *)qname));
    memset(qname, 0, strlen((char *)qname));
    u_char *dns_qname_data_ptr = qname;

    size_t domain_len = strlen((char *)dns_qname_data_copy);
    size_t num_labels = ceil((double)domain_len / SUBDOMAIN_DATA_LENGTH);
    for (size_t i = 0; i < num_labels; ++i) {
        //
        size_t start = i * SUBDOMAIN_DATA_LENGTH;
        size_t count = (start + SUBDOMAIN_DATA_LENGTH <= domain_len) ? SUBDOMAIN_DATA_LENGTH : domain_len - start;

        // Set data
        *(dns_qname_data_ptr) = (unsigned char)count;
        memcpy(dns_qname_data_ptr + 1, dns_qname_data_copy + start, count);

        dns_qname_data_ptr += count + 1;  // next subdomain
    }

    CALL_CALLBACK(DEBUG_EVENT, callback, (char *)args->dst_filepath, dgram->id, (char *)qname);
}

void get_dns_name_format_base_host(u_char *domain) {
    u_char final_string[QNAME_MAX_LENGTH] = {0};
    char *ptr = strstr((char *)domain, ".");
    char *ptr_prev = (char *)domain;
    while (ptr != ptr_prev) {
        int number = (int)(ptr - ptr_prev);
        *(final_string + strlen((char *)final_string)) = (u_char)number;
        memcpy(final_string + strlen((char *)final_string), ptr_prev, ptr - ptr_prev);
        ptr_prev = ptr + 1;
        ptr = strstr(ptr + 1, ".");
        if (!ptr && !strstr(ptr_prev, ".")) {
            ptr = ptr_prev + strlen(ptr_prev);
        }
    }
    *(final_string + strlen((char *)final_string)) = (u_char)0;
    memset(domain, 0, strlen((char *)domain));
    memcpy(domain, final_string, strlen((char *)final_string));
}

enum IP_TYPE ip_version(const char *src) {
    char buf[16];
    if (inet_pton(AF_INET, src, buf)) {
        return IPv4;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return IPv6;
    }
    return IP_TYPE_ERROR;
}

bool is_not_resend_packet_type(enum PACKET_TYPE pkt_type) {
    return pkt_type == START || pkt_type == DATA || pkt_type == END;
}

bool is_problem_packet_packet(enum PACKET_TYPE pkt_type) {
    return pkt_type == MALFORMED_PACKET || pkt_type == BAD_BASE_HOST;
}
