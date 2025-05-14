#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

void dump(unsigned char* buf, int size) {
    for (int i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static u_int32_t extract_packet_info(struct nfq_data *tb, unsigned char **data) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, data);
    return id;
}

int is_malicious_site(unsigned char* data, const char *host_to_block) {
    unsigned char *http_data = data + ((data[0] & 0x0F) * 4) + ((data[20] & 0xF0) >> 4) * 4;
    const char *ptr = strstr((const char *) http_data, "Host: ");
    
    if (ptr) {
        char host[256];
        sscanf(ptr, "Host: %255s", host);
        if (strcmp(host, host_to_block) == 0) {
            return 1;
        }
    }
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    unsigned char *packet_data;
    u_int32_t id = extract_packet_info(nfa, &packet_data);

    printf("entering callback\n");

    if (is_malicious_site(packet_data, (const char *) data)) {
        printf("Blocking access to host: %s\n", (const char *) data);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <host>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(EXIT_FAILURE);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    qh = nfq_create_queue(h, 0, &cb, argv[1]);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        exit(EXIT_FAILURE);
    }

    fd = nfq_fd(h);

    for (;;) {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    exit(0);
}
