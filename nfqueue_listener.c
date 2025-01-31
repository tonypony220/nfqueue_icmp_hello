#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>    // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h> // for libnetfilter_queue

#include <netinet/ip.h>   // for iphdr
#include <netinet/ip_icmp.h> // for icmphdr

char code;
char type;
// Function to calculate the checksum
unsigned short ip_checksum(void *vdata, size_t length) {
    unsigned long sum = 0;
    unsigned short *data = vdata;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    if (length > 0) {
        sum += *(unsigned char *)data;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}

static int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    unsigned char *packet;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    int id = ntohl(ph->packet_id);
    int len = nfq_get_payload(nfa, &packet);

    printf("Packet ID: %d, Payload Length: %d\n", id, len);

    if (len > 0) {
        struct iphdr *ip_header = (struct iphdr *)packet;

        // Check if it's an ICMP packet
        if (ip_header->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp_header = (struct icmphdr *)(packet + (ip_header->ihl * 4));

            printf("Original ICMP Type: %d, Code: %d\n", icmp_header->type, icmp_header->code);

            // Modify the ICMP header
            icmp_header->type = type; // Destination Unreachable
            icmp_header->code = code; // Host Unreachable

            // Recalculate the checksum
            icmp_header->checksum = 0;  // Reset checksum field
            icmp_header->checksum = ip_checksum((unsigned short *)icmp_header, sizeof(struct icmphdr));

            printf("Modified ICMP Type: %d, Code: %d\n", icmp_header->type, icmp_header->code);
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, len, packet);
}


int main(int argc, char *argv[]) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if( argc != 3) {
        fprintf(stderr, "Error: args\n");
        exit(1);
    }

    type = atoi( argv[1] );
    code = atoi( argv[2] );
    printf("type=%d code=%d\n", type, code);
    // Open the NFQUEUE library handle
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error: Unable to open nfqueue handle\n");
        exit(1);
    }

    // Unbind any previous NFQUEUE handler for AF_INET (IPv4)
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: Unable to unbind nfqueue handler\n");
        exit(1);
    }

    // Bind this program to handle packets from AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: Unable to bind nfqueue handler\n");
        exit(1);
    }

    // Create a queue handle for queue number 0
    qh = nfq_create_queue(h, 0, &process_packet, NULL);
    if (!qh) {
        fprintf(stderr, "Error: Unable to create nfqueue\n");
        exit(1);
    }

    // Set the copy packet mode
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error: Unable to set packet copy mode\n");
        exit(1);
    }

    // Get the file descriptor for the NFQUEUE
    fd = nfq_fd(h);

    // Main loop to process packets
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    // Cleanup
    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

