#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_PACKET_SIZE 65536
#define TAG_LEN 16
#define NONCE_LEN 12

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes > 0) {
        sum += *(unsigned char *)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

void recalculate_ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    iph->check = calculate_checksum((unsigned short *)iph, iph->ihl * 4);
}

void recalculate_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, unsigned char *payload, int payload_len) {
    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } psh;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    
    int tcp_len = sizeof(struct tcphdr) + payload_len;
    psh.tcp_length = htons(tcp_len);

    int psh_size = sizeof(struct pseudo_header) + tcp_len;
    unsigned char *pseudogram = malloc(psh_size);
    if (!pseudogram) return;

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), (unsigned char *)tcph, sizeof(struct tcphdr));
    memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), payload, payload_len);

    tcph->check = 0;
    tcph->check = calculate_checksum((unsigned short *)pseudogram, psh_size);
    free(pseudogram);
}

int decrypt_payload(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, 
                    unsigned char *key, unsigned char *nonce, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0;

    if (!ctx) return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto err;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto err;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) goto err;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto err;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <in_interface> <out_interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    unsigned char session_key[32];
    memset(session_key, 0xA5, sizeof(session_key)); 
    uint64_t packet_counter = 0;

    int rx_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int tx_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rx_sock < 0 || tx_sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[MAX_PACKET_SIZE];
    printf("Device2 (Receiver) active: Verifying tag and decrypting packets...\n");

    while (1) {
        ssize_t data_len = recvfrom(rx_sock, buffer, MAX_PACKET_SIZE, 0, NULL, NULL);
        if (data_len < 0) continue;

        struct ether_header *eth = (struct ether_header *)buffer;
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ether_header) + iph->ihl * 4);
                
                unsigned char *payload = (unsigned char *)tcph + tcph->doff * 4;
                int header_len = sizeof(struct ether_header) + iph->ihl * 4 + tcph->doff * 4;
                int received_total_payload_len = data_len - header_len;

                if (received_total_payload_len > TAG_LEN) {
                    int cipher_len = received_total_payload_len - TAG_LEN;
                    unsigned char *ciphertext = payload;
                    unsigned char *tag = payload + cipher_len;

                    unsigned char nonce[NONCE_LEN];
                    memset(nonce, 0, NONCE_LEN);
                    memcpy(nonce, &packet_counter, sizeof(uint64_t));
                    packet_counter++;

                    unsigned char plaintext[MAX_PACKET_SIZE];
                    int plain_len = decrypt_payload(ciphertext, cipher_len, tag, session_key, nonce, plaintext);
                    
                    if (plain_len >= 0) {
                        memcpy(payload, plaintext, plain_len);

                        int new_total_len = iph->ihl * 4 + tcph->doff * 4 + plain_len;
                        iph->tot_len = htons(new_total_len);
                        recalculate_ip_checksum(iph);
                        recalculate_tcp_checksum(iph, tcph, payload, plain_len);
                    } else {
                        fprintf(stderr, "Authentication failed! Dropping packet.\n");
                    }
                }
            }
        }
    }

    close(rx_sock);
    close(tx_sock);
    return 0;
}
