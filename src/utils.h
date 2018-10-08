#pragma once

#include <net/udp.h>

#define IS_STEAM_PACKET(pckt) (memcmp((pckt)->marker, "\xFF\xFF\xFF\xFF", 4) == 0)

#pragma pack(push)
#pragma pack(1)

struct steam_connect_ack {
    uint8_t marker[4];
    uint8_t header;
    uint16_t version;
};

#pragma pack(pop)


typedef struct steam_connect_ack steam_connect_ack_t;


void calc_transport_csum(struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct udphdr *udp_header = udp_hdr(skb);

    int transport_len = skb->len - skb_transport_offset(skb);

    udp_header->check = 0;

    // skb->ip_summed == 3 when tx on, skb->ip_summed == 0 tx off
    if (skb->ip_summed == CHECKSUM_NONE) {
        skb->csum = csum_partial((char *)udp_header,sizeof(struct udphdr), skb->csum);
        udp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, transport_len, IPPROTO_UDP, skb->csum);
    }
    else {
        udp4_hwcsum(skb, ip_header->saddr, ip_header->daddr);
    }

    if (udp_header->check == 0) udp_header->check = CSUM_MANGLED_0;

    ip_send_check(ip_header);
}


int is_a2s_info_request(uint8_t* data, size_t len)
{
    static uint8_t payload[] = "\xFF\xFF\xFF\xFFTSource Engine Query";
    static size_t pl_len = sizeof(payload);

    if (len < pl_len) {
        return 0;
    }

    return memcmp(data, payload, pl_len) == 0;
}


int is_a2s_rules_request(uint8_t* data, size_t len)
{
    static uint8_t payload[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x56};
    static size_t pl_len = sizeof(payload);

    // 4 bytes for inside challenge number (ignored here)
    // e.g: \xFF\xFF\xFF\xFFV\x4B\xA1\xD5\x22
    if (len < pl_len + 4)
    {
        return 0;
    }

    return memcmp(data, payload, pl_len) == 0;
}


int is_a2s_players_request(uint8_t* data, size_t len)
{
    static uint8_t payload[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x55};
    static size_t pl_len = sizeof(payload);

    // 4 bytes for inside challenge number (ignored here)
    // e.g: \xFF\xFF\xFF\xFFU\x4B\xA1\xD5\x22
    if (len < pl_len + 4)
    {
        return 0;
    }

    return memcmp(data, payload, pl_len) == 0;
}


int is_steam_connect_ack(uint8_t* data, size_t len)
{
    steam_connect_ack_t* packet = (steam_connect_ack_t*)data;

    if (len < sizeof(steam_connect_ack_t))
    {
        return 0;
    }

    return IS_STEAM_PACKET(packet) && (packet->header) == 0x6b;
}
