#include "utils.h"

#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <uapi/linux/ipv6.h>

#include <bcc/proto.h>
#include <bcc/helpers.h>


BPF_HASH(gameserver2cache_port, u16, u16, 128);
BPF_HASH(cache2gameserver_port, u16, u16, 128);


int incoming(struct __sk_buff *skb) {
    u8 *cursor = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet->type == ETH_P_IP)) {
        return TC_ACT_OK;
    }
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    if (ip->nextp != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

    if (!udp->crc) {
        // Attacker can miss checsum calculation
        // for performance reasons
        return TC_ACT_SHOT;
    }

    u16 dport = udp->dport;

    u16 *value = gameserver2cache_port.lookup(&dport);
    if (!value) {
        return TC_ACT_OK;
    }

    u16 cache_port = *value;

    u32 payload_offset = sizeof(*ethernet) + sizeof(*ip) + sizeof(*udp);
    u32 payload_length = ip->tlen - (sizeof(*ip) + sizeof(*udp));

    if (payload_length < 5) {
        return TC_ACT_OK;
    }

    // `BPF_FUNC_skb_load_bytes()` emulation to support Kernel 4.4
    // this function was added in Kernel 4.5
    // https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
    uint8_t data[5];
    data[0] = load_byte(skb, payload_offset);
    data[1] = load_byte(skb, payload_offset + 1);
    data[2] = load_byte(skb, payload_offset + 2);
    data[3] = load_byte(skb, payload_offset + 3);
    data[4] = load_byte(skb, payload_offset + 4);

    if (IS_STEAM_PACKET(data)) {
        if (IS_QUERY_REQUEST_PACKET(data)) {
            incr_cksum_l4(&udp->crc, udp->dport, cache_port, 1);
            udp->dport = cache_port;
        }
        else if (IS_UNLEGIT_REQUEST_PACKET(data)) {
            // we receive unlegit responses on game port
            // looks like ddos attack
            // drop it
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}


int outgoing(struct __sk_buff *skb) {
    u8 *cursor = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet->type == ETH_P_IP)) {
        return TC_ACT_OK;
    }
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    if (ip->nextp != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
    u16 sport = udp->sport;

    u16 *value = cache2gameserver_port.lookup(&sport);
    if (value != 0) {
        u16 gameserver_port = *value;

        incr_cksum_l4(&udp->crc, udp->sport, gameserver_port, 2);
        udp->sport = gameserver_port;
    }

    return TC_ACT_OK;
}
