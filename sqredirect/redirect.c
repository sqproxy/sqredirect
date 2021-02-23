#include "utils.h"

#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <uapi/linux/ipv6.h>

#include <bcc/proto.h>
#include <bcc/helpers.h>

BPF_HASH(gameserver2proxy_port, u16, u16, 128);
BPF_HASH(proxy2gameserver_port, u16, u16, 128);

#pragma pack(push)
#pragma pack(1)
struct _addr_key {
  u32 ip;
  u16 port;
};
#pragma pack(pop)

typedef struct _addr_key addr_key_t;

BPF_HASH(addr_gameserver2proxy_port, addr_key_t, u16, 128);
BPF_HASH(addr_proxy2gameserver_port, addr_key_t, u16, 128);


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

    u32 ip_dst = ip->dst;
    u16 dport = udp->dport;

    #ifndef USE_IPPORT_KEY
        u16 *value = gameserver2proxy_port.lookup(&dport);
    #else
        addr_key_t addr = {.ip = ip_dst, .port = dport};
        u16 *value = addr_gameserver2proxy_port.lookup(&addr);
    #endif

    if (!value) {
        return TC_ACT_OK;
    }

    u16 proxy_port = *value;

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
            incr_cksum_l4(&udp->crc, udp->dport, proxy_port, 1);
            udp->dport = proxy_port;
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

    u32 ip_src = ip->src;
    u16 sport = udp->sport;

    #ifndef USE_IPPORT_KEY
        u16 *value = proxy2gameserver_port.lookup(&sport);
    #else
        addr_key_t addr = {.ip = ip_src, .port = sport};
        u16 *value = addr_proxy2gameserver_port.lookup(&addr);
    #endif

    if (value != 0) {
        u16 gameserver_port = *value;

        incr_cksum_l4(&udp->crc, udp->sport, gameserver_port, 2);
        udp->sport = gameserver_port;
    }

    return TC_ACT_OK;
}
