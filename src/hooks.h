#pragma once

#include <linux/version.h>

#include "utils.h"

const size_t IP_UDP_HDR_SIZE = sizeof(struct iphdr) + sizeof(struct udphdr);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#define HOOK(name) unsigned int name( \
	void *priv, \
	struct sk_buff *skb, \
	const struct nf_hook_state *state) { \
		struct net_device *in = state->in; \
		struct net_device *out = state->out;

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#define HOOK(name) unsigned int name( \
	const struct nf_hook_ops *ops, \
	struct sk_buff *skb, \
	const struct nf_hook_state *state) { \
		struct net_device *in = state->in; \
		struct net_device *out = state->out;

#else  // < 4.1.0
#define HOOK(name) unsigned int name( \
	const struct nf_hook_ops *ops, \
	struct sk_buff *skb, \
	const struct net_device *in, \
	const struct net_device *out, \
	int (*okfn)(struct sk_buff *)) {
#endif


HOOK(pre_hook)
	struct iphdr* ip_header = ip_hdr(skb);

	// Handle only UDP IPv4 packets
	if (
		skb->protocol != htons(ETH_P_IP)
		|| ip_header->version != 4
		|| ip_header->protocol != IPPROTO_UDP
	) {
		return NF_ACCEPT;
	}

	struct udphdr* udp_header = udp_hdr(skb);

	if (in != NULL && strcmp(in->name, "lo") != 0)
	{
		// Redirect incoming requests to proxy

		size_t data_len = skb->len - IP_UDP_HDR_SIZE;
		uint8_t* data = (uint8_t *)skb_header_pointer(skb, IP_UDP_HDR_SIZE, 0, NULL);

		if (
			is_a2s_info_request(data, data_len)
			|| is_inet_search_request(data, data_len)
			|| is_a2s_players_request(data, data_len)
			|| is_a2s_rules_request(data, data_len)
		)
		{
			//printk(KERN_INFO "A2S: %d", is_a2s_info_request(data, data_len));
			//printk(KERN_INFO "A2S_Players: %d\n", is_a2s_players_request(data, data_len));
			//printk(KERN_INFO "A2S_Rules: %d\n", is_a2s_rules_request(data, data_len));

			uint16_t dst_port = ntohs(udp_header->dest);
			uint16_t new_dst_port = dst_port;

			switch(dst_port)
			{
				case 27022:
					new_dst_port = 27922;
					break;
				case 27021:
					new_dst_port = 27921;
					break;
				case 27020:
					new_dst_port = 27920;
					break;
				case 27019:
					new_dst_port = 27919;
					break;
				case 27018:
					new_dst_port = 27918;
					break;
				case 27017:
					new_dst_port = 27917;
					break;
				case 27016:
					new_dst_port = 27916;
					break;
				case 27015:
					new_dst_port = 27915;
					break;
			}

			if (new_dst_port != dst_port)
			{
				udp_header->dest = htons(new_dst_port);
				udp_header->check = 0;
				//calc_transport_csum(skb);
			}
		}
	}

	return NF_ACCEPT;
}

HOOK(post_hook)
	struct iphdr* ip_header = ip_hdr(skb);

	// Handle only UDP IPv4 packets
	if (
		skb->protocol != htons(ETH_P_IP)
		|| ip_header->version != 4
		|| ip_header->protocol != IPPROTO_UDP
	) {
		return NF_ACCEPT;
	}

	struct udphdr* udp_header = udp_hdr(skb);

	size_t data_len = skb->len - IP_UDP_HDR_SIZE;
	uint8_t* data = (uint8_t *)skb_header_pointer(skb, IP_UDP_HDR_SIZE, 0, NULL);

	if (out != NULL && strcmp(out->name, "lo") != 0)
	{
		// Redirect all proxy outgoing traffic
		uint16_t src_port = ntohs(udp_header->source);
		uint16_t new_src_port = src_port;

		switch(src_port)
		{
			case 27922:
				new_src_port = 27022;
				break;
			case 27921:
				new_src_port = 27021;
				break;
			case 27920:
				new_src_port = 27020;
				break;
			case 27919:
				new_src_port = 27019;
				break;
			case 27918:
				new_src_port = 27018;
				break;
			case 27917:
				new_src_port = 27017;
				break;
			case 27916:
				new_src_port = 27016;
				break;
			case 27915:
				new_src_port = 27015;
				break;
		}

		if (new_src_port != src_port)
		{
			udp_header->source = htons(new_src_port);
			calc_transport_csum(skb);
		}
	}

	return NF_ACCEPT;
}
