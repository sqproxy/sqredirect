#pragma once

#define A2S_INFO_REQUEST 0x54
#define A2S_RULES_REQUEST 0x56
#define A2S_PLAYERS_REQUEST 0x55

#define A2S_INFO_RESPONSE 0x49
#define A2S_RULES_RESPONSE 0x45
#define A2S_PLAYERS_RESPONSE 0x44
#define CSGO_UNKNOWN1_RESPONSE 0x6d
#define YOU_ARE_BANNED_RESPONSE 0x4c

#define IS_STEAM_PACKET(pckt) (bpf_memcmp(pckt, "\xFF\xFF\xFF\xFF", 4) == 0)

#define IS_QUERY_REQUEST_PACKET(pckt) ( \
    (pckt[4] == A2S_INFO_REQUEST) \
    || (pckt[4] == A2S_RULES_REQUEST) \
    || (pckt[4] == A2S_PLAYERS_REQUEST) \
)

// A2S_RESPONSES ATTACK
#define IS_UNLEGIT_REQUEST_PACKET(pckt) ( \
    (pckt[4] == A2S_INFO_RESPONSE) \
    || (pckt[4] == A2S_RULES_RESPONSE) \
    || (pckt[4] == A2S_PLAYERS_RESPONSE) \
    || (pckt[4] == CSGO_UNKNOWN1_RESPONSE) \
    || (pckt[4] == YOU_ARE_BANNED_RESPONSE) \
)

static __always_inline __u32 bpf_memcmp(void *lhs, void *rhs, __u8 len)
{
    u8 *lhs_byte = (u8*) lhs;
    u8 *rhs_byte = (u8*) rhs;

#pragma clang loop unroll(full)
    for (u8 i = 0; i < len; ++i) {
        if (lhs_byte[i] != rhs_byte[i]) {
            return 1;
        }
    }

    return 0;
}


static __always_inline void bpf_memcpy(void *dst, __u8 len, void *ptr)
{
    u8 *lhs_byte = (u8*) dst;
    u8 *rhs_byte = (u8*) ptr;

#pragma clang loop unroll(full)
    for (u8 i = 0; i < len; ++i) {
        lhs_byte[i] = rhs_byte[i];
    }
}
