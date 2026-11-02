// run_metal_shim.cpp - executes the actual crypto.metal kernels on the host
// via the C++ shim (metal_shim.h), validating them against vectors.h.
// Build: g++ -std=c++14 -O2 -I. -include metal_shim.h -x c++ run_metal_shim.cpp -o run_metal_shim
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>

#include "crypto.metal"
#include "vectors.h"

static int fails = 0;
static void tohex(char *dst, const unsigned char *src, int n) {
    for (int i = 0; i < n; i++) sprintf(dst + 2*i, "%02x", src[i]);
    dst[2*n] = 0;
}
static void check(const char *name, const unsigned char *got, const char *exp_hex, int n) {
    char buf[130]; tohex(buf, got, n);
    if (strcmp(buf, exp_hex) == 0) printf("PASS %s\n", name);
    else { printf("FAIL %s\n  got %s\n  exp %s\n", name, buf, exp_hex); fails++; }
}

int main() {
    // pack all sha messages into one buffer
    {
        const unsigned char *msgs[7] = {msg_s0, msg_s1, msg_s2, msg_s3, msg_s4, msg_s5, msg_s6};
        const unsigned lens[7] = {sha_len_s0, sha_len_s1, sha_len_s2, sha_len_s3, sha_len_s4, sha_len_s5, sha_len_s6};
        const char *e1[7] = {exp_s0_sha1, exp_s1_sha1, exp_s2_sha1, exp_s3_sha1, exp_s4_sha1, exp_s5_sha1, exp_s6_sha1};
        const char *e2[7] = {exp_s0_sha256, exp_s1_sha256, exp_s2_sha256, exp_s3_sha256, exp_s4_sha256, exp_s5_sha256, exp_s6_sha256};
        const char *e5[7] = {exp_s0_sha512, exp_s1_sha512, exp_s2_sha512, exp_s3_sha512, exp_s4_sha512, exp_s5_sha512, exp_s6_sha512};
        unsigned char data[2048]; unsigned offs[7], lens32[7];
        unsigned pos = 0;
        for (int i = 0; i < 7; i++) { offs[i] = pos; lens32[i] = lens[i]; memcpy(data + pos, msgs[i], lens[i] ? lens[i] : 1); pos += lens[i] ? lens[i] : 1; }
        unsigned char o1[7*20], o2[7*32], o5[7*64];
        for (unsigned g = 0; g < 7; g++) {
            sha1_batch(data, offs, lens32, o1, g);
            sha256_batch(data, offs, lens32, o2, g);
            sha512_batch(data, offs, lens32, o5, g);
        }
        for (int i = 0; i < 7; i++) {
            char nm[64];
            sprintf(nm, "metal sha1   s%d", i); check(nm, o1 + i*20, e1[i], 20);
            sprintf(nm, "metal sha256 s%d", i); check(nm, o2 + i*32, e2[i], 32);
            sprintf(nm, "metal sha512 s%d", i); check(nm, o5 + i*64, e5[i], 64);
        }
    }
    // AES-CTR: one thread per 16-byte block
    {
        unsigned char out[64];
        unsigned klen = 16, len = 64;
        for (unsigned g = 0; g < 4; g++) aes_ctr_kernel(aes_k128, klen, aes_iv, aes_pt, out, len, g);
        check("metal aes128-ctr NIST", out, aes_ct128, 64);
        klen = 32;
        for (unsigned g = 0; g < 4; g++) aes_ctr_kernel(aes_k256, klen, aes_iv, aes_pt, out, len, g);
        check("metal aes256-ctr NIST", out, aes_ct256, 64);
        klen = 16; len = 33;
        unsigned char out2[33];
        for (unsigned g = 0; g < 3; g++) aes_ctr_kernel(aes_k2, klen, aes_iv2, aes_pt2, out2, len, g);
        check("metal aes128-ctr 33B", out2, aes_ct2, 33);
    }
    // secp256k1 field + point
    {
        unsigned char ab[32], bb[32], ob[32];
        auto hex2bin = [](const char *h, unsigned char *b) {
            for (int i = 0; i < 32; i++) { char t[3] = {h[2*i], h[2*i+1], 0}; b[i] = (unsigned char)strtoul(t, 0, 16); }
        };
        hex2bin(secp_a, ab); hex2bin(secp_b, bb);
        secp_field_mul_kernel(ab, bb, ob, 0);
        check("metal secp mul a*b", ob, secp_mul_ab, 32);
        // 2G and kG
        unsigned char two[32] = {0}, kb[32], ox[32], oy[32];
        two[31] = 2;
        secp_mul_g_kernel(two, ox, oy, 0);
        check("metal secp 2G.x", ox, secp_G2x, 32);
        check("metal secp 2G.y", oy, secp_G2y, 32);
        hex2bin(secp_k_big, kb);
        secp_mul_g_kernel(kb, ox, oy, 0);
        check("metal secp kG.x", ox, secp_kG_x, 32);
        check("metal secp kG.y", oy, secp_kG_y, 32);
    }
    // BIP32
    {
        unsigned char k[32], c[32]; char kh[65], ch[65];
        unsigned seedlen = 16;
        bip32_master_kernel(bip_seed, seedlen, k, c, 0);
        tohex(kh, k, 32); tohex(ch, c, 32);
        if (!strcmp(kh, bip_master_k)) printf("PASS metal bip32 master key\n"); else { printf("FAIL metal bip32 master key\n"); fails++; }
        if (!strcmp(ch, bip_master_c)) printf("PASS metal bip32 master chain\n"); else { printf("FAIL metal bip32 master chain\n"); fails++; }
        const unsigned idxs[5] = {bip_step0_index, bip_step1_index, bip_step2_index, bip_step3_index, bip_step4_index};
        const char *ek[5] = {bip_step0_k, bip_step1_k, bip_step2_k, bip_step3_k, bip_step4_k};
        const char *ec[5] = {bip_step0_c, bip_step1_c, bip_step2_c, bip_step3_c, bip_step4_c};
        for (int i = 0; i < 5; i++) {
            unsigned char kc[32], cc[32];
            unsigned idx = idxs[i];
            bip32_ckd_priv_kernel(k, c, idx, kc, cc, 0);
            memcpy(k, kc, 32); memcpy(c, cc, 32);
            tohex(kh, kc, 32); tohex(ch, cc, 32);
            char nm[64]; sprintf(nm, "metal bip32 step %d (idx 0x%08x)", i, idxs[i]);
            if (!strcmp(kh, ek[i]) && !strcmp(ch, ec[i])) printf("PASS %s\n", nm);
            else { printf("FAIL %s\n  k got %s exp %s\n  c got %s exp %s\n", nm, kh, ek[i], ch, ec[i]); fails++; }
        }
    }
    printf(fails ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
