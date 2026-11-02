/* ref.c - C reference implementation that mirrors crypto.metal kernel logic
 * operation-for-operation (same integer widths, same limb layout), used to
 * validate every primitive against vectors.h on a host without a GPU.
 * Build: gcc -O2 -Wall -Wextra -o ref ref.c
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes_tables.h"
#include "sha_consts.h"
#include "vectors.h"

typedef uint32_t u32; typedef uint64_t u64; typedef uint8_t u8;

/* ============================ SHA-1 ============================ */
static u32 rol32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_compress(u32 h[5], const u8 blk[64]) {
    u32 w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)blk[4*i] << 24) | ((u32)blk[4*i+1] << 16) | ((u32)blk[4*i+2] << 8) | blk[4*i+3];
    for (int i = 16; i < 80; i++) w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20)      { f = (b & c) | (~b & d);       k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                k = 0xCA62C1D6; }
        u32 t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

static void sha1(const u8 *msg, u64 len, u8 out[20]) {
    u32 h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    u64 full = len / 64;
    for (u64 i = 0; i < full; i++) sha1_compress(h, msg + i * 64);
    u8 blk[64]; memset(blk, 0, 64);
    u64 rem = len - full * 64;
    memcpy(blk, msg + full * 64, rem);
    blk[rem] = 0x80;
    if (rem >= 56) { sha1_compress(h, blk); memset(blk, 0, 64); }
    u64 bits = len * 8;
    for (int i = 0; i < 8; i++) blk[63 - i] = (u8)(bits >> (8 * i));
    sha1_compress(h, blk);
    for (int i = 0; i < 5; i++) {
        out[4*i] = (u8)(h[i] >> 24); out[4*i+1] = (u8)(h[i] >> 16);
        out[4*i+2] = (u8)(h[i] >> 8); out[4*i+3] = (u8)h[i];
    }
}

/* ============================ SHA-256 ============================ */
static u32 ror32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(u32 h[8], const u8 blk[64]) {
    u32 w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)blk[4*i] << 24) | ((u32)blk[4*i+1] << 16) | ((u32)blk[4*i+2] << 8) | blk[4*i+3];
    for (int i = 16; i < 64; i++) {
        u32 s0 = ror32(w[i-15], 7) ^ ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        u32 s1 = ror32(w[i-2], 17) ^ ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        u32 S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        u32 maj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const u8 *msg, u64 len, u8 out[32]) {
    u32 h[8]; memcpy(h, SHA256_H, sizeof h);
    u64 full = len / 64;
    for (u64 i = 0; i < full; i++) sha256_compress(h, msg + i * 64);
    u8 blk[64]; memset(blk, 0, 64);
    u64 rem = len - full * 64;
    memcpy(blk, msg + full * 64, rem);
    blk[rem] = 0x80;
    if (rem >= 56) { sha256_compress(h, blk); memset(blk, 0, 64); }
    u64 bits = len * 8;
    for (int i = 0; i < 8; i++) blk[63 - i] = (u8)(bits >> (8 * i));
    sha256_compress(h, blk);
    for (int i = 0; i < 8; i++) {
        out[4*i] = (u8)(h[i] >> 24); out[4*i+1] = (u8)(h[i] >> 16);
        out[4*i+2] = (u8)(h[i] >> 8); out[4*i+3] = (u8)h[i];
    }
}

/* ============================ SHA-512 ============================ */
static u64 ror64(u64 x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_compress(u64 h[8], const u8 blk[128]) {
    u64 w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | blk[8*i + j];
    }
    for (int i = 16; i < 80; i++) {
        u64 s0 = ror64(w[i-15], 1) ^ ror64(w[i-15], 8) ^ (w[i-15] >> 7);
        u64 s1 = ror64(w[i-2], 19) ^ ror64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u64 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; i++) {
        u64 S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        u64 ch = (e & f) ^ (~e & g);
        u64 t1 = hh + S1 + ch + SHA512_K[i] + w[i];
        u64 S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        u64 maj = (a & b) ^ (a & c) ^ (b & c);
        u64 t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha512(const u8 *msg, u64 len, u8 out[64]) {
    u64 h[8]; memcpy(h, SHA512_H, sizeof h);
    u64 full = len / 128;
    for (u64 i = 0; i < full; i++) sha512_compress(h, msg + i * 128);
    u8 blk[128]; memset(blk, 0, 128);
    u64 rem = len - full * 128;
    memcpy(blk, msg + full * 128, rem);
    blk[rem] = 0x80;
    if (rem >= 112) { sha512_compress(h, blk); memset(blk, 0, 128); }
    u64 bits_lo = len << 3;
    u64 bits_hi = len >> 61;
    for (int i = 0; i < 8; i++) blk[127 - i] = (u8)(bits_lo >> (8 * i));
    for (int i = 0; i < 8; i++) blk[119 - i] = (u8)(bits_hi >> (8 * i));
    sha512_compress(h, blk);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[8*i + j] = (u8)(h[i] >> (56 - 8 * j));
}

/* ============================ AES (T-table) + CTR ============================ */
static u32 sub_word(u32 w) {
    return ((u32)sbox[(w >> 24) & 0xFF] << 24) | ((u32)sbox[(w >> 16) & 0xFF] << 16) |
           ((u32)sbox[(w >> 8) & 0xFF] << 8) | sbox[w & 0xFF];
}
static u32 rot_word(u32 w) { return (w << 8) | (w >> 24); }

static u8 xtime(u8 x) { return (u8)((x << 1) ^ ((x & 0x80) ? 0x1B : 0)); }

static void aes_key_expand(const u8 *key, int keylen, u32 *rk) {
    int nk = keylen / 4, nr = nk + 6;
    for (int i = 0; i < nk; i++)
        rk[i] = ((u32)key[4*i] << 24) | ((u32)key[4*i+1] << 16) | ((u32)key[4*i+2] << 8) | key[4*i+3];
    u8 rc = 1;
    for (int i = nk; i < 4 * (nr + 1); i++) {
        u32 t = rk[i-1];
        if (i % nk == 0) {
            t = sub_word(rot_word(t)) ^ ((u32)rc << 24);
            rc = xtime(rc);
        } else if (nk > 6 && i % nk == 4) {
            t = sub_word(t);
        }
        rk[i] = rk[i-nk] ^ t;
    }
}

static void aes_encrypt_block(const u32 *rk, int nr, const u8 in[16], u8 out[16]) {
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    s0 = ((u32)in[0] << 24) | ((u32)in[1] << 16) | ((u32)in[2] << 8) | in[3];     s0 ^= rk[0];
    s1 = ((u32)in[4] << 24) | ((u32)in[5] << 16) | ((u32)in[6] << 8) | in[7];     s1 ^= rk[1];
    s2 = ((u32)in[8] << 24) | ((u32)in[9] << 16) | ((u32)in[10] << 8) | in[11];  s2 ^= rk[2];
    s3 = ((u32)in[12] << 24) | ((u32)in[13] << 16) | ((u32)in[14] << 8) | in[15]; s3 ^= rk[3];
    for (int r = 1; r < nr; r++) {
        t0 = Te0[(s0 >> 24) & 0xFF] ^ Te1[(s1 >> 16) & 0xFF] ^ Te2[(s2 >> 8) & 0xFF] ^ Te3[s3 & 0xFF] ^ rk[4*r];
        t1 = Te0[(s1 >> 24) & 0xFF] ^ Te1[(s2 >> 16) & 0xFF] ^ Te2[(s3 >> 8) & 0xFF] ^ Te3[s0 & 0xFF] ^ rk[4*r+1];
        t2 = Te0[(s2 >> 24) & 0xFF] ^ Te1[(s3 >> 16) & 0xFF] ^ Te2[(s0 >> 8) & 0xFF] ^ Te3[s1 & 0xFF] ^ rk[4*r+2];
        t3 = Te0[(s3 >> 24) & 0xFF] ^ Te1[(s0 >> 16) & 0xFF] ^ Te2[(s1 >> 8) & 0xFF] ^ Te3[s2 & 0xFF] ^ rk[4*r+3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    t0 = ((u32)sbox[(s0 >> 24) & 0xFF] << 24) | ((u32)sbox[(s1 >> 16) & 0xFF] << 16) |
         ((u32)sbox[(s2 >> 8) & 0xFF] << 8) | sbox[s3 & 0xFF];
    t1 = ((u32)sbox[(s1 >> 24) & 0xFF] << 24) | ((u32)sbox[(s2 >> 16) & 0xFF] << 16) |
         ((u32)sbox[(s3 >> 8) & 0xFF] << 8) | sbox[s0 & 0xFF];
    t2 = ((u32)sbox[(s2 >> 24) & 0xFF] << 24) | ((u32)sbox[(s3 >> 16) & 0xFF] << 16) |
         ((u32)sbox[(s0 >> 8) & 0xFF] << 8) | sbox[s1 & 0xFF];
    t3 = ((u32)sbox[(s3 >> 24) & 0xFF] << 24) | ((u32)sbox[(s0 >> 16) & 0xFF] << 16) |
         ((u32)sbox[(s1 >> 8) & 0xFF] << 8) | sbox[s2 & 0xFF];
    t0 ^= rk[4*nr]; t1 ^= rk[4*nr+1]; t2 ^= rk[4*nr+2]; t3 ^= rk[4*nr+3];
    out[0] = (u8)(t0 >> 24); out[1] = (u8)(t0 >> 16); out[2] = (u8)(t0 >> 8); out[3] = (u8)t0;
    out[4] = (u8)(t1 >> 24); out[5] = (u8)(t1 >> 16); out[6] = (u8)(t1 >> 8); out[7] = (u8)t1;
    out[8] = (u8)(t2 >> 24); out[9] = (u8)(t2 >> 16); out[10] = (u8)(t2 >> 8); out[11] = (u8)t2;
    out[12] = (u8)(t3 >> 24); out[13] = (u8)(t3 >> 16); out[14] = (u8)(t3 >> 8); out[15] = (u8)t3;
}

static void aes_ctr(const u8 *key, int keylen, const u8 iv[16], const u8 *in, u8 *out, u64 len) {
    u32 rk[60];
    int nr = keylen / 4 + 6;
    aes_key_expand(key, keylen, rk);
    u8 ctr[16], ks[16];
    memcpy(ctr, iv, 16);
    for (u64 off = 0; off < len; off += 16) {
        aes_encrypt_block(rk, nr, ctr, ks);
        u64 n = len - off < 16 ? len - off : 16;
        for (u64 i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
        for (int i = 15; i >= 0; i--) { if (++ctr[i]) break; }
    }
}

/* ============================ secp256k1 ============================ */
/* field element: 8 x 32-bit limbs, little-endian */
typedef struct { u32 l[8]; } fe;

static const fe FE_P = {{0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
                         0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
static const fe FE_N = {{0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
                         0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

static int fe_ge(const fe *a, const fe *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->l[i] != b->l[i]) return a->l[i] > b->l[i];
    }
    return 1;
}

/* r = a - b mod p (assumes a,b < p) */
static void fe_sub(fe *r, const fe *a, const fe *b) {
    u64 borrow = 0;
    for (int i = 0; i < 8; i++) {
        u64 d = (u64)a->l[i] - b->l[i] - borrow;
        r->l[i] = (u32)d;
        borrow = (d >> 63) & 1;
    }
    if (borrow) { /* add p back */
        u64 carry = 0;
        for (int i = 0; i < 8; i++) {
            u64 s = (u64)r->l[i] + FE_P.l[i] + carry;
            r->l[i] = (u32)s; carry = s >> 32;
        }
    }
}

/* r = a + b mod p */
static void fe_add(fe *r, const fe *a, const fe *b) {
    u64 carry = 0;
    for (int i = 0; i < 8; i++) {
        u64 s = (u64)a->l[i] + b->l[i] + carry;
        r->l[i] = (u32)s; carry = s >> 32;
    }
    if (carry || fe_ge(r, &FE_P)) {
        u64 borrow = 0;
        for (int i = 0; i < 8; i++) {
            u64 d = (u64)r->l[i] - FE_P.l[i] - borrow;
            r->l[i] = (u32)d; borrow = (d >> 63) & 1;
        }
    }
}

/* raw 512-bit product of two 256-bit values (8 limbs each) -> 16 limbs */
static void mul256(const u32 a[8], const u32 b[8], u32 r[16]) {
    for (int i = 0; i < 16; i++) r[i] = 0;
    for (int i = 0; i < 8; i++) {
        u64 carry = 0;
        for (int j = 0; j < 8; j++) {
            u64 cur = (u64)r[i+j] + (u64)a[i] * b[j] + carry;
            r[i+j] = (u32)cur;
            carry = cur >> 32;
        }
        r[i+8] = (u32)carry;
    }
}

/* reduce 512-bit r mod p into fe out; p = 2^256 - 2^32 - 977, 2^256 = c = 2^32+977 */
static void fe_reduce(fe *out, const u32 r[16]) {
    /* 2^256 = 2^32 + 977 (mod p) */
    u32 u[10]; /* H * c, H = r[8..15]; c is 33-bit so compute as (H<<32) + H*977 */
    u64 carry = 0;
    for (int i = 0; i < 8; i++) {
        u64 cur = (u64)r[8+i] * 977 + carry;
        u[i] = (u32)cur; carry = cur >> 32;
    }
    u[8] = (u32)carry; u[9] = 0;
    carry = 0;
    for (int i = 0; i < 8; i++) {
        u64 cur = (u64)u[i+1] + r[8+i] + carry;
        u[i+1] = (u32)cur; carry = cur >> 32;
    }
    u[9] += (u32)carry;
    /* v = L + u, L = r[0..7] */
    u32 v[10];
    carry = 0;
    for (int i = 0; i < 10; i++) {
        u64 s = (u64)(i < 8 ? r[i] : 0) + u[i] + carry;
        v[i] = (u32)s; carry = s >> 32;
    }
    /* fold high 64 bits: w = v[8] + v[9]*2^32 (< 2^33), add w*c = w*977 + (w<<32) */
    u64 w = (u64)v[8] | ((u64)v[9] << 32);
    u64 w977 = w * 977; /* < 2^43 */
    u32 s[9];
    u64 cur = (u64)v[0] + (u32)w977;
    s[0] = (u32)cur; carry = cur >> 32;
    cur = (u64)v[1] + (u32)(w977 >> 32) + (u32)w + carry;
    s[1] = (u32)cur; carry = cur >> 32;
    cur = (u64)v[2] + (u32)(w >> 32) + carry;
    s[2] = (u32)cur; carry = cur >> 32;
    for (int i = 3; i < 8; i++) {
        cur = (u64)v[i] + carry;
        s[i] = (u32)cur; carry = cur >> 32;
    }
    s[8] = (u32)carry;
    /* s < 2^258; subtract p until < p */
    for (;;) {
        int ge = s[8] != 0;
        if (!ge) {
            fe tmp; for (int i = 0; i < 8; i++) tmp.l[i] = s[i];
            ge = fe_ge(&tmp, &FE_P);
        }
        if (!ge) break;
        u64 borrow = 0;
        for (int i = 0; i < 8; i++) {
            u64 d = (u64)s[i] - FE_P.l[i] - borrow;
            s[i] = (u32)d; borrow = (d >> 63) & 1;
        }
        s[8] = (u32)(s[8] - borrow);
    }
    for (int i = 0; i < 8; i++) out->l[i] = s[i];
}

static void fe_mul(fe *r, const fe *a, const fe *b) {
    u32 t[16];
    mul256(a->l, b->l, t);
    fe_reduce(r, t);
}

static void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }

static void fe_set_u32(fe *r, u32 x) {
    memset(r, 0, sizeof *r);
    r->l[0] = x;
}

static void fe_inv(fe *r, const fe *a) {
    /* a^(p-2) mod p; p-2 = 0xFFFF...FFFFFC2D */
    static const u8 exp[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2D };
    fe result, base;
    fe_set_u32(&result, 1);
    base = *a;
    for (int i = 0; i < 256; i++) {
        if ((exp[31 - i / 8] >> (i % 8)) & 1) fe_mul(&result, &result, &base);
        if (i < 255) fe_sqr(&base, &base);
    }
    *r = result;
}

static void fe_from_bytes(fe *r, const u8 b[32]) {
    for (int i = 0; i < 8; i++) {
        r->l[i] = ((u32)b[28 - 4*i] << 24) | ((u32)b[29 - 4*i] << 16) |
                  ((u32)b[30 - 4*i] << 8) | b[31 - 4*i];
    }
}

static void fe_to_bytes(u8 b[32], const fe *a) {
    for (int i = 0; i < 8; i++) {
        b[28 - 4*i] = (u8)(a->l[i] >> 24); b[29 - 4*i] = (u8)(a->l[i] >> 16);
        b[30 - 4*i] = (u8)(a->l[i] >> 8); b[31 - 4*i] = (u8)a->l[i];
    }
}

/* scalar (mod n) addition for BIP32 */
static void sc_add_mod_n(u8 out[32], const u8 a[32], const u8 b[32]) {
    u32 x[8], y[8];
    for (int i = 0; i < 8; i++) {
        x[i] = ((u32)a[28-4*i] << 24) | ((u32)a[29-4*i] << 16) | ((u32)a[30-4*i] << 8) | a[31-4*i];
        y[i] = ((u32)b[28-4*i] << 24) | ((u32)b[29-4*i] << 16) | ((u32)b[30-4*i] << 8) | b[31-4*i];
    }
    u64 carry = 0;
    for (int i = 0; i < 8; i++) {
        u64 s = (u64)x[i] + y[i] + carry;
        x[i] = (u32)s; carry = s >> 32;
    }
    fe tmp; for (int i = 0; i < 8; i++) tmp.l[i] = x[i];
    if (carry || fe_ge(&tmp, &FE_N)) {
        u64 borrow = 0;
        for (int i = 0; i < 8; i++) {
            u64 d = (u64)x[i] - FE_N.l[i] - borrow;
            x[i] = (u32)d; borrow = (d >> 63) & 1;
        }
    }
    for (int i = 0; i < 8; i++) {
        out[28-4*i] = (u8)(x[i] >> 24); out[29-4*i] = (u8)(x[i] >> 16);
        out[30-4*i] = (u8)(x[i] >> 8); out[31-4*i] = (u8)x[i];
    }
}

/* Jacobian point */
typedef struct { fe x, y, z; int inf; } pt;

static void pt_double(pt *r, const pt *p) {
    if (p->inf) { *r = *p; return; }
    fe y2, s, m, t, x3, y4, y3;
    fe_sqr(&y2, &p->y);
    fe_mul(&s, &p->x, &y2);            /* X*Y^2 */
    fe_add(&s, &s, &s); fe_add(&s, &s, &s); /* 4*X*Y^2 */
    fe_sqr(&t, &p->x);
    fe_add(&m, &t, &t); fe_add(&m, &m, &t); /* 3*X^2 */
    fe_sqr(&x3, &m);
    fe_sub(&x3, &x3, &s); fe_sub(&x3, &x3, &s); /* M^2 - 2S */
    fe_mul(&y4, &y2, &y2);
    fe_add(&t, &y4, &y4); fe_add(&t, &t, &t); fe_add(&t, &t, &t); /* 8*Y^4 */
    fe_sub(&y3, &s, &x3);
    fe_mul(&y3, &m, &y3);
    fe_sub(&y3, &y3, &t);
    fe_mul(&r->z, &p->y, &p->z);
    fe_add(&r->z, &r->z, &r->z);
    r->x = x3; r->y = y3; r->inf = 0;
}

static void pt_add(pt *r, const pt *p, const pt *q) {
    if (p->inf) { *r = *q; return; }
    if (q->inf) { *r = *p; return; }
    fe z1z1, z2z2, u1, u2, s1, s2, h, rr, h2, h3, t;
    fe_sqr(&z1z1, &p->z); fe_sqr(&z2z2, &q->z);
    fe_mul(&u1, &p->x, &z2z2);
    fe_mul(&u2, &q->x, &z1z1);
    fe_mul(&t, &q->z, &z2z2); fe_mul(&s1, &p->y, &t);
    fe_mul(&t, &p->z, &z1z1); fe_mul(&s2, &q->y, &t);
    if (fe_ge(&u1, &u2) && fe_ge(&u2, &u1)) { /* equal */
        fe neg; fe_sub(&neg, &FE_P, &s1); /* cheap equality via s1==s2 or s1+s2==0 */
        if (fe_ge(&s1, &s2) && fe_ge(&s2, &s1)) { pt_double(r, p); return; }
        (void)neg;
        r->inf = 1; return;
    }
    fe_sub(&h, &u2, &u1);
    fe_sub(&rr, &s2, &s1);
    fe_sqr(&h2, &h);
    fe_mul(&h3, &h2, &h);
    fe_mul(&t, &u1, &h2);
    fe_sqr(&r->x, &rr);
    fe_sub(&r->x, &r->x, &h3);
    fe_sub(&r->x, &r->x, &t); fe_sub(&r->x, &r->x, &t);
    fe_sub(&t, &t, &r->x);
    fe_mul(&r->y, &rr, &t);
    fe_mul(&t, &s1, &h3);
    fe_sub(&r->y, &r->y, &t);
    fe_mul(&r->z, &h, &p->z);
    fe_mul(&r->z, &r->z, &q->z);
    r->inf = 0;
}

static void pt_mul(pt *r, const u8 k[32], const pt *p) {
    pt acc; acc.inf = 1;
    pt base = *p;
    for (int i = 0; i < 256; i++) {
        if ((k[31 - i / 8] >> (i % 8)) & 1) pt_add(&acc, &acc, &base);
        if (i < 255) { pt d; pt_double(&d, &base); base = d; }
    }
    *r = acc;
}

static void pt_to_affine(pt *r, const pt *p) {
    if (p->inf) { *r = *p; return; }
    fe zi, zi2, zi3;
    fe_inv(&zi, &p->z);
    fe_sqr(&zi2, &zi);
    fe_mul(&zi3, &zi2, &zi);
    fe_mul(&r->x, &p->x, &zi2);
    fe_mul(&r->y, &p->y, &zi3);
    fe_set_u32(&r->z, 1);
    r->inf = 0;
}

/* ============================ HMAC-SHA512 / BIP32 ============================ */
static void hmac_sha512(const u8 *key, u64 keylen, const u8 *msg, u64 msglen, u8 out[64]) {
    u8 k[128], ipad[128], opad[128], inner[64];
    memset(k, 0, 128);
    if (keylen > 128) { sha512(key, keylen, k); }
    else memcpy(k, key, keylen);
    for (int i = 0; i < 128; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5C; }
    /* inner: ipad || msg */
    u64 total = 128 + msglen;
    u8 *buf = malloc(total);
    memcpy(buf, ipad, 128); memcpy(buf + 128, msg, msglen);
    sha512(buf, total, inner);
    u8 obuf[192]; memcpy(obuf, opad, 128); memcpy(obuf + 128, inner, 64);
    sha512(obuf, 192, out);
    free(buf);
}

static void bip32_master(const u8 seed[], u64 seedlen, u8 k[32], u8 c[32]) {
    static const u8 label[12] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    u8 buf[12 + 64], I[64];
    memcpy(buf, label, 12);
    u64 n = seedlen < 64 ? seedlen : 64;
    memcpy(buf + 12, seed, n);
    hmac_sha512(label, 12, buf + 12, n, I);
    memcpy(k, I, 32); memcpy(c, I + 32, 32);
}

static void ser32(u8 out[4], u32 i) {
    out[0] = (u8)(i >> 24); out[1] = (u8)(i >> 16); out[2] = (u8)(i >> 8); out[3] = (u8)i;
}

static void bip32_ckd_priv(const u8 kpar[32], const u8 cpar[32], u32 index, u8 kc[32], u8 cc[32]) {
    u8 data[37], I[64];
    if (index & 0x80000000u) {
        data[0] = 0;
        memcpy(data + 1, kpar, 32);
    } else {
        fe kx, ky; fe_from_bytes(&kx, kpar);
        /* pubkey = kpar * G */
        pt G, R, A;
        fe_from_bytes(&G.x, (const u8[]){0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
                                         0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98});
        fe_from_bytes(&G.y, (const u8[]){0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
                                         0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8});
        fe_set_u32(&G.z, 1); G.inf = 0;
        pt_mul(&R, kpar, &G);
        pt_to_affine(&A, &R);
        u8 xb[32], yb[32];
        fe_to_bytes(xb, &A.x); fe_to_bytes(yb, &A.y);
        data[0] = (yb[31] & 1) ? 0x03 : 0x02;
        memcpy(data + 1, xb, 32);
        (void)kx; (void)ky;
    }
    ser32(data + 33, index);
    hmac_sha512(cpar, 32, data, 37, I);
    sc_add_mod_n(kc, I, kpar);
    memcpy(cc, I + 32, 32);
}

/* ============================ test harness ============================ */
static int fails = 0;
static void tohex(char *dst, const u8 *src, int n) {
    for (int i = 0; i < n; i++) sprintf(dst + 2*i, "%02x", src[i]);
    dst[2*n] = 0;
}
static void check(const char *name, const u8 *got, const char *exp_hex, int n) {
    char buf[130]; tohex(buf, got, n);
    if (strcmp(buf, exp_hex) == 0) printf("PASS %s\n", name);
    else { printf("FAIL %s\n  got %s\n  exp %s\n", name, buf, exp_hex); fails++; }
}

int main(void) {
    /* SHA */
    {
        const u8 *msgs[7] = {msg_s0, msg_s1, msg_s2, msg_s3, msg_s4, msg_s5, msg_s6};
        unsigned lens[7] = {sha_len_s0, sha_len_s1, sha_len_s2, sha_len_s3, sha_len_s4, sha_len_s5, sha_len_s6};
        const char *e1[7] = {exp_s0_sha1, exp_s1_sha1, exp_s2_sha1, exp_s3_sha1, exp_s4_sha1, exp_s5_sha1, exp_s6_sha1};
        const char *e2[7] = {exp_s0_sha256, exp_s1_sha256, exp_s2_sha256, exp_s3_sha256, exp_s4_sha256, exp_s5_sha256, exp_s6_sha256};
        const char *e5[7] = {exp_s0_sha512, exp_s1_sha512, exp_s2_sha512, exp_s3_sha512, exp_s4_sha512, exp_s5_sha512, exp_s6_sha512};
        u8 out[64];
        for (int i = 0; i < 7; i++) {
            char name[64];
            sha1(msgs[i], lens[i], out);   sprintf(name, "sha1   s%d(len=%u)", i, lens[i]);     check(name, out, e1[i], 20);
            sha256(msgs[i], lens[i], out); sprintf(name, "sha256 s%d(len=%u)", i, lens[i]);     check(name, out, e2[i], 32);
            sha512(msgs[i], lens[i], out); sprintf(name, "sha512 s%d(len=%u)", i, lens[i]);     check(name, out, e5[i], 64);
        }
    }
    /* AES-CTR */
    {
        u8 out[64];
        aes_ctr(aes_k128, 16, aes_iv, aes_pt, out, 64);
        check("aes128-ctr NIST", out, aes_ct128, 64);
        aes_ctr(aes_k256, 32, aes_iv, aes_pt, out, 64);
        check("aes256-ctr NIST", out, aes_ct256, 64);
        aes_ctr(aes_k2, 16, aes_iv2, aes_pt2, out, 33);
        check("aes128-ctr 33B", out, aes_ct2, 33);
    }
    /* secp256k1 field */
    {
        fe a, b, r;
        #define HEX2FE(dst, hexstr) do { \
            u8 tmp[32]; for (int i = 0; i < 32; i++) { \
                char b2[3] = {hexstr[2*i], hexstr[2*i+1], 0}; tmp[i] = (u8)strtoul(b2, 0, 16); } \
            fe_from_bytes(dst, tmp); } while (0)
        HEX2FE(&a, secp_a); HEX2FE(&b, secp_b);
        fe_mul(&r, &a, &b);
        u8 ob[32]; fe_to_bytes(ob, &r);
        check("secp mul a*b", ob, secp_mul_ab, 32);
        fe pm1 = FE_P; fe_sub(&pm1, &pm1, &((fe){.l={1,0,0,0,0,0,0,0}}));
        fe_sqr(&r, &pm1);
        fe_to_bytes(ob, &r);
        check("secp (p-1)^2", ob, secp_sq_pm1, 32);
        fe five; fe_set_u32(&five, 5);
        fe_inv(&r, &five);
        fe_to_bytes(ob, &r);
        check("secp inv(5)", ob, secp_inv5, 32);
        /* point ops: 2G and kG */
        pt G, R, A;
        u8 gx[32], gy[32];
        for (int i = 0; i < 32; i++) {
            char b2[3] = {secp_Gx[2*i], secp_Gx[2*i+1], 0}; gx[i] = (u8)strtoul(b2, 0, 16);
            b2[0] = secp_Gy[2*i]; b2[1] = secp_Gy[2*i+1]; gy[i] = (u8)strtoul(b2, 0, 16);
        }
        fe_from_bytes(&G.x, gx); fe_from_bytes(&G.y, gy); fe_set_u32(&G.z, 1); G.inf = 0;
        u8 two[32] = {0}; two[31] = 2;
        pt_mul(&R, two, &G); pt_to_affine(&A, &R);
        fe_to_bytes(ob, &A.x); check("secp 2G.x", ob, secp_G2x, 32);
        fe_to_bytes(ob, &A.y); check("secp 2G.y", ob, secp_G2y, 32);
        u8 kb[32];
        for (int i = 0; i < 32; i++) { char b2[3] = {secp_k_big[2*i], secp_k_big[2*i+1], 0}; kb[i] = (u8)strtoul(b2, 0, 16); }
        pt_mul(&R, kb, &G); pt_to_affine(&A, &R);
        fe_to_bytes(ob, &A.x); check("secp kG.x", ob, secp_kG_x, 32);
        fe_to_bytes(ob, &A.y); check("secp kG.y", ob, secp_kG_y, 32);
        /* scalar add mod n: (n-1) + 2 = 1 */
        u8 nm1[32], twoo[32] = {0}, res[32];
        for (int i = 0; i < 32; i++) { char b2[3] = {secp_n[2*i], secp_n[2*i+1], 0}; nm1[i] = (u8)strtoul(b2, 0, 16); }
        nm1[31] -= 1;
        twoo[31] = 2;
        sc_add_mod_n(res, nm1, twoo);
        char rhex[65]; tohex(rhex, res, 32);
        if (strcmp(rhex, secp_n_add) == 0) printf("PASS secp (n-1)+2 mod n\n");
        else { printf("FAIL secp (n-1)+2 mod n: got %s exp %s\n", rhex, secp_n_add); fails++; }
    }
    /* BIP32 */
    {
        u8 k[32], c[32];
        bip32_master(bip_seed, 16, k, c);
        char kh[65], ch[65]; tohex(kh, k, 32); tohex(ch, c, 32);
        if (strcmp(kh, bip_master_k) == 0) printf("PASS bip32 master key\n");
        else { printf("FAIL bip32 master key: got %s exp %s\n", kh, bip_master_k); fails++; }
        if (strcmp(ch, bip_master_c) == 0) printf("PASS bip32 master chain\n");
        else { printf("FAIL bip32 master chain: got %s exp %s\n", ch, bip_master_c); fails++; }
        const unsigned idxs[5] = {bip_step0_index, bip_step1_index, bip_step2_index, bip_step3_index, bip_step4_index};
        const char *ek[5] = {bip_step0_k, bip_step1_k, bip_step2_k, bip_step3_k, bip_step4_k};
        const char *ec[5] = {bip_step0_c, bip_step1_c, bip_step2_c, bip_step3_c, bip_step4_c};
        for (int i = 0; i < 5; i++) {
            u8 kc[32], cc[32];
            bip32_ckd_priv(k, c, idxs[i], kc, cc);
            memcpy(k, kc, 32); memcpy(c, cc, 32);
            char name[64]; sprintf(name, "bip32 step %d (idx 0x%08x)", i, idxs[i]);
            tohex(kh, kc, 32); tohex(ch, cc, 32);
            if (strcmp(kh, ek[i]) == 0 && strcmp(ch, ec[i]) == 0) printf("PASS %s\n", name);
            else { printf("FAIL %s\n  k got %s exp %s\n  c got %s exp %s\n", name, kh, ek[i], ch, ec[i]); fails++; }
        }
    }
    printf(fails ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
