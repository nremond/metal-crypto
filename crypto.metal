// crypto.metal - GPU kernels for SHA-1, SHA-256, SHA-512, AES-CTR,
// BIP32 (HMAC-SHA512 based) and secp256k1 field/point arithmetic.
//
// The logic mirrors ref.c operation-for-operation (same integer widths and
// limb layout); ref.c validates every primitive against vectors.h on the host.
//
// Build:  xcrun -sdk macosx metal -c crypto.metal -o crypto.air
//         xcrun -sdk macosx metallib crypto.air -o crypto.metallib

#include <metal_stdlib>
using namespace metal;

#include "sha_consts.h"   // constant uint/ulong SHA256_K, SHA256_H, SHA512_K, SHA512_H (Metal branch)
#include "aes_tables.h"   // constant uchar sbox[256]; constant uint Te0..Te3 (Metal branch)

static inline void zero_bytes(thread uchar *p, uint n) { for (uint i = 0; i < n; i++) p[i] = 0; }

// ============================ SHA-1 ============================
static inline uint rol32(uint x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_compress(thread uint h[5], thread const uchar blk[64]) {
    uint w[80];
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = ((uint)blk[4*i] << 24) | ((uint)blk[4*i+1] << 16) | ((uint)blk[4*i+2] << 8) | blk[4*i+3];
    #pragma unroll
    for (int i = 16; i < 80; i++) w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
        uint t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

static void sha1(thread const uchar *msg, ulong len, thread uchar out[20]) {
    uint h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    ulong full = len / 64;
    for (ulong i = 0; i < full; i++) sha1_compress(h, msg + i * 64);
    uchar blk[64]; zero_bytes(blk, 64);
    ulong rem = len - full * 64;
    for (ulong i = 0; i < rem; i++) blk[i] = msg[full * 64 + i];
    blk[rem] = 0x80;
    if (rem >= 56) { sha1_compress(h, blk); zero_bytes(blk, 64); }
    ulong bits = len * 8;
    for (int i = 0; i < 8; i++) blk[63 - i] = (uchar)(bits >> (8 * i));
    sha1_compress(h, blk);
    for (int i = 0; i < 5; i++) {
        out[4*i] = (uchar)(h[i] >> 24); out[4*i+1] = (uchar)(h[i] >> 16);
        out[4*i+2] = (uchar)(h[i] >> 8); out[4*i+3] = (uchar)h[i];
    }
}

kernel void sha1_batch(device const uchar *data [[buffer(0)]],
                       constant uint *offsets [[buffer(1)]],
                       constant uint *lens [[buffer(2)]],
                       device uchar *outs [[buffer(3)]],
                       uint gid [[thread_position_in_grid]]) {
    sha1(data + offsets[gid], lens[gid], outs + gid * 20);
}

// ============================ SHA-256 ============================
static inline uint ror32(uint x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(thread uint h[8], thread const uchar blk[64]) {
    uint w[64];
    #pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = ((uint)blk[4*i] << 24) | ((uint)blk[4*i+1] << 16) | ((uint)blk[4*i+2] << 8) | blk[4*i+3];
    #pragma unroll
    for (int i = 16; i < 64; i++) {
        uint s0 = ror32(w[i-15], 7) ^ ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint s1 = ror32(w[i-2], 17) ^ ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        uint S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(thread const uchar *msg, ulong len, thread uchar out[32]) {
    uint h[8];
    for (int i = 0; i < 8; i++) h[i] = SHA256_H[i];
    ulong full = len / 64;
    for (ulong i = 0; i < full; i++) sha256_compress(h, msg + i * 64);
    uchar blk[64]; zero_bytes(blk, 64);
    ulong rem = len - full * 64;
    for (ulong i = 0; i < rem; i++) blk[i] = msg[full * 64 + i];
    blk[rem] = 0x80;
    if (rem >= 56) { sha256_compress(h, blk); zero_bytes(blk, 64); }
    ulong bits = len * 8;
    for (int i = 0; i < 8; i++) blk[63 - i] = (uchar)(bits >> (8 * i));
    sha256_compress(h, blk);
    for (int i = 0; i < 8; i++) {
        out[4*i] = (uchar)(h[i] >> 24); out[4*i+1] = (uchar)(h[i] >> 16);
        out[4*i+2] = (uchar)(h[i] >> 8); out[4*i+3] = (uchar)h[i];
    }
}

kernel void sha256_batch(device const uchar *data [[buffer(0)]],
                         constant uint *offsets [[buffer(1)]],
                         constant uint *lens [[buffer(2)]],
                         device uchar *outs [[buffer(3)]],
                         uint gid [[thread_position_in_grid]]) {
    sha256(data + offsets[gid], lens[gid], outs + gid * 32);
}

// ============================ SHA-512 (streaming, for HMAC) ============================
static inline ulong ror64(ulong x, int n) { return (x >> n) | (x << (64 - n)); }

typedef struct { ulong h[8]; ulong len; uchar buf[128]; uint buflen; } sha512_ctx;

static void sha512_init(thread sha512_ctx *c) {
    for (int i = 0; i < 8; i++) c->h[i] = SHA512_H[i];
    c->len = 0; c->buflen = 0;
}

static void sha512_compress(thread ulong h[8], thread const uchar blk[128]) {
    ulong w[80];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | blk[8*i + j];
    }
    #pragma unroll
    for (int i = 16; i < 80; i++) {
        ulong s0 = ror64(w[i-15], 1) ^ ror64(w[i-15], 8) ^ (w[i-15] >> 7);
        ulong s1 = ror64(w[i-2], 19) ^ ror64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    ulong a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    #pragma unroll
    for (int i = 0; i < 80; i++) {
        ulong S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        ulong ch = (e & f) ^ (~e & g);
        ulong t1 = hh + S1 + ch + SHA512_K[i] + w[i];
        ulong S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha512_update(thread sha512_ctx *c, thread const uchar *msg, ulong len) {
    c->len += len;
    ulong i = 0;
    if (c->buflen) {
        uint need = 128 - c->buflen;
        uint take = (uint)min((ulong)need, len);
        for (uint j = 0; j < take; j++) c->buf[c->buflen + j] = msg[j];
        c->buflen += take; i = take;
        if (c->buflen == 128) { sha512_compress(c->h, c->buf); c->buflen = 0; }
    }
    for (; i + 128 <= len; i += 128) sha512_compress(c->h, msg + i);
    for (; i < len; i++) c->buf[c->buflen++] = msg[i];
}

static void sha512_final(thread sha512_ctx *c, thread uchar out[64]) {
    ulong bits_lo = c->len << 3;
    ulong bits_hi = c->len >> 61;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 112) {
        zero_bytes(c->buf + c->buflen, 128 - c->buflen);
        sha512_compress(c->h, c->buf);
        c->buflen = 0;
    }
    zero_bytes(c->buf + c->buflen, 112 - c->buflen);
    for (int i = 0; i < 8; i++) c->buf[119 - i] = (uchar)(bits_hi >> (8 * i));
    for (int i = 0; i < 8; i++) c->buf[127 - i] = (uchar)(bits_lo >> (8 * i));
    sha512_compress(c->h, c->buf);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) out[8*i + j] = (uchar)(c->h[i] >> (56 - 8 * j));
}

static void sha512(thread const uchar *msg, ulong len, thread uchar out[64]) {
    sha512_ctx c; sha512_init(&c);
    sha512_update(&c, msg, len);
    sha512_final(&c, out);
}

kernel void sha512_batch(device const uchar *data [[buffer(0)]],
                         constant uint *offsets [[buffer(1)]],
                         constant uint *lens [[buffer(2)]],
                         device uchar *outs [[buffer(3)]],
                         uint gid [[thread_position_in_grid]]) {
    sha512(data + offsets[gid], lens[gid], outs + gid * 64);
}

// ============================ AES (T-table) + CTR ============================
static inline uchar xtime(uchar x) { return (uchar)((x << 1) ^ ((x & 0x80) ? 0x1B : 0)); }
static inline uint sub_word(uint w) {
    return ((uint)sbox[(w >> 24) & 0xFF] << 24) | ((uint)sbox[(w >> 16) & 0xFF] << 16) |
           ((uint)sbox[(w >> 8) & 0xFF] << 8) | sbox[w & 0xFF];
}
static inline uint rot_word(uint w) { return (w << 8) | (w >> 24); }

static void aes_key_expand(thread const uchar *key, int keylen, thread uint *rk) {
    int nk = keylen / 4, nr = nk + 6;
    for (int i = 0; i < nk; i++)
        rk[i] = ((uint)key[4*i] << 24) | ((uint)key[4*i+1] << 16) | ((uint)key[4*i+2] << 8) | key[4*i+3];
    uchar rc = 1;
    for (int i = nk; i < 4 * (nr + 1); i++) {
        uint t = rk[i-1];
        if (i % nk == 0) {
            t = sub_word(rot_word(t)) ^ ((uint)rc << 24);
            rc = xtime(rc);
        } else if (nk > 6 && i % nk == 4) {
            t = sub_word(t);
        }
        rk[i] = rk[i-nk] ^ t;
    }
}

static void aes_encrypt_block(thread const uint *rk, int nr, thread const uchar in[16], thread uchar out[16]) {
    uint s0, s1, s2, s3, t0, t1, t2, t3;
    s0 = ((uint)in[0] << 24) | ((uint)in[1] << 16) | ((uint)in[2] << 8) | in[3];     s0 ^= rk[0];
    s1 = ((uint)in[4] << 24) | ((uint)in[5] << 16) | ((uint)in[6] << 8) | in[7];     s1 ^= rk[1];
    s2 = ((uint)in[8] << 24) | ((uint)in[9] << 16) | ((uint)in[10] << 8) | in[11];  s2 ^= rk[2];
    s3 = ((uint)in[12] << 24) | ((uint)in[13] << 16) | ((uint)in[14] << 8) | in[15]; s3 ^= rk[3];
    for (int r = 1; r < nr; r++) {
        t0 = Te0[(s0 >> 24) & 0xFF] ^ Te1[(s1 >> 16) & 0xFF] ^ Te2[(s2 >> 8) & 0xFF] ^ Te3[s3 & 0xFF] ^ rk[4*r];
        t1 = Te0[(s1 >> 24) & 0xFF] ^ Te1[(s2 >> 16) & 0xFF] ^ Te2[(s3 >> 8) & 0xFF] ^ Te3[s0 & 0xFF] ^ rk[4*r+1];
        t2 = Te0[(s2 >> 24) & 0xFF] ^ Te1[(s3 >> 16) & 0xFF] ^ Te2[(s0 >> 8) & 0xFF] ^ Te3[s1 & 0xFF] ^ rk[4*r+2];
        t3 = Te0[(s3 >> 24) & 0xFF] ^ Te1[(s0 >> 16) & 0xFF] ^ Te2[(s1 >> 8) & 0xFF] ^ Te3[s2 & 0xFF] ^ rk[4*r+3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    t0 = ((uint)sbox[(s0 >> 24) & 0xFF] << 24) | ((uint)sbox[(s1 >> 16) & 0xFF] << 16) |
         ((uint)sbox[(s2 >> 8) & 0xFF] << 8) | sbox[s3 & 0xFF];
    t1 = ((uint)sbox[(s1 >> 24) & 0xFF] << 24) | ((uint)sbox[(s2 >> 16) & 0xFF] << 16) |
         ((uint)sbox[(s3 >> 8) & 0xFF] << 8) | sbox[s0 & 0xFF];
    t2 = ((uint)sbox[(s2 >> 24) & 0xFF] << 24) | ((uint)sbox[(s3 >> 16) & 0xFF] << 16) |
         ((uint)sbox[(s0 >> 8) & 0xFF] << 8) | sbox[s1 & 0xFF];
    t3 = ((uint)sbox[(s3 >> 24) & 0xFF] << 24) | ((uint)sbox[(s0 >> 16) & 0xFF] << 16) |
         ((uint)sbox[(s1 >> 8) & 0xFF] << 8) | sbox[s2 & 0xFF];
    t0 ^= rk[4*nr]; t1 ^= rk[4*nr+1]; t2 ^= rk[4*nr+2]; t3 ^= rk[4*nr+3];
    out[0] = (uchar)(t0 >> 24); out[1] = (uchar)(t0 >> 16); out[2] = (uchar)(t0 >> 8); out[3] = (uchar)t0;
    out[4] = (uchar)(t1 >> 24); out[5] = (uchar)(t1 >> 16); out[6] = (uchar)(t1 >> 8); out[7] = (uchar)t1;
    out[8] = (uchar)(t2 >> 24); out[9] = (uchar)(t2 >> 16); out[10] = (uchar)(t2 >> 8); out[11] = (uchar)t2;
    out[12] = (uchar)(t3 >> 24); out[13] = (uchar)(t3 >> 16); out[14] = (uchar)(t3 >> 8); out[15] = (uchar)t3;
}

// One thread per 16-byte block. Counter is a 128-bit big-endian value incremented per block.
kernel void aes_ctr_kernel(device const uchar *key [[buffer(0)]],
                           constant uint &keylen [[buffer(1)]],
                           device const uchar *iv [[buffer(2)]],
                           device const uchar *in [[buffer(3)]],
                           device uchar *out [[buffer(4)]],
                           constant uint &len [[buffer(5)]],
                           uint gid [[thread_position_in_grid]]) {
    if ((ulong)gid * 16 >= len) return;
    uint rk[60];
    int nr = keylen / 4 + 6;
    aes_key_expand(key, keylen, rk);
    uchar ctr[16], ks[16];
    for (int i = 0; i < 16; i++) ctr[i] = iv[i];
    ulong inc = gid;
    for (int i = 15; i >= 0 && inc; i--) { ulong s = (ulong)ctr[i] + (inc & 0xFF); ctr[i] = (uchar)s; inc = (inc >> 8) + (s >> 8); }
    aes_encrypt_block(rk, nr, ctr, ks);
    ulong off = (ulong)gid * 16;
    uint n = (uint)min((ulong)16, (ulong)len - off);
    for (uint i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
}

// ============================ secp256k1 ============================
// Field element: 8 x 32-bit limbs, little-endian. 32-bit limbs are used because
// 64-bit integer ALU ops are reduced-rate on Apple GPUs; all products still fit
// in a full-rate 64-bit multiply.
typedef struct { uint l[8]; } fe;

static inline fe fe_p() {
    fe r = {{0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
             0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    return r;
}
static inline fe fe_n() {
    fe r = {{0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
             0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    return r;
}

static bool fe_ge(thread const fe *a, thread const fe *b) {
    for (int i = 7; i >= 0; i--)
        if (a->l[i] != b->l[i]) return a->l[i] > b->l[i];
    return true;
}

static void fe_sub(thread fe *r, thread const fe *a, thread const fe *b) {
    ulong borrow = 0;
    fe p = fe_p();
    for (int i = 0; i < 8; i++) {
        ulong d = (ulong)a->l[i] - b->l[i] - borrow;
        r->l[i] = (uint)d;
        borrow = (d >> 63) & 1;
    }
    if (borrow) {
        ulong carry = 0;
        for (int i = 0; i < 8; i++) {
            ulong s = (ulong)r->l[i] + p.l[i] + carry;
            r->l[i] = (uint)s; carry = s >> 32;
        }
    }
}

static void fe_add(thread fe *r, thread const fe *a, thread const fe *b) {
    ulong carry = 0;
    fe p = fe_p();
    for (int i = 0; i < 8; i++) {
        ulong s = (ulong)a->l[i] + b->l[i] + carry;
        r->l[i] = (uint)s; carry = s >> 32;
    }
    if (carry || fe_ge(r, &p)) {
        ulong borrow = 0;
        for (int i = 0; i < 8; i++) {
            ulong d = (ulong)r->l[i] - p.l[i] - borrow;
            r->l[i] = (uint)d; borrow = (d >> 63) & 1;
        }
    }
}

static void mul256(thread const uint a[8], thread const uint b[8], thread uint r[16]) {
    for (int i = 0; i < 16; i++) r[i] = 0;
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong cur = (ulong)r[i+j] + (ulong)a[i] * b[j] + carry;
            r[i+j] = (uint)cur;
            carry = cur >> 32;
        }
        r[i+8] = (uint)carry;
    }
}

// Reduce 512-bit r mod p; uses 2^256 = 2^32 + 977 (mod p). Both folds split the
// 33-bit constant into (x<<32) + x*977 so every product fits in 64 bits.
static void fe_reduce(thread fe *out, thread const uint r[16]) {
    uint u[10];
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong cur = (ulong)r[8+i] * 977 + carry;
        u[i] = (uint)cur; carry = cur >> 32;
    }
    u[8] = (uint)carry; u[9] = 0;
    carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong cur = (ulong)u[i+1] + r[8+i] + carry;
        u[i+1] = (uint)cur; carry = cur >> 32;
    }
    u[9] += (uint)carry;
    uint v[10];
    carry = 0;
    for (int i = 0; i < 10; i++) {
        ulong s = (ulong)(i < 8 ? r[i] : 0) + u[i] + carry;
        v[i] = (uint)s; carry = s >> 32;
    }
    ulong w = (ulong)v[8] | ((ulong)v[9] << 32);
    ulong w977 = w * 977;
    uint s[9];
    ulong cur = (ulong)v[0] + (uint)w977;
    s[0] = (uint)cur; carry = cur >> 32;
    cur = (ulong)v[1] + (uint)(w977 >> 32) + (uint)w + carry;
    s[1] = (uint)cur; carry = cur >> 32;
    cur = (ulong)v[2] + (uint)(w >> 32) + carry;
    s[2] = (uint)cur; carry = cur >> 32;
    for (int i = 3; i < 8; i++) {
        cur = (ulong)v[i] + carry;
        s[i] = (uint)cur; carry = cur >> 32;
    }
    s[8] = (uint)carry;
    fe p = fe_p();
    for (;;) {
        bool ge = s[8] != 0;
        if (!ge) {
            fe tmp; for (int i = 0; i < 8; i++) tmp.l[i] = s[i];
            ge = fe_ge(&tmp, &p);
        }
        if (!ge) break;
        ulong borrow = 0;
        for (int i = 0; i < 8; i++) {
            ulong d = (ulong)s[i] - p.l[i] - borrow;
            s[i] = (uint)d; borrow = (d >> 63) & 1;
        }
        s[8] = (uint)(s[8] - borrow);
    }
    for (int i = 0; i < 8; i++) out->l[i] = s[i];
}

static void fe_mul(thread fe *r, thread const fe *a, thread const fe *b) {
    uint t[16];
    mul256(a->l, b->l, t);
    fe_reduce(r, t);
}

static void fe_sqr(thread fe *r, thread const fe *a) { fe_mul(r, a, a); }

static void fe_set_u32(thread fe *r, uint x) {
    for (int i = 0; i < 8; i++) r->l[i] = 0;
    r->l[0] = x;
}

constant uchar FE_P_MINUS_2[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2D };

static void fe_inv(thread fe *r, thread const fe *a) {
    // a^(p-2) mod p, LSB-first square-and-multiply
    fe result, base;
    fe_set_u32(&result, 1);
    base = *a;
    for (int i = 0; i < 256; i++) {
        if ((FE_P_MINUS_2[31 - i / 8] >> (i % 8)) & 1) fe_mul(&result, &result, &base);
        if (i < 255) fe_sqr(&base, &base);
    }
    *r = result;
}

static void fe_from_bytes(thread fe *r, thread const uchar b[32]) {
    for (int i = 0; i < 8; i++)
        r->l[i] = ((uint)b[28 - 4*i] << 24) | ((uint)b[29 - 4*i] << 16) |
                  ((uint)b[30 - 4*i] << 8) | b[31 - 4*i];
}

static void fe_to_bytes(thread uchar b[32], thread const fe *a) {
    for (int i = 0; i < 8; i++) {
        b[28 - 4*i] = (uchar)(a->l[i] >> 24); b[29 - 4*i] = (uchar)(a->l[i] >> 16);
        b[30 - 4*i] = (uchar)(a->l[i] >> 8); b[31 - 4*i] = (uchar)a->l[i];
    }
}

// scalar (mod n) addition for BIP32
static void sc_add_mod_n(thread uchar out[32], thread const uchar a[32], thread const uchar b[32]) {
    uint x[8], y[8];
    for (int i = 0; i < 8; i++) {
        x[i] = ((uint)a[28-4*i] << 24) | ((uint)a[29-4*i] << 16) | ((uint)a[30-4*i] << 8) | a[31-4*i];
        y[i] = ((uint)b[28-4*i] << 24) | ((uint)b[29-4*i] << 16) | ((uint)b[30-4*i] << 8) | b[31-4*i];
    }
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong s = (ulong)x[i] + y[i] + carry;
        x[i] = (uint)s; carry = s >> 32;
    }
    fe n = fe_n();
    fe tmp; for (int i = 0; i < 8; i++) tmp.l[i] = x[i];
    if (carry || fe_ge(&tmp, &n)) {
        ulong borrow = 0;
        for (int i = 0; i < 8; i++) {
            ulong d = (ulong)x[i] - n.l[i] - borrow;
            x[i] = (uint)d; borrow = (d >> 63) & 1;
        }
    }
    for (int i = 0; i < 8; i++) {
        out[28-4*i] = (uchar)(x[i] >> 24); out[29-4*i] = (uchar)(x[i] >> 16);
        out[30-4*i] = (uchar)(x[i] >> 8); out[31-4*i] = (uchar)x[i];
    }
}

// Jacobian point
typedef struct { fe x, y, z; bool inf; } pt;

static void pt_double(thread pt *r, thread const pt *p) {
    if (p->inf) { *r = *p; return; }
    fe y2, s, m, t, x3, y4, y3;
    fe_sqr(&y2, &p->y);
    fe_mul(&s, &p->x, &y2);
    fe_add(&s, &s, &s); fe_add(&s, &s, &s);              // 4*X*Y^2
    fe_sqr(&t, &p->x);
    fe_add(&m, &t, &t); fe_add(&m, &m, &t);              // 3*X^2
    fe_sqr(&x3, &m);
    fe_sub(&x3, &x3, &s); fe_sub(&x3, &x3, &s);          // M^2 - 2S
    fe_mul(&y4, &y2, &y2);
    fe_add(&t, &y4, &y4); fe_add(&t, &t, &t); fe_add(&t, &t, &t); // 8*Y^4
    fe_sub(&y3, &s, &x3);
    fe_mul(&y3, &m, &y3);
    fe_sub(&y3, &y3, &t);
    fe_mul(&r->z, &p->y, &p->z);
    fe_add(&r->z, &r->z, &r->z);
    r->x = x3; r->y = y3; r->inf = false;
}

static void pt_add(thread pt *r, thread const pt *p, thread const pt *q) {
    if (p->inf) { *r = *q; return; }
    if (q->inf) { *r = *p; return; }
    fe z1z1, z2z2, u1, u2, s1, s2, h, rr, h2, h3, t;
    fe_sqr(&z1z1, &p->z); fe_sqr(&z2z2, &q->z);
    fe_mul(&u1, &p->x, &z2z2);
    fe_mul(&u2, &q->x, &z1z1);
    fe_mul(&t, &q->z, &z2z2); fe_mul(&s1, &p->y, &t);
    fe_mul(&t, &p->z, &z1z1); fe_mul(&s2, &q->y, &t);
    bool ueq = true, seq = true;
    for (int i = 0; i < 8; i++) {
        if (u1.l[i] != u2.l[i]) ueq = false;
        if (s1.l[i] != s2.l[i]) seq = false;
    }
    if (ueq) {
        if (seq) { pt_double(r, p); return; }
        r->inf = true; return;
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
    r->inf = false;
}

// 4-bit windowed scalar multiplication: 64 digits, table of 16 multiples of G.
constant uchar SECP_GX[32] = {0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
                               0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98};
constant uchar SECP_GY[32] = {0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
                               0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8};

static void pt_mul_g(thread pt *r, thread const uchar k[32]) {
    pt G;
    fe_from_bytes(&G.x, SECP_GX); fe_from_bytes(&G.y, SECP_GY); fe_set_u32(&G.z, 1); G.inf = false;
    pt tab[16];
    tab[0].inf = true;
    tab[1] = G;
    for (int j = 2; j < 16; j++) {
        pt a; pt_add(&a, &tab[j-1], &G);
        tab[j] = a;
    }
    pt acc; acc.inf = true;
    for (int i = 63; i >= 0; i--) {
        if (!acc.inf)
            for (int b = 0; b < 4; b++) { pt d; pt_double(&d, &acc); acc = d; }
        uint digit = (k[31 - i/2] >> ((i % 2) * 4)) & 0xF;
        if (digit) pt_add(&acc, &acc, &tab[digit]);
    }
    *r = acc;
}

static void pt_to_affine(thread pt *r, thread const pt *p) {
    if (p->inf) { *r = *p; return; }
    fe zi, zi2, zi3;
    fe_inv(&zi, &p->z);
    fe_sqr(&zi2, &zi);
    fe_mul(&zi3, &zi2, &zi);
    fe_mul(&r->x, &p->x, &zi2);
    fe_mul(&r->y, &p->y, &zi3);
    fe_set_u32(&r->z, 1);
    r->inf = false;
}

kernel void secp_field_mul_kernel(device const uchar *a [[buffer(0)]],
                                  device const uchar *b [[buffer(1)]],
                                  device uchar *out [[buffer(2)]],
                                  uint gid [[thread_position_in_grid]]) {
    fe x, y, r;
    fe_from_bytes(&x, a + gid * 32);
    fe_from_bytes(&y, b + gid * 32);
    fe_mul(&r, &x, &y);
    fe_to_bytes(out + gid * 32, &r);
}

kernel void secp_mul_g_kernel(device const uchar *k [[buffer(0)]],
                              device uchar *outx [[buffer(1)]],
                              device uchar *outy [[buffer(2)]],
                              uint gid [[thread_position_in_grid]]) {
    pt r, a;
    pt_mul_g(&r, k + gid * 32);
    pt_to_affine(&a, &r);
    fe_to_bytes(outx + gid * 32, &a.x);
    fe_to_bytes(outy + gid * 32, &a.y);
}

// ============================ HMAC-SHA512 / BIP32 ============================
constant uchar BIP32_SEED_LABEL[12] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};

static void hmac_sha512(thread const uchar *key, ulong keylen,
                        thread const uchar *msg, ulong msglen, thread uchar out[64]) {
    uchar k[128], inner[64];
    zero_bytes(k, 128);
    if (keylen > 128) sha512(key, keylen, k);
    else for (ulong i = 0; i < keylen; i++) k[i] = key[i];
    sha512_ctx c;
    sha512_init(&c);
    uchar blk[128];
    for (int i = 0; i < 128; i++) blk[i] = k[i] ^ 0x36;
    sha512_update(&c, blk, 128);
    sha512_update(&c, msg, msglen);
    sha512_final(&c, inner);
    sha512_init(&c);
    for (int i = 0; i < 128; i++) blk[i] = k[i] ^ 0x5C;
    sha512_update(&c, blk, 128);
    sha512_update(&c, inner, 64);
    sha512_final(&c, out);
}

static void ser32(thread uchar out[4], uint i) {
    out[0] = (uchar)(i >> 24); out[1] = (uchar)(i >> 16); out[2] = (uchar)(i >> 8); out[3] = (uchar)i;
}

kernel void bip32_master_kernel(device const uchar *seed [[buffer(0)]],
                                constant uint &seedlen [[buffer(1)]],
                                device uchar *k_out [[buffer(2)]],
                                device uchar *c_out [[buffer(3)]],
                                uint gid [[thread_position_in_grid]]) {
    uchar I[64];
    hmac_sha512(BIP32_SEED_LABEL, 12, seed + gid * 64, min(seedlen, (uint)64), I);
    for (int i = 0; i < 32; i++) { k_out[gid*32 + i] = I[i]; c_out[gid*32 + i] = I[32 + i]; }
}

kernel void bip32_ckd_priv_kernel(device const uchar *kpar [[buffer(0)]],
                                  device const uchar *cpar [[buffer(1)]],
                                  constant uint &index [[buffer(2)]],
                                  device uchar *k_out [[buffer(3)]],
                                  device uchar *c_out [[buffer(4)]],
                                  uint gid [[thread_position_in_grid]]) {
    uchar data[37], I[64];
    if (index & 0x80000000u) {
        data[0] = 0;
        for (int i = 0; i < 32; i++) data[1 + i] = kpar[gid*32 + i];
    } else {
        pt R, A;
        pt_mul_g(&R, kpar + gid * 32);
        pt_to_affine(&A, &R);
        uchar xb[32], yb[32];
        fe_to_bytes(xb, &A.x); fe_to_bytes(yb, &A.y);
        data[0] = (yb[31] & 1) ? 0x03 : 0x02;
        for (int i = 0; i < 32; i++) data[1 + i] = xb[i];
    }
    ser32(data + 33, index);
    hmac_sha512(cpar + gid*32, 32, data, 37, I);
    sc_add_mod_n(k_out + gid*32, I, kpar + gid*32);
    for (int i = 0; i < 32; i++) c_out[gid*32 + i] = I[32 + i];
}
