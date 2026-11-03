// main.m - on-device validation of crypto.metal against vectors.h (macOS).
//
// Build & run:
//   xcrun -sdk macosx metal -c crypto.metal -o crypto.air
//   xcrun -sdk macosx metallib crypto.air -o crypto.metallib
//   clang -framework Metal -framework Foundation main.m -o metaltest
//   ./metaltest crypto.metallib
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "vectors.h"

static int fails = 0;
static id<MTLDevice> dev;
static id<MTLLibrary> lib;

static void tohex(char *dst, const unsigned char *src, int n) {
    for (int i = 0; i < n; i++) sprintf(dst + 2*i, "%02x", src[i]);
    dst[2*n] = 0;
}
static void check(const char *name, const unsigned char *got, const char *exp, int n) {
    char buf[130]; tohex(buf, got, n);
    if (!strcmp(buf, exp)) printf("PASS %s\n", name);
    else { printf("FAIL %s\n  got %s\n  exp %s\n", name, buf, exp); fails++; }
}
static id<MTLBuffer> buf(const void *p, NSUInteger n) {
    return [dev newBufferWithBytes:p length:n options:MTLResourceStorageModeShared];
}
static void run(id<MTLComputePipelineState> k, NSUInteger threads) {
    id<MTLCommandBuffer> cb = [dev newCommandBuffer];
    id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
    [enc setComputePipelineState:k];
    NSUInteger w = k.maxTotalThreadsPerThreadgroup;
    [enc dispatchThreadgroups:MTLSizeMake((threads + w - 1) / w, 1, 1)
            threadsPerThreadgroup:MTLSizeMake(MIN(w, threads), 1, 1)];
    [enc endEncoding];
    [cb commit]; [cb waitUntilCompleted];
}
static id<MTLComputePipelineState> pipe(const char *name) {
    return [lib newComputePipelineStateWithFunction:[lib newFunctionWithName:[NSString stringWithUTF8String:name]] error:nil];
}

int main(int argc, char **argv) {
    @autoreleasepool {
        dev = MTLCreateSystemDefaultDevice();
        lib = [dev newLibraryWithFile:[NSString stringWithUTF8String:argv[1]] error:nil];
        if (!lib) { printf("cannot load metallib\n"); return 2; }

        // ---- SHA batches ----
        const unsigned char *msgs[7] = {msg_s0, msg_s1, msg_s2, msg_s3, msg_s4, msg_s5, msg_s6};
        const unsigned lens[7] = {sha_len_s0, sha_len_s1, sha_len_s2, sha_len_s3, sha_len_s4, sha_len_s5, sha_len_s6};
        const char *e1[7] = {exp_s0_sha1, exp_s1_sha1, exp_s2_sha1, exp_s3_sha1, exp_s4_sha1, exp_s5_sha1, exp_s6_sha1};
        const char *e2[7] = {exp_s0_sha256, exp_s1_sha256, exp_s2_sha256, exp_s3_sha256, exp_s4_sha256, exp_s5_sha256, exp_s6_sha256};
        const char *e5[7] = {exp_s0_sha512, exp_s1_sha512, exp_s2_sha512, exp_s3_sha512, exp_s4_sha512, exp_s5_sha512, exp_s6_sha512};
        unsigned char data[2048]; unsigned offs[7], lens32[7]; unsigned pos = 0;
        for (int i = 0; i < 7; i++) { offs[i] = pos; lens32[i] = lens[i]; memcpy(data + pos, msgs[i], lens[i] ? lens[i] : 1); pos += lens[i] ? lens[i] : 1; }
        id<MTLBuffer> bData = buf(data, sizeof data), bOff = buf(offs, sizeof offs), bLen = buf(lens32, sizeof lens32);
        id<MTLBuffer> o1 = [dev newBufferWithLength:7*20 options:0], o2 = [dev newBufferWithLength:7*32 options:0], o5 = [dev newBufferWithLength:7*64 options:0];
        id<MTLComputePipelineState> k1 = pipe("sha1_batch"), k2 = pipe("sha256_batch"), k5 = pipe("sha512_batch");
        id<MTLCommandBuffer> cb = [dev newCommandBuffer];
        id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
        [enc setComputePipelineState:k1]; [enc setBuffer:bData offset:0 atIndex:0]; [enc setBuffer:bOff offset:0 atIndex:1];
        [enc setBuffer:bLen offset:0 atIndex:2]; [enc setBuffer:o1 offset:0 atIndex:3];
        [enc dispatchThreadgroups:MTLSizeMake(7,1,1) threadsPerThreadgroup:MTLSizeMake(7,1,1)];
        [enc setComputePipelineState:k2]; [enc setBuffer:o2 offset:0 atIndex:3];
        [enc dispatchThreadgroups:MTLSizeMake(7,1,1) threadsPerThreadgroup:MTLSizeMake(7,1,1)];
        [enc setComputePipelineState:k5]; [enc setBuffer:o5 offset:0 atIndex:3];
        [enc dispatchThreadgroups:MTLSizeMake(7,1,1) threadsPerThreadgroup:MTLSizeMake(7,1,1)];
        [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
        for (int i = 0; i < 7; i++) {
            char nm[64];
            sprintf(nm, "sha1   s%d", i); check(nm, (unsigned char*)o1.contents + i*20, e1[i], 20);
            sprintf(nm, "sha256 s%d", i); check(nm, (unsigned char*)o2.contents + i*32, e2[i], 32);
            sprintf(nm, "sha512 s%d", i); check(nm, (unsigned char*)o5.contents + i*64, e5[i], 64);
        }

        // ---- AES-CTR ----
        {
            unsigned klen = 16, len = 64;
            id<MTLBuffer> bKey = buf(aes_k128, 16), bIv = buf(aes_iv, 16), bIn = buf(aes_pt, 64);
            id<MTLBuffer> bOut = [dev newBufferWithLength:64 options:0];
            id<MTLComputePipelineState> kc = pipe("aes_ctr_kernel");
            cb = [dev newCommandBuffer]; enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:kc];
            [enc setBuffer:bKey offset:0 atIndex:0]; [enc setBuffer:buf(&klen,4) offset:0 atIndex:1];
            [enc setBuffer:bIv offset:0 atIndex:2]; [enc setBuffer:bIn offset:0 atIndex:3];
            [enc setBuffer:bOut offset:0 atIndex:4]; [enc setBuffer:buf(&len,4) offset:0 atIndex:5];
            [enc dispatchThreadgroups:MTLSizeMake(4,1,1) threadsPerThreadgroup:MTLSizeMake(4,1,1)];
            [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
            check("aes128-ctr NIST", (unsigned char*)bOut.contents, aes_ct128, 64);
            klen = 32;
            cb = [dev newCommandBuffer]; enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:kc];
            [enc setBuffer:buf(aes_k256,32) offset:0 atIndex:0]; [enc setBuffer:buf(&klen,4) offset:0 atIndex:1];
            [enc setBuffer:bIv offset:0 atIndex:2]; [enc setBuffer:bIn offset:0 atIndex:3];
            [enc setBuffer:bOut offset:0 atIndex:4]; [enc setBuffer:buf(&len,4) offset:0 atIndex:5];
            [enc dispatchThreadgroups:MTLSizeMake(4,1,1) threadsPerThreadgroup:MTLSizeMake(4,1,1)];
            [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
            check("aes256-ctr NIST", (unsigned char*)bOut.contents, aes_ct256, 64);
        }

        // ---- secp256k1 ----
        {
            auto hex2bin = [](const char *h, unsigned char *b) {
                for (int i = 0; i < 32; i++) { char t[3] = {h[2*i], h[2*i+1], 0}; b[i] = (unsigned char)strtoul(t, 0, 16); }
            };
            unsigned char ab[32], bb[32], ob[32], two[32] = {0}, kb[32], ox[32], oy[32];
            hex2bin(secp_a, ab); hex2bin(secp_b, bb);
            id<MTLComputePipelineState> kfm = pipe("secp_field_mul_kernel");
            cb = [dev newCommandBuffer]; enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:kfm];
            [enc setBuffer:buf(ab,32) offset:0 atIndex:0]; [enc setBuffer:buf(bb,32) offset:0 atIndex:1];
            [enc setBuffer:buf(ob,32) offset:0 atIndex:2];
            [enc dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
            check("secp mul a*b", ob, secp_mul_ab, 32);
            id<MTLComputePipelineState> kg = pipe("secp_mul_g_kernel");
            two[31] = 2;
            cb = [dev newCommandBuffer]; enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:kg];
            [enc setBuffer:buf(two,32) offset:0 atIndex:0]; [enc setBuffer:buf(ox,32) offset:0 atIndex:1]; [enc setBuffer:buf(oy,32) offset:0 atIndex:2];
            [enc dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
            check("secp 2G.x", ox, secp_G2x, 32);
            check("secp 2G.y", oy, secp_G2y, 32);
            hex2bin(secp_k_big, kb);
            cb = [dev newCommandBuffer]; enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:kg];
            [enc setBuffer:buf(kb,32) offset:0 atIndex:0]; [enc setBuffer:buf(ox,32) offset:0 atIndex:1]; [enc setBuffer:buf(oy,32) offset:0 atIndex:2];
            [enc dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
            check("secp kG.x", ox, secp_kG_x, 32);
            check("secp kG.y", oy, secp_kG_y, 32);
        }

        // ---- BIP32 ----
        {
            unsigned char k[32], c[32], kc[32], cc[32]; char kh[65], ch[65];
            unsigned seedlen = 16;
            id<MTLComputePipelineState> km = pipe("bip32_master_kernel"), kd = pipe("bip32_ckd_priv_kernel");
            cb = [dev newCommandBuffer]; enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:km];
            [enc setBuffer:buf(bip_seed,16) offset:0 atIndex:0]; [enc setBuffer:buf(&seedlen,4) offset:0 atIndex:1];
            [enc setBuffer:buf(k,32) offset:0 atIndex:2]; [enc setBuffer:buf(c,32) offset:0 atIndex:3];
            [enc dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
            tohex(kh, k, 32); tohex(ch, c, 32);
            check("bip32 master key", k, bip_master_k, 32);
            check("bip32 master chain", c, bip_master_c, 32);
            const unsigned idxs[5] = {bip_step0_index, bip_step1_index, bip_step2_index, bip_step3_index, bip_step4_index};
            const char *ek[5] = {bip_step0_k, bip_step1_k, bip_step2_k, bip_step3_k, bip_step4_k};
            const char *ec[5] = {bip_step0_c, bip_step1_c, bip_step2_c, bip_step3_c, bip_step4_c};
            for (int i = 0; i < 5; i++) {
                unsigned idx = idxs[i];
                cb = [dev newCommandBuffer]; enc = [cb computeCommandEncoder];
                [enc setComputePipelineState:kd];
                [enc setBuffer:buf(k,32) offset:0 atIndex:0]; [enc setBuffer:buf(c,32) offset:0 atIndex:1];
                [enc setBuffer:buf(&idx,4) offset:0 atIndex:2]; [enc setBuffer:buf(kc,32) offset:0 atIndex:3]; [enc setBuffer:buf(cc,32) offset:0 atIndex:4];
                [enc dispatchThreadgroups:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
                [enc endEncoding]; [cb commit]; [cb waitUntilCompleted];
                memcpy(k, kc, 32); memcpy(c, cc, 32);
                char nm[64]; sprintf(nm, "bip32 step %d (idx 0x%08x) key", i, idxs[i]);
                check(nm, kc, ek[i], 32);
                sprintf(nm, "bip32 step %d (idx 0x%08x) chain", i, idxs[i]);
                check(nm, cc, ec[i], 32);
            }
        }
        printf(fails ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", fails);
        return fails ? 1 : 0;
    }
}
