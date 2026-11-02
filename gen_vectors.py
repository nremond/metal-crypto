#!/usr/bin/env python3
"""Generate authoritative test vectors -> vectors.h (C) and vectors.json."""
import hashlib, hmac, json, subprocess, binascii, os

OUT = os.path.dirname(os.path.abspath(__file__))

# ---------- SHA ----------
sha_msgs = [
    b"",
    b"abc",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    b"a" * 55,   # padding edge: one byte short of two blocks
    b"a" * 56,   # padding edge: exactly needs extra block
    b"a" * 64,
    b"a" * 1000,
]
sha = {}
for m in sha_msgs:
    sha[m.hex() or "empty"] = {
        "sha1": hashlib.sha1(m).hexdigest(),
        "sha256": hashlib.sha256(m).hexdigest(),
        "sha512": hashlib.sha512(m).hexdigest(),
    }

# ---------- AES-CTR (NIST SP 800-38A F.5.1 / F.5.5 style, via openssl) ----------
def aes_ctr(key_hex, iv_hex, pt_hex):
    p = subprocess.run(
        ["openssl", "enc", "-aes-%d-ctr" % (len(key_hex) * 4), "-K", key_hex, "-iv", iv_hex],
        input=binascii.unhexlify(pt_hex), capture_output=True, check=True)
    return p.stdout.hex()

# NIST SP 800-38A F.5.1 (AES-128-CTR) and F.5.5 (AES-256-CTR)
key128 = "2b7e151628aed2a6abf7158809cf4f3c"
key256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
ctr0 = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
pt_nist = ("6bc1bee22e409f96e93d7e117393172a"
           "ae2d8a571e03ac9c9eb76fac45af8e51"
           "30c81c46a35ce411e5fbc1191a0a52ef"
           "f69f2445df4f9b17ad2b417be66c3710")
ct128 = aes_ctr(key128, ctr0, pt_nist)
ct256 = aes_ctr(key256, ctr0, pt_nist)
# cross-check against published NIST ciphertexts
assert ct128 == ("874d6191b620e3261bef6864990db6ce"
                 "9806f66b7970fdff8617187bb9fffdff"
                 "5ae4df3edbd5d35e5b4f09020db03eab"
                 "1e031dda2fbe03d1792170a0f3009cee"), ct128
assert ct256 == ("601ec313775789a5b7a7f504bbf3d228"
                 "f443e3ca4d62b59aca84e990cacaf5c5"
                 "2b0930daa23de94ce87017ba2d84988d"
                 "dfc9c58db67aada613c2dd08457941a6"), ct256

# extra CTR vectors: different key/iv/length incl. non-multiple of 16
aes = {
    "k128": key128, "k256": key256, "iv": ctr0, "pt": pt_nist, "ct128": ct128, "ct256": ct256,
    "k2": "00112233445566778899aabbccddeeff",
    "iv2": "0102030405060708090a0b0c0d0e0f10",
    "pt2": "00ff11ee22dd33cc44bb55aa66998877" "deadbeefcafebabe0123456789abcdef00",
    "ct2": aes_ctr("00112233445566778899aabbccddeeff", "0102030405060708090a0b0c0d0e0f10",
                   "00ff11ee22dd33cc44bb55aa66998877deadbeefcafebabe0123456789abcdef00"),
}

# ---------- secp256k1 ----------
p = 2**256 - 2**32 - 977
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P == Q:
        l = (3 * x1 * x1) * pow(2 * y1, p - 2, p) % p
    else:
        l = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(k, P):
    R = None
    while k:
        if k & 1: R = ec_add(R, P)
        P = ec_add(P, P); k >>= 1
    return R

G = (Gx, Gy)
G2 = ec_mul(2, G)
k_big = 0xDEADBEEFCAFEBABE1234567890ABCDEF0F1E2D3C4B5A69788796A5B4C3D2E1F
assert 0 < k_big < n
kG = ec_mul(k_big, G)
a_f = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
b_f = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
secp = {
    "p": "%064x" % p, "n": "%064x" % n,
    "Gx": "%064x" % Gx, "Gy": "%064x" % Gy,
    "sq_pm1": "%064x" % ((p - 1) * (p - 1) % p),
    "inv5": "%064x" % pow(5, p - 2, p),
    "mul_ab": "%064x" % (a_f * b_f % p),
    "a": "%064x" % a_f, "b": "%064x" % b_f,
    "G2x": "%064x" % G2[0], "G2y": "%064x" % G2[1],
    "kG_x": "%064x" % kG[0], "kG_y": "%064x" % kG[1],
    "k_big": "%064x" % k_big,
    "n_add": "%064x" % ((n - 1 + 2) % n),
}

# ---------- BIP32 test vector 1 ----------
def ser32(i): return i.to_bytes(4, "big")
def ser256(k): return k.to_bytes(32, "big")
def serP(P):
    x, y = P
    return (b"\x03" if y & 1 else b"\x02") + ser256(x)

def hmac512(key, msg): return hmac.new(key, msg, hashlib.sha512).digest()

def master(seed):
    I = hmac512(b"Bitcoin seed", seed)
    return int.from_bytes(I[:32], "big"), I[32:]

def ckd_priv(k, c, i):
    if i >= 0x80000000:
        data = b"\x00" + ser256(k) + ser32(i)
    else:
        data = serP(ec_mul(k, G)) + ser32(i)
    I = hmac512(c, data)
    child = (int.from_bytes(I[:32], "big") + k) % n
    assert child != 0 and int.from_bytes(I[:32], "big") < n
    return child, I[32:]

seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
mk, mc = master(seed)
assert "%064x" % mk == "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
assert mc.hex() == "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"

path = [0x80000000, 1, 0x80000002, 2, 1000000000]
k, c = mk, mc
bip = {"seed": seed.hex(), "master_k": "%064x" % mk, "master_c": mc.hex(), "chain": []}
for i in path:
    k, c = ckd_priv(k, c, i)
    bip["chain"].append({"index": i, "k": "%064x" % k, "c": c.hex()})
# spot-check against published vector: m/0' = edb2e14f.../47fdacbd...
assert bip["chain"][0]["k"] == "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
assert bip["chain"][0]["c"] == "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"

data = {"sha": sha, "aes": aes, "secp": secp, "bip32": bip}
with open(os.path.join(OUT, "vectors.json"), "w") as f:
    json.dump(data, f, indent=1)

# ---------- emit vectors.h ----------
def carr(name, hexstr):
    b = binascii.unhexlify(hexstr)
    return "static const unsigned char %s[%d] = {%s};\n" % (
        name, len(b), ",".join("0x%02x" % x for x in b))

lines = ["/* Auto-generated by gen_vectors.py. Do not edit. */", "#pragma once", ""]
for idx, (key, v) in enumerate(sha.items()):
    mlen = 0 if key == "empty" else len(bytes.fromhex(key))
    tag = "s%d" % idx
    lines.append("static const unsigned sha_len_%s = %d;" % (tag, mlen))
    lines.append(carr("msg_" + tag, "00" if key == "empty" else key))
    lines.append('static const char *exp_%s_sha1 = "%s";' % (tag, v["sha1"]))
    lines.append('static const char *exp_%s_sha256 = "%s";' % (tag, v["sha256"]))
    lines.append('static const char *exp_%s_sha512 = "%s";' % (tag, v["sha512"]))
    lines.append("")
lines.append(carr("aes_k128", aes["k128"]))
lines.append(carr("aes_k256", aes["k256"]))
lines.append(carr("aes_iv", aes["iv"]))
lines.append(carr("aes_pt", aes["pt"]))
lines.append('static const char *aes_ct128 = "%s";' % aes["ct128"])
lines.append('static const char *aes_ct256 = "%s";' % aes["ct256"])
lines.append(carr("aes_k2", aes["k2"]))
lines.append(carr("aes_iv2", aes["iv2"]))
lines.append(carr("aes_pt2", aes["pt2"]))
lines.append('static const char *aes_ct2 = "%s";' % aes["ct2"])
lines.append("")
for k, v in secp.items():
    if isinstance(v, str) and len(v) == 64:
        lines.append('static const char *secp_%s = "%s";' % (k, v))
lines.append("")
lines.append(carr("bip_seed", bip["seed"]))
lines.append('static const char *bip_master_k = "%s";' % bip["master_k"])
lines.append('static const char *bip_master_c = "%s";' % bip["master_c"])
for idx, step in enumerate(bip["chain"]):
    lines.append("static const unsigned bip_step%d_index = 0x%08xu;" % (idx, step["index"]))
    lines.append('static const char *bip_step%d_k = "%s";' % (idx, step["k"]))
    lines.append('static const char *bip_step%d_c = "%s";' % (idx, step["c"]))
with open(os.path.join(OUT, "vectors.h"), "w") as f:
    f.write("\n".join(lines) + "\n")
print("vectors written; sha msgs:", len(sha), "; bip32 path len:", len(bip["chain"]))
