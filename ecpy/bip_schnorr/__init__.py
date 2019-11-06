# -*- encoding:utf-8 -*-

import hashlib
import binascii

import future
from builtins import int, bytes, pow

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def tagged_hash(tag, msg):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def x(P):
    return P[0]

def y(P):
    return P[1]

def point_add(P1, P2):
    if (P1 is None):
        return P2
    if (P2 is None):
        return P1
    if (x(P1) == x(P2) and y(P1) != y(P2)):
        return None
    if (P1 == P2):
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P, n):
    R = None
    for i in range(256):
        if ((n >> i) & 1):
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x):
    return int(x).to_bytes(32, byteorder="big")

def bytes_from_point(P):
    return bytes_from_int(x(P))

def encode_from_point(P):
    return (b"\x03" if y(P) & 1 else b"\x02") + bytes_from_int(x(P))

def point_from_bytes(b):
    x = int_from_bytes(b)
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return [x, y]

def int_from_bytes(b):
    return int.from_bytes(b, byteorder="big")

def hash_sha256(b):
    return hashlib.sha256(b).digest()

def jacobi(x):
    return pow(x, (p - 1) // 2, p)

def is_quad(x):
    return jacobi(x) == 1

def pubkey_gen(seckey):
    x = int_from_bytes(seckey)
    if not (1 <= x <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, x)
    return bytes_from_point(P)

# https://github.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js
def schnorr_bcrypto410_sign(msg, seckey0):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    # const a = this.curve.decodeScalar(key);
    seckey0 = int_from_bytes(seckey0)
    # if (a.isZero() || a.cmp(N) >= 0)
    #   throw new Error('Invalid private key.');
    if not (1 <= seckey0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    # const k = this.hashInt(key, msg);
    k0 = int_from_bytes(hashlib.sha256(bytes_from_int(seckey0) + msg).digest()) % n
    # if (k.isZero())
    #   throw new Error('Signing failed (k\' = 0).');
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    # const R = G.mulBlind(k);
    R = point_mul(G, k0)
    # const Rraw = this.curve.encodeField(R.getX());
    Rraw = bytes_from_point(R)
    # const Araw = G.mulBlind(a).encode();
    P = point_mul(G, seckey0)
    Araw = encode_from_point(P)
    # const e = this.hashInt(Rraw, Araw, msg);
    e = int_from_bytes(hashlib.sha256(Rraw + Araw + msg).digest()) % n
    # const [blind, unblind] = this.curve.getBlinding(); // blind = unblind = 1
    # a.imul(blind).imod(N);
    # k.imul(blind).imod(N);
    k0 %= n
    seckey0 %= n
    # if (R.y.redJacobi() !== 1)
    #    k.ineg().imod(N); // -k%n == n-k
    k = n - k0 if not is_quad(y(R)) else k0
    # const S = k.iadd(e.imul(a)).imod(N);
    S = (k + e * seckey0) % n
    # S.imul(unblind).imod(N);
    S %= n
    # return Buffer.concat([Rraw, this.curve.encodeScalar(S)]);
    return bytes_from_point(R) + bytes_from_int(S)

def schnorr_bcrypto410_verify(msg, P, sig):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    if (P is None):
        return False
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (r >= p or s >= n):
        return False
    Rraw = sig[0:32]
    Araw = encode_from_point(P)
    e = int_from_bytes(hashlib.sha256(Rraw + Araw + msg).digest()) % n
    R = point_add(point_mul(G, s), point_mul(P, n-e))
    if R is None or not is_quad(y(R)) or x(R) != r:
        return False
    return True

def schnorr_sign(msg, seckey0):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    seckey0 = int_from_bytes(seckey0)
    if not (1 <= seckey0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, seckey0)
    seckey = seckey0 if is_quad(y(P)) else n - seckey0
    k0 = int_from_bytes(tagged_hash("BIPSchnorrDerive", bytes_from_int(seckey) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    k = n - k0 if not is_quad(y(R)) else k0
    e = int_from_bytes(tagged_hash("BIPSchnorr", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    return bytes_from_point(R) + bytes_from_int((k + e * seckey) % n)

def schnorr_verify(msg, pubkey, sig):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = point_from_bytes(pubkey)
    if (P is None):
        return False
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (r >= p or s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIPSchnorr", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if R is None or not is_quad(y(R)) or x(R) != r:
        return False
    return True


__all__ = ["schnorr_sign", "schnorr_verify", "schnorr_bcrypto410_sign"]

#
# The following code is only used to verify the test vectors.
#
import csv

def test_vectors():
    all_passed = True
    with open('test-vectors.csv') as csvfile:
        reader = csv.reader(csvfile, delimiter=";")
        # reader.__next__()
        next(reader)
        for row in reader:
            (index, seckey, pubkey, msg, sig, result, comment) = row
            pubkey = bytes.fromhex(pubkey)
            msg = bytes.fromhex(msg)
            sig = bytes.fromhex(sig)
            result = result == 'TRUE'
            print('\nTest vector #%-3i: ' % int(index))
            if seckey != '':
                seckey = bytes.fromhex(seckey)
                pubkey_actual = pubkey_gen(seckey)
                if pubkey != pubkey_actual:
                    print(' * Failed key generation.')
                    print('   Expected key:', pubkey.hex().upper())
                    print('     Actual key:', pubkey_actual.hex().upper())
                sig_actual = schnorr_sign(msg, seckey)
                if sig == sig_actual:
                    print(' * Passed signing test.')
                else:
                    print(' * Failed signing test.')
                    print('   Expected signature:', sig.hex().upper())
                    print('     Actual signature:', sig_actual.hex().upper())
                    all_passed = False
            result_actual = schnorr_verify(msg, pubkey, sig)
            if result == result_actual:
                print(' * Passed verification test.')
            else:
                print(' * Failed verification test.')
                print('   Expected verification result:', result)
                print('     Actual verification result:', result_actual)
                if comment:
                    print('   Comment:', comment)
                all_passed = False
    print()
    if all_passed:
        print('All test vectors passed.')
    else:
        print('Some test vectors failed.')
    return all_passed

if __name__ == '__main__':
    test_vectors()