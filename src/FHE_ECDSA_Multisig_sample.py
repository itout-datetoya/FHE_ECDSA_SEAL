from seal import *

from random import randint
from ecc import S256Point, Signature, PrivateKey

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


parms = EncryptionParameters(scheme_type.bgv)
poly_modulus_degree = 16384
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
context = SEALContext(parms)


sk_a = PrivateKey(randint(0, N))
sk_b = PrivateKey(randint(0, N))
pk = sk_a.point + sk_b.point
z = randint(0, 2**256)


# Alice
k_a = sk_a.deterministic_k(z)
R_a = k_a * G # send to Bob


# Bob
k_b = sk_b.deterministic_k(z)
R_b = k_b * G # send to Alice


# Alice
R = k_a * R_b # == k_b * R_a
r = R.x.num
keygen = KeyGenerator(context)
secret_key = keygen.secret_key()
public_key = keygen.create_public_key() # send to Bob
relin_keys = keygen.create_relin_keys()

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

k_a_inv = pow(k_a, N-2, N)
encrypted_k_a_inv = encryptor.encrypt(k_a_inv) # send to Bob
encrypted_secret_a = encryptor.encrypt(sk_a.secret) # send to Bob


# Bob
encrypted_rsa = evaluator.multiply_plain(encrypted_secret_a, r) # r * s_a
encrypted_zrs = evaluator.add_plain(encrypted_rsa, z + r * sk_b.secret) # z + r * s_b + r * s_a == z + r * (s_a + s_b)
k_b_inv = pow(k_b, N-2, N)
encrypted_k_inv = evaluator.multiply_plain(encrypted_k_a_inv, k_b_inv)
encrypted_s = evaluator.multiply(encrypted_zrs, encrypted_k_inv) # send to Alice


# Alice
s = decryptor.decrypt(encrypted_s) % N
if s > N / 2:
    s = N - s
sig = Signature(r, s)


if pk.verify(z, sig):
    print("Verify")
else:
    print("Fail")






